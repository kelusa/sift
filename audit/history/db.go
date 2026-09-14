package history

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sift/audit"

	_ "modernc.org/sqlite"
)

type DB struct {
	db *sql.DB
}

type ScanMeta struct {
	ID         string    `json:"id"`
	Provider   string    `json:"provider"`
	Profile    string    `json:"profile"`
	Command    string    `json:"command"`
	Region     string    `json:"region,omitempty"`
	Services   string    `json:"services,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	DurationMs int64     `json:"duration_ms,omitempty"`
}

func OpenDB() (*DB, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}
	dir := filepath.Join(home, ".sift")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create sift dir: %w", err)
	}

	dbPath := filepath.Join(dir, "sift.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}

	return &DB{db: db}, nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

func (d *DB) SaveScan(meta ScanMeta, findings []audit.Finding) error {
	slog.Info(
		"saving scan",
		"profile",
		meta.Profile,
		"command",
		meta.Command,
		"findings",
		len(findings),
	)
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	provider := meta.Provider
	if provider == "" {
		provider = "aws"
	}
	_, err = tx.Exec(
		`INSERT INTO scans (id, provider, profile, command, region, services, timestamp, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		meta.ID,
		provider,
		meta.Profile,
		meta.Command,
		meta.Region,
		meta.Services,
		meta.Timestamp,
		meta.DurationMs,
	)
	if err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}

	stmt, err := tx.Prepare(
		`INSERT OR REPLACE INTO findings (id, scan_id, region, service, resource_id, check_name, status, detail, risk_level, cost, remediation, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return fmt.Errorf("prepare stmt: %w", err)
	}
	defer stmt.Close()

	for i := range findings {
		f := &findings[i]
		if f.ID == "" {
			f.ComputeID()
		}

		var remJSON, tagsJSON string
		if f.Remediation != nil {
			b, _ := json.Marshal(f.Remediation)
			remJSON = string(b)
		}
		if len(f.Tags) > 0 {
			b, _ := json.Marshal(f.Tags)
			tagsJSON = string(b)
		}

		_, err = stmt.Exec(
			f.ID, meta.ID, f.Region, f.Service, f.ResourceID, f.Check,
			f.Status, f.Detail, f.RiskLevel, f.EstimatedMonthlyCost,
			remJSON, tagsJSON,
		)
		if err != nil {
			return fmt.Errorf("insert finding: %w", err)
		}

		// Track first-seen (ignore if already exists)
		if f.Status != "PASS" {
			tx.Exec(
				`INSERT OR IGNORE INTO finding_first_seen (finding_id, first_seen) VALUES (?,?)`,
				f.ID, meta.Timestamp,
			)
		}
	}
	return tx.Commit()
}

func (d *DB) LatestScan(provider, profile, command string) (*ScanMeta, []audit.Finding, error) {
	q := `SELECT id, provider, profile, command, region, services, timestamp, duration_ms FROM scans WHERE profile = ? AND command = ?`
	args := []interface{}{profile, command}
	if provider != "" {
		q += " AND provider = ?"
		args = append(args, provider)
	}
	q += " ORDER BY timestamp DESC LIMIT 1"
	row := d.db.QueryRow(q, args...)

	var meta ScanMeta
	if err := row.Scan(&meta.ID, &meta.Provider, &meta.Profile, &meta.Command, &meta.Region, &meta.Services, &meta.Timestamp, &meta.DurationMs); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("query latest scan: %w", err)
	}

	findings, err := d.findingsByScan(meta.ID)
	if err != nil {
		return nil, nil, err
	}
	return &meta, findings, nil
}

func (d *DB) FindingHistory(findingID string) ([]audit.Finding, error) {
	rows, err := d.db.Query(
		`SELECT f.id, f.region, f.service, f.resource_id, f.check_name, f.status, f.detail, f.risk_level, f.cost, f.remediation, f.tags
		FROM findings f JOIN scans s ON f.scan_id = s.id
		WHERE f.id = ? ORDER BY s.timestamp DESC`,
		findingID,
	)
	if err != nil {
		return nil, fmt.Errorf("query finding history: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

func (d *DB) Query(provider, service, riskLevel, status, module, profile string) ([]audit.Finding, error) {
	scanSubQuery := `SELECT id, command FROM scans`
	var conditions []string
	var args []interface{}
	if provider != "" {
		conditions = append(conditions, "provider = ?")
		args = append(args, provider)
	}
	if module != "" {
		conditions = append(conditions, "command = ?")
		args = append(args, module)
	}
	if profile != "" {
		conditions = append(conditions, "profile = ?")
		args = append(args, profile)
	}
	if len(conditions) > 0 {
		scanSubQuery += " WHERE " + strings.Join(conditions, " AND ")
	}
	scanSubQuery += " ORDER BY timestamp DESC LIMIT 1"

	q := `SELECT f.id, f.region, f.service, f.resource_id, f.check_name, f.status, f.detail, f.risk_level, f.cost, f.remediation, f.tags, s.command
		  FROM findings f
		  JOIN (` + scanSubQuery + `) s ON f.scan_id = s.id
		  WHERE 1=1`

	if service != "" {
		q += " AND f.service = ?"
		args = append(args, service)
	}
	if riskLevel != "" {
		q += " AND f.risk_level = ?"
		args = append(args, riskLevel)
	}
	if status != "" {
		q += " AND f.status = ?"
		args = append(args, status)
	}

	rows, err := d.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings: %w", err)
	}
	defer rows.Close()

	var findings []audit.Finding
	for rows.Next() {
		var f audit.Finding
		var remJSON, tagsJSON sql.NullString
		if err := rows.Scan(&f.ID, &f.Region, &f.Service, &f.ResourceID, &f.Check, &f.Status, &f.Detail, &f.RiskLevel, &f.EstimatedMonthlyCost, &remJSON, &tagsJSON, &f.Module); err != nil {
			return nil, err
		}
		if remJSON.Valid && remJSON.String != "" {
			var rem audit.Remediation
			if err := json.Unmarshal([]byte(remJSON.String), &rem); err == nil {
				f.Remediation = &rem
			}
		}
		if tagsJSON.Valid && tagsJSON.String != "" {
			json.Unmarshal([]byte(tagsJSON.String), &f.Tags)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func (d *DB) findingsByScan(scanID string) ([]audit.Finding, error) {
	rows, err := d.db.Query(
		`SELECT id, region, service, resource_id, check_name, status, detail, risk_level, cost, remediation, tags FROM findings WHERE scan_id = ?`,
		scanID,
	)
	if err != nil {
		return nil, fmt.Errorf("query findings by scan: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

func scanFindings(rows *sql.Rows) ([]audit.Finding, error) {
	var findings []audit.Finding
	for rows.Next() {
		var f audit.Finding
		var remJSON, tagsJSON sql.NullString
		if err := rows.Scan(&f.ID, &f.Region, &f.Service, &f.ResourceID, &f.Check, &f.Status, &f.Detail, &f.RiskLevel, &f.EstimatedMonthlyCost, &remJSON, &tagsJSON); err != nil {
			return nil, err
		}
		if remJSON.Valid && remJSON.String != "" {
			var rem audit.Remediation
			json.Unmarshal([]byte(remJSON.String), &rem)
			f.Remediation = &rem
		}
		if tagsJSON.Valid && tagsJSON.String != "" {
			json.Unmarshal([]byte(tagsJSON.String), &f.Tags)
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings: %w", err)
	}
	return findings, nil
}

func (d *DB) RecentScans(limit int) ([]ScanMeta, error) {
	rows, err := d.db.Query(
		`SELECT id, provider, profile, command, region, services, timestamp, duration_ms FROM scans ORDER BY timestamp DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query recent scans: %w", err)
	}
	defer rows.Close()

	var scans []ScanMeta
	for rows.Next() {
		var s ScanMeta
		if err := rows.Scan(&s.ID, &s.Provider, &s.Profile, &s.Command, &s.Region, &s.Services, &s.Timestamp, &s.DurationMs); err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate recent scans: %w", err)
	}
	return scans, nil
}

func (d *DB) FindingsByCommand(
	provider string,
	profile string,
	commands []string,
) (map[string][]audit.Finding, error) {
	result := make(map[string][]audit.Finding)
	for _, cmd := range commands {
		meta, findings, err := d.LatestScan(provider, profile, cmd)
		if err != nil {
			return nil, err
		}
		if meta != nil && len(findings) > 0 {
			result[cmd] = findings
		}
	}
	return result, nil
}

type AgingFinding struct {
	ID         string    `json:"id"`
	FirstSeen  time.Time `json:"first_seen"`
	AgeDays    int       `json:"age_days"`
	Service    string    `json:"service"`
	ResourceID string    `json:"resource_id"`
	Check      string    `json:"check"`
	RiskLevel  string    `json:"risk_level"`
	Detail     string    `json:"detail"`
}

func (d *DB) AgingFindings(minDays int) ([]AgingFinding, error) {
	rows, err := d.db.Query(
		`SELECT fs.finding_id, fs.first_seen, f.service, f.resource_id, f.check_name, f.risk_level, f.detail
		FROM finding_first_seen fs
		JOIN findings f ON fs.finding_id = f.id
		JOIN (SELECT id FROM scans ORDER BY timestamp DESC LIMI 1) s ON f.scan_id = s.id
		WHERE julianday('now') - julianday(fs.first_seen) >= ?
		AND f.status != 'PASS'
		ORDER BY fs.first_seen ASC`,
		minDays,
	)
	if err != nil {
		return nil, fmt.Errorf("query aging findings: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate aging findings: %w", err)
	}
	defer rows.Close()

	var results []AgingFinding
	for rows.Next() {
		var a AgingFinding
		if err := rows.Scan(&a.ID, &a.FirstSeen, &a.Service, &a.ResourceID, &a.Check, &a.RiskLevel, &a.Detail); err != nil {
			return nil, err
		}
		a.AgeDays = int(time.Since(a.FirstSeen).Hours() / 24)
		results = append(results, a)
	}
	return results, nil
}

func (d *DB) PreviousScan(profile, command string) (*ScanMeta, []audit.Finding, error) {
	var latestRegion, latestServices string
	d.db.QueryRow(
		`SELECT COALESCE(region, ''), COALESCE(services, '') FROM scans WHERE profile = ? AND command = ? ORDER BY timestamp DESC LIMIT 1`,
		profile,
		command,
	).Scan(&latestRegion, &latestServices)

	// Find previous scan with matching scope
	row := d.db.QueryRow(
		`SELECT id, profile, command, region, services, timestamp, duration_ms FROM scans WHERE profile = ? AND command = ? AND COALESCE(region, '') = ? AND COALESCE(services,'') = ? ORDER BY timestamp DESC LIMIT 1 OFFSET 1`,
		profile,
		command,
		latestRegion,
		latestServices,
	)

	var meta ScanMeta
	if err := row.Scan(&meta.ID, &meta.Profile, &meta.Command, &meta.Region, &meta.Services, &meta.Timestamp, &meta.DurationMs); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("query previous scan: %w", err)
	}

	findings, err := d.findingsByScan(meta.ID)
	if err != nil {
		return nil, nil, err
	}
	return &meta, findings, nil
}

func (d *DB) SaveSpend(
	profile, tagKey string,
	spendByValue map[string]float64,
	period string,
) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`DELETE FROM spend_data WHERE profile = ? AND tag_key = ?`, profile, tagKey)
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(
		`INSERT INTO spend_data (profile, tag_key, tag_value, spend, period, updated_at) VALUES (?, ?, ?, ?, ?, datetime('now'))`,
	)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for val, spend := range spendByValue {
		if _, err := stmt.Exec(profile, tagKey, val, spend, period); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type SpendRow struct {
	TagValue string
	Spend    float64
}

func (d *DB) GetSpend(profiles []string, tagKey string) ([]SpendRow, error) {
	var rows []SpendRow
	for _, p := range profiles {
		sqlRows, err := d.db.Query(
			`SELECT tag_value, spend FROM spend_data WHERE profile = ? AND tag_key = ?`,
			p, tagKey,
		)
		if err != nil {
			return nil, err
		}
		for sqlRows.Next() {
			var r SpendRow
			if err := sqlRows.Scan(&r.TagValue, &r.Spend); err != nil {
				sqlRows.Close()
				return nil, err
			}
			rows = append(rows, r)
		}
		if err := sqlRows.Err(); err != nil {
			sqlRows.Close()
			return nil, err
		}
		sqlRows.Close()
	}
	return rows, nil
}
