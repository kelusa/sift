package history

import "database/sql"

var migrations = []string{
	// v1: initial schema
	`CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		profile TEXT NOT NULL,
		command TEXT NOT NULL,
		region TEXT,
		services TEXT,
		timestamp DATETIME NOT NULL,
		duration_ms INTEGER
	);
	CREATE TABLE IF NOT EXISTS findings (
		id TEXT NOT NULL,
		scan_id TEXT NOT NULL REFERENCES scans(id),
		region TEXT,
		service TEXT NOT NULL,
		resource_id TEXT,
		check_name TEXT NOT NULL,
		status TEXT NOT NULL,
		detail TEXT,
		risk_level TEXT,
		cost REAL,
		remediation TEXT,
		tags TEXT,
		PRIMARY KEY (id, scan_id)
	);
	CREATE INDEX IF NOT EXISTS idx_findings_service ON findings(service);
	CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
	CREATE INDEX IF NOT EXISTS idx_findings_risk ON findings(risk_level);
	CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);`,

	// v2: first-seen tracking
	`CREATE TABLE IF NOT EXISTS finding_first_seen (
		finding_id TEXT PRIMARY KEY,
		first_seen DATETIME NOT NULL
	);`,

	// v3: cost explorer spend data
	`CREATE TABLE IF NOT EXISTS spend_data (
		profile TEXT NOT NULL,
		tag_key TEXT NOT NULL,
		tag_value TEXT NOT NULL,
		spend REAL NOT NULL,
		period TEXT NOT NULL,
		updated_at DATETIME NOT NULL,
		PRIMARY KEY (profile, tag_key, tag_value)
	);`,

	// v4: multi-provider support - tag each scan with its source provider.
	// Existing rows default to 'aws' so historical data stays queryable.
	`ALTER TABLE scans ADD COLUMN provider TEXT NOT NULL DEFAULT 'aws';
	CREATE INDEX IF NOT EXISTS idx_scans_provider ON scans(provider);`,
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`)
	if err != nil {
		return err
	}

	var current int
	row := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`)
	row.Scan(&current)

	for i := current; i < len(migrations); i++ {
		if _, err := db.Exec(migrations[i]); err != nil {
			return err
		}
		if _, err := db.Exec(`INSERT INTO schema_version (version) VALUES (?)`, i+1); err != nil {
			return err
		}
	}
	return nil
}
