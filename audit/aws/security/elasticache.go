package security

import (
	"context"
	"fmt"
	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
)

func init() {
	audit.RegisterAWS(Module, "elasticache", AuditElastiCache)
}

func AuditElastiCache(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := elasticache.NewFromConfig(cfg)

	type cacheEntry struct {
		id                string
		engine            string
		transitEncryption bool
		atRestEncryption  bool
		authTokenEnabled  bool
	}

	var entries []cacheEntry
	input := &elasticache.DescribeCacheClustersInput{}
	for {
		resp, err := client.DescribeCacheClusters(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("describe cache clusters: %w", err)
		}
		for _, c := range resp.CacheClusters {
			entries = append(entries, cacheEntry{
				id:                aws.ToString(c.CacheClusterId),
				engine:            aws.ToString(c.Engine),
				transitEncryption: aws.ToBool(c.TransitEncryptionEnabled),
				atRestEncryption:  aws.ToBool(c.AtRestEncryptionEnabled),
				authTokenEnabled:  c.AuthTokenEnabled != nil && *c.AuthTokenEnabled,
			})
		}
		if resp.Marker == nil {
			break
		}
		input.Marker = resp.Marker
	}

	return audit.ProcessAllMulti(
		ctx,
		entries,
		"Auditing ElastiCache security",
		func(_ context.Context, e cacheEntry) []audit.Finding {
			var results []audit.Finding
			if !e.atRestEncryption {
				d := fmt.Sprintf("engine=%s, at-rest encryption disabled", e.engine)
				results = append(
					results,
					audit.Finding{
						Service:    "elasticache",
						ResourceID: e.id,
						Check:      "no_at_rest_encryption",
						Status:     "FAIL",
						Detail:     d,
						RiskLevel:  "HIGH",
						Remediation: remediation.Recommend(
							"security",
							"elasticache",
							"no_at_rest_encryption",
							e.id,
							d,
						),
					},
				)
			}
			if !e.transitEncryption {
				d := fmt.Sprintf("engine=%s, in-transit encryption disabled", e.engine)
				results = append(
					results,
					audit.Finding{
						Service:    "elasticache",
						ResourceID: e.id,
						Check:      "no_transit_encryption",
						Status:     "FAIL",
						Detail:     d,
						RiskLevel:  "HIGH",
						Remediation: remediation.Recommend(
							"security",
							"elasticache",
							"no_transit_encryption",
							e.id,
							d,
						),
					},
				)
			}
			if !e.authTokenEnabled {
				d := fmt.Sprintf("engine=%s, AUTH token not enabled", e.engine)
				results = append(
					results,
					audit.Finding{
						Service:    "elasticache",
						ResourceID: e.id,
						Check:      "no_auth",
						Status:     "FAIL",
						Detail:     d,
						RiskLevel:  "MEDIUM",
						Remediation: remediation.Recommend(
							"security",
							"elasticache",
							"no_auth",
							e.id,
							d,
						),
					},
				)
			}
			if len(results) == 0 {
				results = append(
					results,
					audit.Finding{
						Service:    "elasticache",
						ResourceID: e.id,
						Check:      "elasticache_posture",
						Status:     "PASS",
						Detail: fmt.Sprintf(
							"engine=%s, all encryption and auth enabled",
							e.engine,
						),
						RiskLevel: "MINIMAL",
					},
				)
			}
			return results
		},
	), nil
}
