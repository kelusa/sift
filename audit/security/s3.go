package security

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func init() {
	audit.RegisterAWS(Module, "s3", AuditS3)
}

func hasS3DataEvents(ctx context.Context, cfg aws.Config) bool {
	ctClient := cloudtrail.NewFromConfig(cfg)
	resp, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return false
	}
	for _, trail := range resp.TrailList {
		selResp, err := ctClient.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{
			TrailName: trail.TrailARN,
		})
		if err != nil {
			continue
		}
		for _, sel := range selResp.EventSelectors {
			for _, dr := range sel.DataResources {
				if aws.ToString(dr.Type) == "AWS::S3::Object" {
					return true
				}
			}
		}
		for _, adv := range selResp.AdvancedEventSelectors {
			for _, fs := range adv.FieldSelectors {
				if aws.ToString(fs.Field) == "resources.type" {
					for _, v := range fs.Equals {
						if v == "AWS::S3::Object" {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func AuditS3(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := s3.NewFromConfig(cfg)

	listResp, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	var names []string
	for _, b := range listResp.Buckets {
		if b.Name != nil {
			names = append(names, *b.Name)
		}
	}

	return audit.ProcessAllMulti(
		ctx,
		names,
		"Auditing S3 buckets",
		func(ctx context.Context, name string) []audit.Finding {
			var publicBlocked, encrypted, versioning, logging bool

			pab, err := client.GetPublicAccessBlock(
				ctx,
				&s3.GetPublicAccessBlockInput{Bucket: &name},
			)
			if err == nil && pab.PublicAccessBlockConfiguration != nil {
				c := pab.PublicAccessBlockConfiguration
				publicBlocked = aws.ToBool(c.BlockPublicAcls) && aws.ToBool(c.BlockPublicPolicy) &&
					aws.ToBool(c.IgnorePublicAcls) &&
					aws.ToBool(c.RestrictPublicBuckets)
			}

			enc, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: &name})
			if err == nil && enc.ServerSideEncryptionConfiguration != nil {
				encrypted = len(enc.ServerSideEncryptionConfiguration.Rules) > 0
			}

			ver, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: &name})
			if err == nil {
				versioning = ver.Status == types.BucketVersioningStatusEnabled
			}

			logResp, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: &name})
			if err == nil {
				logging = logResp.LoggingEnabled != nil
			}

			var tags map[string]string
			tagResp, err := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: &name})
			if err == nil {
				tags = make(map[string]string, len(tagResp.TagSet))
				for _, t := range tagResp.TagSet {
					tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				}
			}

			var results []audit.Finding
			if !publicBlocked {
				risk := "HIGH"
				if !encrypted {
					risk = "CRITICAL"
				}
				d := "public access block not fully enabled"
				results = append(
					results,
					audit.Finding{
						Service:    "s3",
						ResourceID: name,
						Tags:       tags,
						Check:      "public_access",
						Status:     statusFromRisk(risk),
						Detail:     d,
						RiskLevel:  risk,
						Remediation: remediation.Recommend(
							"security",
							"s3",
							"public_access",
							name,
							d,
						),
					},
				)
			}
			if !encrypted {
				d := "default encryption not configured"
				results = append(
					results,
					audit.Finding{
						Service:    "s3",
						ResourceID: name,
						Tags:       tags,
						Check:      "no_encryption",
						Status:     "FAIL",
						Detail:     d,
						RiskLevel:  "MEDIUM",
						Remediation: remediation.Recommend(
							"security",
							"s3",
							"no_encryption",
							name,
							d,
						),
					},
				)
			}
			if !versioning {
				d := "versioning not enabled"
				results = append(
					results,
					audit.Finding{
						Service:    "s3",
						ResourceID: name,
						Tags:       tags,
						Check:      "no_versioning",
						Status:     "FAIL",
						Detail:     d,
						RiskLevel:  "LOW",
						Remediation: remediation.Recommend(
							"security",
							"s3",
							"no_versioning",
							name,
							d,
						),
					},
				)
			}
			if !logging {
				d := "access logging not enabled"
				results = append(
					results,
					audit.Finding{
						Service:     "s3",
						ResourceID:  name,
						Tags:        tags,
						Check:       "no_logging",
						Status:      "FAIL",
						Detail:      d,
						RiskLevel:   "LOW",
						Remediation: remediation.Recommend("security", "s3", "no_logging", name, d),
					},
				)
			}
			if len(results) == 0 {
				results = append(
					results,
					audit.Finding{
						Service:    "s3",
						ResourceID: name,
						Tags:       tags,
						Check:      "s3_posture",
						Status:     "PASS",
						Detail:     "public_blocked=true, encrypted=true, versioning=true, logging=true",
						RiskLevel:  "MINIMAL",
					},
				)
			}
			return results
		},
	), nil
}
