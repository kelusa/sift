package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sift/audit"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	tagtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
)

const Module = "governance"

var serviceToResourceType = map[string][]string{
	"ec2":           {"ec2:instance"},
	"rds":           {"rds:db"},
	"s3":            {"s3"},
	"lambda":        {"lambda:function"},
	"dynamodb":      {"dynamodb:table"},
	"eks":           {"eks:cluster"},
	"elasticache":   {"elasticache:cluster"},
	"opensearch":    {"opensearch:domain"},
	"redshift":      {"redshift:cluster"},
	"sagemaker":     {"sagemaker:notebook-instance"},
	"glue":          {"glue:job"},
	"kinesis":       {"kinesis:stream"},
	"kms":           {"kms:key"},
	"elb":           {"elasticloadbalancing:loadbalancer"},
	"sqs":           {"sqs:queue"},
	"sns":           {"sns:topic"},
	"stepfunctions": {"states:stateMachine"},
}

type conditionalTag struct {
	WhenTag    string   `json:"when_tag"`
	WhenValues []string `json:"when_values"`
}

type taggingConfig struct {
	BaselineTags    []string                  `json:"baseline_tags"`
	IaCTags         []string                  `json:"iac_tags"`
	CostTags        []string                  `json:"cost_tags"`
	OwnershipTags   []string                  `json:"ownership_tags"`
	ConditionalTags map[string]conditionalTag `json:"conditional_tags"`
}

func init() {
	audit.RegisterAWS(Module, "tagging", AuditTagging)
}

func loadTaggingConfig() (taggingConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return taggingConfig{}, fmt.Errorf(
			"tagging policy not configured: create ~/.sift/tagging.json",
		)
	}
	data, err := os.ReadFile(filepath.Join(home, ".sift", "tagging.json"))
	if err != nil {
		return taggingConfig{}, fmt.Errorf(
			"tagging policy not configured: create ~/.sift/tagging.json",
		)
	}
	var cfg taggingConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return taggingConfig{}, fmt.Errorf("invalid ~/.sift/tagging.json: %w", err)
	}
	if len(cfg.BaselineTags) == 0 && len(cfg.IaCTags) == 0 && len(cfg.CostTags) == 0 &&
		len(cfg.ConditionalTags) == 0 {
		return taggingConfig{}, fmt.Errorf(
			"tagging policy is empty: define at least one tag tier in ~/.sift/tagging.json",
		)
	}
	return cfg, nil
}

func resourceTypesForServices(services []string) []string {
	if len(services) == 0 {
		var all []string
		for _, rt := range serviceToResourceType {
			all = append(all, rt...)
		}
		return all
	}
	var types []string
	for _, svc := range services {
		if rt, ok := serviceToResourceType[svc]; ok {
			types = append(types, rt...)
		}
	}
	return types
}

func hasTagCI(tagKeysLower map[string]bool, tag string) bool {
	return tagKeysLower[strings.ToLower(tag)]
}

func getTagValueCI(tagMap map[string]string, tag string) (string, bool) {
	for k, v := range tagMap {
		if strings.EqualFold(k, tag) {
			return v, true
		}
	}
	return "", false
}

func AuditTagging(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	tagCfg, err := loadTaggingConfig()
	if err != nil {
		return nil, err
	}

	client := resourcegroupstaggingapi.NewFromConfig(cfg)
	resourceTypes := resourceTypesForServices(audit.GetServices(ctx))

	var resources []tagtypes.ResourceTagMapping
	input := &resourcegroupstaggingapi.GetResourcesInput{
		ResourceTypeFilters: resourceTypes,
	}
	for {
		resp, err := client.GetResources(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("get resources: %w", err)
		}
		resources = append(resources, resp.ResourceTagMappingList...)
		if resp.PaginationToken == nil || *resp.PaginationToken == "" {
			break
		}
		input.PaginationToken = resp.PaginationToken
	}

	return audit.ProcessAllMulti(ctx, resources, "Auditing resource tagging",
		func(_ context.Context, r tagtypes.ResourceTagMapping) []audit.Finding {
			arn := aws.ToString(r.ResourceARN)
			resourceID := arnToID(arn)
			service := arnToService(arn)

			tagMap := make(map[string]string, len(r.Tags))
			tagKeysLower := make(map[string]bool, len(r.Tags))
			for _, t := range r.Tags {
				tagMap[aws.ToString(t.Key)] = aws.ToString(t.Value)
				tagKeysLower[strings.ToLower(aws.ToString(t.Key))] = true
			}

			var results []audit.Finding

			// Tier 1: Baseline
			var missingBaseline []string
			for _, tag := range tagCfg.BaselineTags {
				if !hasTagCI(tagKeysLower, tag) {
					missingBaseline = append(missingBaseline, tag)
				}
			}
			if len(missingBaseline) > 0 {
				d := fmt.Sprintf("missing baseline tags: %s", strings.Join(missingBaseline, ", "))
				results = append(results, audit.Finding{
					Service:    service,
					ResourceID: resourceID,
					Tags:       tagMap,
					Check:      "missing_baseline_tags",
					Status:     "FAIL",
					Detail:     d,
					RiskLevel:  "CRITICAL",
					Remediation: remediation.Recommend(
						"governance",
						"tagging",
						"missing_baseline_tags",
						arn,
						d,
					),
				})
			}

			// Tier 2: IaC compliance
			var missingIaC []string
			for _, tag := range tagCfg.IaCTags {
				if !hasTagCI(tagKeysLower, tag) {
					missingIaC = append(missingIaC, tag)
				}
			}
			if len(missingIaC) > 0 {
				d := fmt.Sprintf("missing IaC tags: %s", strings.Join(missingIaC, ", "))
				results = append(results, audit.Finding{
					Service:    service,
					ResourceID: resourceID,
					Tags:       tagMap,
					Check:      "missing_iac_tags",
					Status:     "FAIL",
					Detail:     d,
					RiskLevel:  "HIGH",
					Remediation: remediation.Recommend(
						"governance",
						"tagging",
						"missing_iac_tags",
						arn,
						d,
					),
				})
			}

			// Tier 3: Cost allocation
			var missingCost []string
			for _, tag := range tagCfg.CostTags {
				if !hasTagCI(tagKeysLower, tag) {
					missingCost = append(missingCost, tag)
				}
			}
			if len(missingCost) > 0 {
				d := fmt.Sprintf("missing cost tags: %s", strings.Join(missingCost, ", "))
				results = append(results, audit.Finding{
					Service:    service,
					ResourceID: resourceID,
					Tags:       tagMap,
					Check:      "missing_cost_tags",
					Status:     "FAIL",
					Detail:     d,
					RiskLevel:  "MEDIUM",
					Remediation: remediation.Recommend(
						"governance",
						"tagging",
						"missing_cost_tags",
						arn,
						d,
					),
				})
			}

			// Conditional tags
			for tag, cond := range tagCfg.ConditionalTags {
				envVal, hasEnv := getTagValueCI(tagMap, cond.WhenTag)
				if !hasEnv {
					continue
				}
				match := false
				for _, v := range cond.WhenValues {
					if strings.EqualFold(envVal, v) {
						match = true
						break
					}
				}
				if match && !hasTagCI(tagKeysLower, tag) {
					d := fmt.Sprintf(
						"missing %s tag (required when %s=%s)",
						tag,
						cond.WhenTag,
						envVal,
					)
					results = append(results, audit.Finding{
						Service:    service,
						ResourceID: resourceID,
						Tags:       tagMap,
						Check:      "missing_conditional_tag",
						Status:     "FAIL",
						Detail:     d,
						RiskLevel:  "HIGH",
						Remediation: remediation.Recommend(
							"governance",
							"tagging",
							"missing_conditional_tag",
							arn,
							d,
						),
					})
				}
			}

			if len(results) == 0 {
				results = append(results, audit.Finding{
					Service:    service,
					ResourceID: resourceID,
					Tags:       tagMap,
					Check:      "tagging_posture",
					Status:     "PASS",
					Detail:     "all required tags present",
					RiskLevel:  "MINIMAL",
				})
			}

			return results
		},
	), nil
}

func Audit(ctx context.Context, cfg aws.Config, services []string) ([]audit.Finding, error) {
	ctx = audit.WithServices(ctx, services)
	checks := audit.GetChecks(ctx)
	checkers := audit.CheckersFor(Module)
	if len(checks) > 0 {
		var filtered []audit.Checker
		for _, c := range checkers {
			for _, ch := range checks {
				if c.Name == ch {
					filtered = append(filtered, c)
				}
			}
		}
		checkers = filtered
	}
	return audit.RunChecks(ctx, cfg, nil, checkers, "Auditing governance")
}

func arnToService(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 3 {
		return parts[2]
	}
	return "unknown"
}

func arnToID(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 6 {
		resource := strings.Join(parts[5:], ":")
		if idx := strings.LastIndex(resource, "/"); idx >= 0 {
			return resource[idx+1:]
		}
		return resource
	}
	return arn
}
