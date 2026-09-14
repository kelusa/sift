package security

import (
	"context"
	"fmt"

	"sift/audit"
	"sift/audit/progress"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func init() {
	audit.RegisterAWS(Module, "ec2", AuditEC2)
}

type ec2Instance struct {
	instanceID  string
	privateIP   *string
	publicIP    bool
	imdsV1      bool
	openToWorld bool
	roleARN     *string
	tags        map[string]string
}

func AuditEC2(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	instances, err := listEC2Instances(ctx, cfg)
	if err != nil {
		return nil, err
	}
	var findings []audit.Finding
	for _, inst := range instances {
		risk := ec2Risk(inst)
		detail := fmt.Sprintf(
			"public_ip=%t, imdsv1=%t, open_to_world=%t",
			inst.publicIP,
			inst.imdsV1,
			inst.openToWorld,
		)
		if inst.roleARN != nil {
			detail += fmt.Sprintf(", role=%s", *inst.roleARN)
		}

		// Compute remediation recommendation
		var rem *audit.Remediation
		if risk != "MINIMAL" {
			rem = remediation.Recommend("security", "ec2", "ec2_posture", inst.instanceID, detail)
		}

		findings = append(findings, audit.Finding{
			Service:     "ec2",
			ResourceID:  inst.instanceID,
			Tags:        inst.tags,
			Check:       "instance_exposure",
			Status:      statusFromRisk(risk),
			Detail:      detail,
			RiskLevel:   risk,
			Remediation: rem,
		})
	}
	return findings, nil
}

func ListEC2Targets(ctx context.Context, cfg aws.Config) ([]TriageTarget, error) {
	instances, err := listEC2Instances(ctx, cfg)
	if err != nil {
		return nil, err
	}
	var targets []TriageTarget
	for _, inst := range instances {
		targets = append(targets, TriageTarget{
			ResourceID:  inst.instanceID,
			Service:     "ec2",
			PrivateIP:   inst.privateIP,
			RoleARN:     inst.roleARN,
			OpenToWorld: inst.openToWorld,
			IMDSv1:      inst.imdsV1,
		})
	}
	return targets, nil
}

func ListEC2TargetByID(
	ctx context.Context,
	cfg aws.Config,
	instanceID string,
) (*TriageTarget, error) {
	client := ec2.NewFromConfig(cfg)
	resp, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe instances: %w", err)
	}
	if len(resp.Reservations) == 0 || len(resp.Reservations[0].Instances) == 0 {
		return nil, fmt.Errorf("instance not found: %s", instanceID)
	}
	raw := &resp.Reservations[0].Instances[0]
	inst := parseInstance(raw)

	// Fetch SGs for this single instance
	var sgIDs []string
	for _, sg := range raw.SecurityGroups {
		if sg.GroupId != nil {
			sgIDs = append(sgIDs, *sg.GroupId)
		}
	}
	if len(sgIDs) > 0 {
		openSGs := FindOpenSGs(ctx, client, sgIDs)
		for _, id := range sgIDs {
			if openSGs[id] {
				inst.openToWorld = true
				break
			}
		}
	}
	return &TriageTarget{
		ResourceID:  inst.instanceID,
		Service:     "ec2",
		PrivateIP:   inst.privateIP,
		RoleARN:     inst.roleARN,
		OpenToWorld: inst.openToWorld,
		IMDSv1:      inst.imdsV1,
	}, nil
}

func listEC2Instances(ctx context.Context, cfg aws.Config) ([]ec2Instance, error) {
	client := ec2.NewFromConfig(cfg)
	bar := progress.NewSpinner(ctx, "Scanning EC2 instances")

	// Collect all raw instances
	type rawInstance struct {
		inst  ec2Instance
		sgIDs []string
	}
	var raw []rawInstance

	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe instances: %w", err)
		}
		for _, res := range page.Reservations {
			for _, inst := range res.Instances {
				r := rawInstance{inst: parseInstance(&inst)}
				for _, sg := range inst.SecurityGroups {
					if sg.GroupId != nil {
						r.sgIDs = append(r.sgIDs, *sg.GroupId)
					}
				}
				raw = append(raw, r)
				bar.Add(1)
			}
		}
	}
	bar.Finish()

	// Deduplicate SG IDs and batch-fetch
	sgSet := make(map[string]bool)
	for _, r := range raw {
		for _, id := range r.sgIDs {
			sgSet[id] = true
		}
	}
	var sgIDs []string
	for id := range sgSet {
		sgIDs = append(sgIDs, id)
	}
	openSGs := FindOpenSGs(ctx, client, sgIDs)

	// Assign openToWorld from the map
	results := make([]ec2Instance, len(raw))
	for i, r := range raw {
		r.inst.openToWorld = false
		for _, id := range r.sgIDs {
			if openSGs[id] {
				r.inst.openToWorld = true
				break
			}
		}
		results[i] = r.inst
	}
	return results, nil
}

func parseInstance(inst *ec2types.Instance) ec2Instance {
	result := ec2Instance{
		privateIP: inst.PrivateIpAddress,
		publicIP:  inst.PublicIpAddress != nil,
		imdsV1:    true,
	}
	if inst.InstanceId != nil {
		result.instanceID = *inst.InstanceId
	}
	if inst.MetadataOptions != nil {
		result.imdsV1 = string(inst.MetadataOptions.HttpTokens) == "optional"
	}
	if inst.IamInstanceProfile != nil && inst.IamInstanceProfile.Arn != nil {
		result.roleARN = inst.IamInstanceProfile.Arn
	}
	result.tags = make(map[string]string, len(inst.Tags))
	for _, t := range inst.Tags {
		result.tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return result
}

func ec2Risk(inst ec2Instance) string {
	switch {
	case inst.publicIP && inst.openToWorld:
		return "CRITICAL"
	case inst.openToWorld:
		return "HIGH"
	case inst.publicIP && inst.imdsV1:
		return "HIGH"
	case inst.publicIP:
		return "MEDIUM"
	case inst.imdsV1:
		return "MEDIUM"
	default:
		return "MINIMAL"
	}
}
