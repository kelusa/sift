package security

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// IsOpenToWorld returns true if any inbound rule allows 0.0.0.0/0 or ::/0.
func IsOpenToWorld(sg ec2types.SecurityGroup) bool {
	for _, perm := range sg.IpPermissions {
		for _, r := range perm.IpRanges {
			if r.CidrIp != nil && *r.CidrIp == "0.0.0.0/0" {
				return true
			}
		}
		for _, r := range perm.Ipv6Ranges {
			if r.CidrIpv6 != nil && *r.CidrIpv6 == "::/0" {
				return true
			}
		}
	}
	return false
}

// FindOpenSGs fetches security groups by ID in batches and returns a set of
// group IDs that are open to the world.
func FindOpenSGs(ctx context.Context, client *ec2.Client, sgIDs []string) map[string]bool {
	open := make(map[string]bool)
	for i := 0; i < len(sgIDs); i += 200 {
		end := i + 200
		if end > len(sgIDs) {
			end = len(sgIDs)
		}
		sgResp, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
			GroupIds: sgIDs[i:end],
		})
		if err != nil {
			continue
		}
		for _, g := range sgResp.SecurityGroups {
			if IsOpenToWorld(g) {
				open[aws.ToString(g.GroupId)] = true
			}
		}
	}
	return open
}
