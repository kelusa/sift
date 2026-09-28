package triage

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

// EKSTarget represents an EKS cluster to investigate
type EKSTarget struct {
	Name string
}

type eksResult struct {
	cluster        string
	nodegroupIssue string
	tgIssues       []string
	sgIssues       []string
	certIssue      string
}

// RunEKS investigates EKS clusters for incident triage.
func RunEKS(ctx context.Context, cfg aws.Config, clusterName string) ([]audit.Finding, error) {
	eksClient := eks.NewFromConfig(cfg)
	elbClient := elasticloadbalancingv2.NewFromConfig(cfg)
	acmClient := acm.NewFromConfig(cfg)

	var clusters []string
	if clusterName != "" {
		clusters = []string{clusterName}
	} else {
		resp, err := eksClient.ListClusters(ctx, &eks.ListClustersInput{})
		if err != nil {
			return nil, fmt.Errorf("list clusters: %w", err)
		}
		clusters = resp.Clusters
	}

	results := audit.FetchAll(
		ctx,
		clusters,
		"Triaging EKS clusters",
		func(ctx context.Context, name string) eksResult {
			r := eksResult{cluster: name}

			// 1. Nodegroup health
			r.nodegroupIssue = checkNodegroups(ctx, eksClient, name)

			// 2. Target group health (LBs tagged with cluster)
			r.tgIssues = checkTargetGroups(ctx, elbClient, name)

			// 3. Cert expiry on associated LBs
			r.certIssue = checkCerts(ctx, elbClient, acmClient, name)

			return r
		},
	)

	var findings []audit.Finding
	for _, r := range results {
		var issues []string
		if r.nodegroupIssue != "" {
			issues = append(issues, r.nodegroupIssue)
		}
		issues = append(issues, r.tgIssues...)
		if r.certIssue != "" {
			issues = append(issues, r.certIssue)
		}

		risk := eksTriageRisk(r)
		status := "FAIL"
		if risk == "LOW" {
			status = "PASS"
		}

		detail := "no issues detected"
		if len(issues) > 0 {
			detail = strings.Join(issues, "; ")
		}

		findings = append(findings, audit.Finding{
			Service:    "eks",
			ResourceID: r.cluster,
			Check:      "incident_triage",
			Status:     status,
			Detail:     detail,
			RiskLevel:  risk,
		})
	}
	return findings, nil
}

func checkNodegroups(ctx context.Context, client *eks.Client, cluster string) string {
	resp, err := client.ListNodegroups(ctx, &eks.ListNodegroupsInput{ClusterName: &cluster})
	if err != nil {
		slog.Warn("list nodegroups failed", "cluster", cluster, "error", err)
		return ""
	}
	if len(resp.Nodegroups) == 0 {
		return "no nodegroups"
	}
	for _, ng := range resp.Nodegroups {
		desc, err := client.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
			ClusterName:   &cluster,
			NodegroupName: &ng,
		})
		if err != nil {
			continue
		}
		ngd := desc.Nodegroup
		if ngd.ScalingConfig != nil {
			desired := aws.ToInt32(ngd.ScalingConfig.DesiredSize)
			if desired == 0 {
				return fmt.Sprintf("nodegroup %s desired=0", ng)
			}
		}
		if ngd.Health != nil && len(ngd.Health.Issues) > 0 {
			return fmt.Sprintf("nodegroup %s unhealthy: %s",
				ng, string(ngd.Health.Issues[0].Code))
		}
	}
	return ""
}

func checkTargetGroups(
	ctx context.Context,
	client *elasticloadbalancingv2.Client,
	cluster string,
) []string {
	var issues []string
	resp, err := client.DescribeTargetGroups(
		ctx,
		&elasticloadbalancingv2.DescribeTargetGroupsInput{},
	)
	if err != nil {
		slog.Warn("describe target groups failed", "cluster", cluster, "error", err)
		return nil
	}
	for _, tg := range resp.TargetGroups {
		// Match TGs by name convention (k8s tags TGs with cluster name)
		name := aws.ToString(tg.TargetGroupName)
		if !strings.Contains(strings.ToLower(name), strings.ToLower(cluster)) {
			continue
		}
		health, err := client.DescribeTargetHealth(
			ctx,
			&elasticloadbalancingv2.DescribeTargetHealthInput{
				TargetGroupArn: tg.TargetGroupArn,
			},
		)
		if err != nil {
			continue
		}
		unhealthy := 0
		total := len(health.TargetHealthDescriptions)
		for _, t := range health.TargetHealthDescriptions {
			if t.TargetHealth != nil &&
				t.TargetHealth.State != elbtypes.TargetHealthStateEnumHealthy {
				unhealthy++
			}
		}
		if total > 0 && unhealthy == total {
			issues = append(
				issues,
				fmt.Sprintf("target_group %s: all %d targets unhealthy", name, total),
			)
		} else if unhealthy > 0 {
			issues = append(issues, fmt.Sprintf("target_group %s: %d/%d targets unhealthy", name, unhealthy, total))
		}
	}
	return issues
}

func checkCerts(
	ctx context.Context,
	elbClient *elasticloadbalancingv2.Client,
	acmClient *acm.Client,
	cluster string,
) string {
	// Find LBs associated with this cluster
	lbs, err := elbClient.DescribeLoadBalancers(
		ctx,
		&elasticloadbalancingv2.DescribeLoadBalancersInput{},
	)
	if err != nil {
		return ""
	}
	for _, lb := range lbs.LoadBalancers {
		name := aws.ToString(lb.LoadBalancerName)
		if !strings.Contains(strings.ToLower(name), strings.ToLower(cluster)) {
			continue
		}
		listeners, err := elbClient.DescribeListeners(
			ctx,
			&elasticloadbalancingv2.DescribeListenersInput{
				LoadBalancerArn: lb.LoadBalancerArn,
			},
		)
		if err != nil {
			continue
		}
		for _, l := range listeners.Listeners {
			for _, cert := range l.Certificates {
				if cert.CertificateArn == nil {
					continue
				}
				desc, err := acmClient.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
					CertificateArn: cert.CertificateArn,
				})
				if err != nil {
					continue
				}
				c := desc.Certificate
				if c.Status == acmtypes.CertificateStatusExpired {
					return fmt.Sprintf("cert expired: %s", aws.ToString(cert.CertificateArn))
				}
				if c.NotAfter != nil && time.Until(*c.NotAfter) < 24*time.Hour {
					return fmt.Sprintf(
						"cert expires within 24h: %s",
						aws.ToString(cert.CertificateArn),
					)
				}
			}
		}
	}
	return ""
}

func eksTriageRisk(r eksResult) string {
	// All targets unhealthy = critical
	for _, issue := range r.tgIssues {
		if strings.Contains(issue, "all") && strings.Contains(issue, "unhealthy") {
			return "CRITICAL"
		}
	}
	// Cert expired
	if strings.Contains(r.certIssue, "expired") {
		return "CRITICAL"
	}
	// No nodegroups or desired=0
	if strings.Contains(r.nodegroupIssue, "desired=0") || r.nodegroupIssue == "no nodegroups" {
		return "HIGH"
	}
	// Nodegroup unhealthy
	if r.nodegroupIssue != "" {
		return "HIGH"
	}
	// Partial target unhealthy
	if len(r.tgIssues) > 0 {
		return "HIGH"
	}
	// Cert expiring soon
	if r.certIssue != "" {
		return "MEDIUM"
	}
	return "LOW"
}
