package cost

import (
	"context"
	"fmt"
	"time"

	"sift/audit"
	"sift/audit/pricing"
	"sift/audit/progress"
	"sift/audit/remediation"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func init() {
	audit.RegisterAWS(Module, "glue", AuditGlueCost)
}

type glueCostJob struct {
	name string
	tags map[string]string
}

func parseGlueCostJob(
	ctx context.Context,
	client *glue.Client,
	job gluetypes.Job,
	region, accountID string,
) glueCostJob {
	g := glueCostJob{name: aws.ToString(job.Name)}
	arn := fmt.Sprintf("arn:aws:glue:%s:%s:job/%s", region, accountID, g.name)
	tagResp, err := client.GetTags(ctx, &glue.GetTagsInput{ResourceArn: &arn})
	if err == nil {
		g.tags = tagResp.Tags
	}
	return g
}

func AuditGlueCost(ctx context.Context, cfg aws.Config) ([]audit.Finding, error) {
	client := glue.NewFromConfig(cfg)
	stsClient := sts.NewFromConfig(cfg)
	var accountID string
	if resp, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err == nil {
		accountID = aws.ToString(resp.Account)
	}
	region := cfg.Region
	var findings []audit.Finding

	// Idle dev endpoints
	devCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	devResp, err := client.GetDevEndpoints(devCtx, &glue.GetDevEndpointsInput{})
	if err == nil {
		for _, ep := range devResp.DevEndpoints {
			name := aws.ToString(ep.EndpointName)
			dpus := ep.NumberOfNodes
			hourlyCost := pricing.GlueJobHourlyCost("Standard", dpus)
			findings = append(findings, audit.Finding{
				Service:              "glue_dev_endpoint",
				ResourceID:           name,
				Check:                "active_dev_endpoint",
				Status:               "WARN",
				Detail:               fmt.Sprintf("dpus=%d, ~$%.2f/hr", dpus, hourlyCost),
				RiskLevel:            "HIGH",
				EstimatedMonthlyCost: hourlyCost * 730,
				Remediation: remediation.Recommend(
					"cost",
					"glue_dev_endpoint",
					"active_dev_endpoint",
					name,
					fmt.Sprintf("dpus=%d, running 24/7", dpus),
				),
			})
		}
	}

	// Collect all jobs
	spinner := progress.NewSpinner(ctx, "Collecting Glue jobs")
	var allJobs []gluetypes.Job
	jobInput := &glue.GetJobsInput{}
	for {
		jobsResp, err := client.GetJobs(ctx, jobInput)
		if err != nil {
			findings = append(findings, audit.ErrorFinding("glue", "jobs", "list_jobs", err))
			break
		}
		allJobs = append(allJobs, jobsResp.Jobs...)
		spinner.Add(len(jobsResp.Jobs))
		if jobsResp.NextToken == nil {
			break
		}
		jobInput.NextToken = jobsResp.NextToken
	}
	spinner.Finish()

	if len(allJobs) == 0 {
		return findings, nil
	}

	jobFindings := audit.ProcessAllMulti(
		ctx,
		allJobs,
		"Auditing Glue jobs",
		func(ctx context.Context, job gluetypes.Job) []audit.Finding {
			g := parseGlueCostJob(ctx, client, job, region, accountID)
			results := auditGlueJob(ctx, client, job, g.tags)
			if len(results) > 0 {
				return results
			}
			return []audit.Finding{{
				Service:    "glue_job",
				ResourceID: g.name,
				Tags:       g.tags,
				Check:      "glue_job_cost",
				Status:     "PASS",
				Detail:     "no cost issues detected",
				RiskLevel:  "MINIMAL",
			}}
		},
	)
	findings = append(findings, jobFindings...)

	return findings, nil
}

func auditGlueJob(
	ctx context.Context,
	client *glue.Client,
	job gluetypes.Job,
	tags map[string]string,
) []audit.Finding {
	name := aws.ToString(job.Name)
	runsResp, err := client.GetJobRuns(ctx, &glue.GetJobRunsInput{
		JobName:    &name,
		MaxResults: aws.Int32(1),
	})
	if err != nil {
		return []audit.Finding{audit.ErrorFinding("glue_job", name, "get_job_runs", err)}
	}
	if len(runsResp.JobRuns) == 0 {
		return nil
	}

	lastRun := runsResp.JobRuns[0]
	var findings []audit.Finding

	if string(lastRun.JobRunState) == "FAILED" {
		findings = append(findings, audit.Finding{
			Service:    "glue_job",
			ResourceID: name,
			Tags:       tags,
			Check:      "failed_job",
			Status:     "WARN",
			Detail:     fmt.Sprintf("last run failed: %s", aws.ToString(lastRun.ErrorMessage)),
			RiskLevel:  "MEDIUM",
			Remediation: remediation.Recommend(
				"cost",
				"glue_job",
				"failed_job",
				name,
				"last run failed",
			),
		})
	}

	if lastRun.CompletedOn != nil {
		days := int(time.Since(*lastRun.CompletedOn).Hours() / 24)
		if days > audit.GetThresholds(ctx).
			GetInt("glue", "unused_days", 90) {
			findings = append(findings, audit.Finding{
				Service:    "glue_job",
				ResourceID: name,
				Tags:       tags,
				Check:      "unused_job",
				Status:     "WARN",
				Detail:     fmt.Sprintf("last run %d days ago", days),
				RiskLevel:  "LOW",
				Remediation: remediation.Recommend(
					"cost",
					"glue_job",
					"unused_job",
					name,
					fmt.Sprintf("last run %d days ago", days),
				),
			})
		}
	}

	workers := aws.ToInt32(job.NumberOfWorkers)
	workerType := string(job.WorkerType)
	if job.Command != nil && aws.ToString(job.Command.Name) == "glueetl" && workers <= 2 &&
		lastRun.ExecutionTime < 600 {
		sparkCost := pricing.GlueJobHourlyCost(workerType, workers)
		shellCost := pricing.GlueJobHourlyCost("G.025X", 1)
		runtimeHours := float64(lastRun.ExecutionTime) / 3600.0
		monthlySavings := (sparkCost - shellCost) * runtimeHours * 30

		findings = append(findings, audit.Finding{
			Service:    "glue_job",
			ResourceID: name,
			Tags:       tags,
			Check:      "consider_python_shell",
			Status:     "WARN",
			Detail: fmt.Sprintf(
				"workers=%d, runtime=%ds, small Spark job could be Python Shell ($0.0625 vs $%.2f/DPU/hr)",
				workers,
				lastRun.ExecutionTime,
				sparkCost/float64(workers),
			),
			RiskLevel:            "LOW",
			EstimatedMonthlyCost: monthlySavings,
			Remediation: remediation.Recommend(
				"cost",
				"glue_job",
				"consider_python_shell",
				name,
				fmt.Sprintf("workers=%d, runtime=%ds", workers, lastRun.ExecutionTime),
			),
		})
	}

	if string(job.WorkerType) == "G.2X" {
		findings = append(findings, audit.Finding{
			Service:    "glue_job",
			ResourceID: name,
			Tags:       tags,
			Check:      "expensive_worker_type",
			Status:     "WARN",
			Detail:     "using G.2X workers (8vCPU/32GB at $0.88/DPU/hr), consider G.1X if memory allows",
			RiskLevel:  "MEDIUM",
			Remediation: remediation.Recommend(
				"cost",
				"glue_job",
				"expensive_worker_type",
				name,
				"using G.2X workers",
			),
		})
	}

	// Flex execution class opportunity
	if job.Command != nil && aws.ToString(job.Command.Name) == "glueetl" &&
		string(job.ExecutionClass) != "FLEX" && lastRun.ExecutionTime > 0 {
		standardCost := pricing.GlueJobHourlyCost(workerType, workers)
		flexCost := standardCost * 0.65
		runtimeHrs := float64(lastRun.ExecutionTime) / 3600.0
		flexSavings := (standardCost - flexCost) * runtimeHrs * 30

		findings = append(findings, audit.Finding{
			Service:    "glue_job",
			ResourceID: name,
			Tags:       tags,
			Check:      "consider_flex",
			Status:     "WARN",
			Detail: fmt.Sprintf(
				"STANDARD class, switch to FLEX for ~35%% savings (suitable for non-urgent batch jobs)",
			),
			RiskLevel:            "LOW",
			EstimatedMonthlyCost: flexSavings,
			Remediation: remediation.Recommend(
				"cost",
				"glue_job",
				"consider_flex",
				name,
				fmt.Sprintf(
					"STANDARD class, workers=%d, runtime=%ds",
					workers,
					lastRun.ExecutionTime,
				),
			),
		})
	}

	if string(lastRun.JobRunState) == "SUCCEEDED" && lastRun.ExecutionTime > 0 {
		allocated := aws.ToFloat64(lastRun.MaxCapacity)
		if allocated == 0 {
			allocated = float64(aws.ToInt32(lastRun.NumberOfWorkers))
		}
		if allocated > 0 {
			dpuSeconds := aws.ToFloat64(lastRun.DPUSeconds)
			maxDPUSeconds := allocated * float64(lastRun.ExecutionTime)
			if maxDPUSeconds > 0 {
				utilization := dpuSeconds / maxDPUSeconds * 100
				if utilization < 30 {
					findings = append(findings, audit.Finding{
						Service:    "glue_job",
						ResourceID: name,
						Tags:       tags,
						Check:      "overprovisioned_job",
						Status:     "WARN",
						Detail: fmt.Sprintf(
							"allocated=%.0f DPUs, utilization=%.0f%%, consider reducing workers",
							allocated,
							utilization,
						),
						RiskLevel: "MEDIUM",
						Remediation: remediation.Recommend(
							"cost",
							"glue_job",
							"overprovisioned_job",
							name,
							fmt.Sprintf("Utilization %.0f%%", utilization),
						),
					})
				}
			}
		}
	}

	return findings
}
