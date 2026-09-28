package list

import (
	"context"
	"fmt"
	"strconv"

	"sift/audit"
	"sift/audit/progress"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func init() {
	Register(Lister{
		Service:  "glue",
		SubTypes: []string{"jobs", "crawlers"},
		Columns: map[string][]Column{
			"job": {
				{Key: "command", Header: "CMD"},
				{Key: "workers", Header: "WORKERS"},
				{Key: "runs_last_30", Header: "RUNS(30)"},
				{Key: "avg_dpu_hours", Header: "AVG DPU-HR"},
				{Key: "last_run_time", Header: "LAST RUN"},
				{Key: "last_run_status", Header: "STATUS"},
			},
			"crawler": {
				{Key: "state", Header: "STATE"},
				{Key: "schedule", Header: "SCHEDULE"},
				{Key: "last_crawl_status", Header: "LAST STATUS"},
				{Key: "last_crawl_time", Header: "LAST CRAWL"},
				{Key: "version", Header: "VERSION"},
			},
		},
		Fn: func(ctx context.Context, cfg aws.Config, subType string) ([]audit.Resource, error) {
			switch subType {
			case "jobs":
				return ListGlueJobs(ctx, cfg)
			case "crawlers":
				return ListGlueCrawlers(ctx, cfg)
			default:
				jobs, err := ListGlueJobs(ctx, cfg)
				if err != nil {
					return nil, err
				}
				crawlers, err := ListGlueCrawlers(ctx, cfg)
				if err != nil {
					return nil, err
				}
				return append(jobs, crawlers...), nil
			}
		},
	})
}

func getAccountID(ctx context.Context, cfg aws.Config) string {
	client := sts.NewFromConfig(cfg)
	resp, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return ""
	}
	return aws.ToString(resp.Account)
}

func ListGlueJobs(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := glue.NewFromConfig(cfg)
	accountID := getAccountID(ctx, cfg)
	spinner := progress.NewSpinner(ctx, "Listing Glue jobs")

	var resources []audit.Resource
	input := &glue.GetJobsInput{}
	for {
		resp, err := client.GetJobs(ctx, input)
		if err != nil {
			spinner.Finish()
			return nil, fmt.Errorf("get jobs: %w", err)
		}
		for _, job := range resp.Jobs {
			props := map[string]string{
				"glue_version": aws.ToString(job.GlueVersion),
				"worker_type":  string(job.WorkerType),
				"workers":      strconv.Itoa(int(aws.ToInt32(job.NumberOfWorkers))),
				"max_capacity": fmt.Sprintf("%.0f", aws.ToFloat64(job.MaxCapacity)),
				"timeout":      strconv.Itoa(int(aws.ToInt32(job.Timeout))),
			}
			if job.Command != nil {
				props["command"] = aws.ToString(job.Command.Name)
			}
			if job.CreatedOn != nil {
				props["created"] = job.CreatedOn.Format("2006-01-02")
			}
			if job.LastModifiedOn != nil {
				props["modified"] = job.LastModifiedOn.Format("2006-01-02")
			}

			runsResp, err := client.GetJobRuns(ctx, &glue.GetJobRunsInput{
				JobName:    job.Name,
				MaxResults: aws.Int32(30),
			})
			if err == nil && len(runsResp.JobRuns) > 0 {
				lastRun := runsResp.JobRuns[0]
				if lastRun.StartedOn != nil {
					props["last_run_time"] = lastRun.StartedOn.Format("2006-01-02")
				}
				props["last_run_status"] = string(lastRun.JobRunState)

				// Calculate run frequency and avg DPU consumption
				var totalDPU float64
				runCount := 0
				for _, run := range runsResp.JobRuns {
					if run.JobRunState == "SUCCEEDED" || run.JobRunState == "FAILED" {
						runCount++
						dpu := aws.ToFloat64(run.MaxCapacity)
						if dpu == 0 {
							dpu = float64(aws.ToInt32(run.NumberOfWorkers))
						}
						var hours float64
						if run.ExecutionTime > 0 {
							hours = float64(run.ExecutionTime) / 3600.0
						}
						totalDPU += dpu * hours
					}
				}
				if runCount > 0 {
					props["runs_last_30"] = strconv.Itoa(runCount)
					props["avg_dpu_hours"] = fmt.Sprintf("%.1f", totalDPU/float64(runCount))
				}
			}

			r := audit.Resource{
				Service:    "glue",
				ResourceID: aws.ToString(job.Name),
				Type:       "job",
				Properties: props,
			}

			arn := fmt.Sprintf(
				"arn:aws:glue:%s:%s:job/%s",
				cfg.Region,
				accountID,
				aws.ToString(job.Name),
			)
			tagResp, err := client.GetTags(ctx, &glue.GetTagsInput{ResourceArn: &arn})
			if err == nil && tagResp.Tags != nil {
				r.Tags = tagResp.Tags
			}

			resources = append(resources, r)
		}
		spinner.Add(len(resp.Jobs))
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}
	spinner.Finish()
	return resources, nil
}

func ListGlueCrawlers(ctx context.Context, cfg aws.Config) ([]audit.Resource, error) {
	client := glue.NewFromConfig(cfg)
	accountID := getAccountID(ctx, cfg)
	spinner := progress.NewSpinner(ctx, "Listing Glue crawlers")

	var resources []audit.Resource
	input := &glue.GetCrawlersInput{}
	for {
		resp, err := client.GetCrawlers(ctx, input)
		if err != nil {
			spinner.Finish()
			return nil, fmt.Errorf("get crawlers: %w", err)
		}
		for _, c := range resp.Crawlers {
			props := map[string]string{
				"state":   string(c.State),
				"version": strconv.FormatInt(c.Version, 10),
			}
			if c.LastCrawl != nil {
				props["last_crawl_status"] = string(c.LastCrawl.Status)
				if c.LastCrawl.StartTime != nil {
					props["last_crawl_time"] = c.LastCrawl.StartTime.Format("2006-01-02")
				}
			}
			if c.Schedule != nil {
				props["schedule"] = aws.ToString(c.Schedule.ScheduleExpression)
			}

			r := audit.Resource{
				Service:    "glue",
				ResourceID: aws.ToString(c.Name),
				Type:       "crawler",
				Properties: props,
			}

			arn := fmt.Sprintf(
				"arn:aws:glue:%s:%s:crawler/%s",
				cfg.Region,
				accountID,
				aws.ToString(c.Name),
			)
			tagResp, err := client.GetTags(ctx, &glue.GetTagsInput{ResourceArn: &arn})
			if err == nil && tagResp.Tags != nil {
				r.Tags = tagResp.Tags
			}

			resources = append(resources, r)
		}
		spinner.Add(len(resp.Crawlers))
		if resp.NextToken == nil {
			break
		}
		input.NextToken = resp.NextToken
	}
	spinner.Finish()
	return resources, nil
}
