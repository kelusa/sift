module sift

go 1.25.0

require (
	github.com/aws/aws-sdk-go-v2 v1.43.6
	github.com/aws/aws-sdk-go-v2/config v1.32.16
	github.com/aws/aws-sdk-go-v2/service/acm v1.39.5
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.66.2
	github.com/aws/aws-sdk-go-v2/service/backup v1.56.0
	github.com/aws/aws-sdk-go-v2/service/bedrock v1.66.6
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.65.1
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.55.10
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.56.2
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.69.1
	github.com/aws/aws-sdk-go-v2/service/configservice v1.62.4
	github.com/aws/aws-sdk-go-v2/service/costexplorer v1.65.1
	github.com/aws/aws-sdk-go-v2/service/databasemigrationservice v1.62.2
	github.com/aws/aws-sdk-go-v2/service/directoryservice v1.38.20
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.57.3
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.299.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.57.1
	github.com/aws/aws-sdk-go-v2/service/efs v1.41.17
	github.com/aws/aws-sdk-go-v2/service/eks v1.82.1
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.52.3
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.54.12
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.46.6
	github.com/aws/aws-sdk-go-v2/service/glue v1.140.0
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.75.2
	github.com/aws/aws-sdk-go-v2/service/iam v1.53.8
	github.com/aws/aws-sdk-go-v2/service/kafka v1.52.2
	github.com/aws/aws-sdk-go-v2/service/kinesis v1.43.7
	github.com/aws/aws-sdk-go-v2/service/kms v1.52.0
	github.com/aws/aws-sdk-go-v2/service/lambda v1.90.0
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.70.1
	github.com/aws/aws-sdk-go-v2/service/quicksight v1.112.0
	github.com/aws/aws-sdk-go-v2/service/rds v1.118.1
	github.com/aws/aws-sdk-go-v2/service/redshift v1.62.8
	github.com/aws/aws-sdk-go-v2/service/resourceexplorer2 v1.24.6
	github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi v1.33.2
	github.com/aws/aws-sdk-go-v2/service/route53 v1.63.2
	github.com/aws/aws-sdk-go-v2/service/s3 v1.100.0
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.242.0
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.41.6
	github.com/aws/aws-sdk-go-v2/service/servicequotas v1.34.7
	github.com/aws/aws-sdk-go-v2/service/sfn v1.41.0
	github.com/aws/aws-sdk-go-v2/service/shield v1.34.23
	github.com/aws/aws-sdk-go-v2/service/sns v1.40.1
	github.com/aws/aws-sdk-go-v2/service/sqs v1.44.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.42.0
	github.com/aws/aws-sdk-go-v2/service/timestreamwrite v1.35.25
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.71.5
	github.com/schollz/progressbar/v3 v3.19.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.9
	golang.org/x/term v0.28.0
	modernc.org/sqlite v1.52.0
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.10 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.15 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.22 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.37 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.37 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.30 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.12.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.22 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.22 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.20 // indirect
	github.com/aws/smithy-go v1.27.8 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/sys v0.42.0 // indirect
	modernc.org/libc v1.72.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
