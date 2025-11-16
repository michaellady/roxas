# Roxas Terraform Infrastructure

This directory contains Terraform configuration for deploying the Roxas webhook handler to AWS Lambda with API Gateway.

## Architecture

- **Lambda Function**: Go binary running on `provided.al2023` runtime
- **API Gateway HTTP API**: Exposes `/webhook` endpoint for GitHub webhooks
- **IAM Role**: Lambda execution role with CloudWatch Logs permissions
- **CloudWatch Logs**: Separate log groups for Lambda and API Gateway

## Prerequisites

1. **AWS CLI** configured with appropriate credentials
2. **Terraform** >= 1.0 installed
3. **Lambda deployment package** built at `../bin/bootstrap.zip`

## Setup

### 1. Build the Lambda deployment package

From the project root:
```bash
make build
```

This creates `bin/bootstrap.zip` with the Go binary.

### 2. Configure variables

Copy the example variables file:
```bash
cd terraform
cp example.tfvars terraform.tfvars
```

Edit `terraform.tfvars` and set your actual values:
```hcl
openai_api_key        = "sk-..."
linkedin_access_token = "your-token"
github_webhook_secret = "your-secret"
```

### 3. Initialize Terraform

```bash
terraform init
```

### 4. Validate configuration

```bash
terraform validate
```

### 5. Preview changes

```bash
terraform plan
```

### 6. Deploy infrastructure

```bash
terraform apply
```

## Outputs

After deployment, Terraform outputs:

- `webhook_url`: Full URL to configure in GitHub (e.g., `https://xyz.execute-api.us-east-1.amazonaws.com/webhook`)
- `lambda_function_name`: Name of the deployed Lambda function
- `cloudwatch_log_group`: Log group for monitoring

## Testing

Configure the webhook URL in your GitHub repository settings:
1. Go to Settings → Webhooks → Add webhook
2. Set Payload URL to the `webhook_url` output
3. Set Content type to `application/json`
4. Set Secret to your `github_webhook_secret`
5. Select "Let me select individual events" → Check "Pull requests"

## Monitoring

View Lambda logs:
```bash
aws logs tail /aws/lambda/roxas-webhook-handler --follow
```

View API Gateway logs:
```bash
aws logs tail /aws/apigateway/roxas-webhook-handler --follow
```

## Cleanup

To destroy all resources:
```bash
terraform destroy
```

## Security Notes

- **Secrets**: Never commit `terraform.tfvars` (it's gitignored)
- **State**: Terraform state may contain sensitive data; consider using remote state with encryption
- **IAM**: Lambda role uses least-privilege permissions (CloudWatch Logs only)
