# Terraform Remote State Backend

This project uses S3 and DynamoDB for Terraform remote state storage and locking.

## Infrastructure

**S3 Bucket**: `roxas-terraform-state`
- Stores Terraform state files
- Versioning enabled for recovery
- Encrypted at rest (AES256)
- All public access blocked

**DynamoDB Table**: `roxas-terraform-locks`
- Prevents concurrent Terraform operations
- On-demand billing (PAY_PER_REQUEST)
- Partition key: `LockID` (String)

## Initial Setup

Run the backend setup script once to create the S3 bucket and DynamoDB table:

```bash
# With default AWS credentials
./scripts/setup-terraform-backend.sh

# Or with a specific AWS profile
AWS_PROFILE=admin ./scripts/setup-terraform-backend.sh
```

This script is **idempotent** - safe to run multiple times.

## Workspace Strategy

Each PR gets an isolated Terraform workspace to prevent state conflicts:

- **Workspace name**: `dev-pr-{PR_NUMBER}`
- **State path**: `env:/dev-pr-{number}/terraform.tfstate`
- **Example**: PR #42 uses workspace `dev-pr-42`

### In GitHub Actions (pr-deploy-dev.yml)

```bash
# Initialize and select/create workspace
terraform init
terraform workspace new dev-pr-${{ github.event.pull_request.number }} || \
  terraform workspace select dev-pr-${{ github.event.pull_request.number }}

# Deploy with isolated state
terraform plan -var-file=dev.tfvars -out=tfplan
terraform apply -auto-approve tfplan
```

### In Cleanup (pr-cleanup-dev.yml)

```bash
# Select workspace
terraform init
terraform workspace select dev-pr-${{ github.event.pull_request.number }}

# Destroy resources
terraform destroy -var-file=dev.tfvars -auto-approve

# Clean up workspace
terraform workspace select default
terraform workspace delete dev-pr-${{ github.event.pull_request.number }}
```

## Required IAM Permissions

The `github-actions-ci` IAM user needs these additional permissions:

**S3 Permissions**:
```json
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:ListBucket"
  ],
  "Resource": [
    "arn:aws:s3:::roxas-terraform-state",
    "arn:aws:s3:::roxas-terraform-state/*"
  ]
}
```

**DynamoDB Permissions**:
```json
{
  "Effect": "Allow",
  "Action": [
    "dynamodb:GetItem",
    "dynamodb:PutItem",
    "dynamodb:DeleteItem"
  ],
  "Resource": "arn:aws:dynamodb:us-east-1:*:table/roxas-terraform-locks"
}
```

See `iam-policy-backend.json` for the complete policy document.

## Local Development

### Migrating to Remote Backend

After adding the backend configuration, run:

```bash
cd terraform
terraform init

# Terraform will prompt to migrate state to S3
# Answer 'yes' to copy local state to remote backend
```

### Using Workspaces Locally

```bash
# List workspaces
terraform workspace list

# Create/select a workspace for testing
terraform workspace new dev-pr-test
terraform workspace select dev-pr-test

# Work normally
terraform plan -var-file=dev.tfvars
terraform apply -var-file=dev.tfvars

# Clean up when done
terraform destroy -var-file=dev.tfvars
terraform workspace select default
terraform workspace delete dev-pr-test
```

## State Locking

DynamoDB locking prevents multiple operations from running simultaneously:

- ✅ **Prevents state corruption** from concurrent operations
- ✅ **Automatic** - no configuration needed
- ✅ **Fast** - acquire/release locks in milliseconds
- ✅ **Cheap** - costs pennies per month

If a lock is held (e.g., workflow is running), Terraform will wait or fail with:
```
Error acquiring the state lock
```

## Troubleshooting

### Lock is Stuck

If a workflow crashes and leaves a lock, you can force unlock:

```bash
# Get the Lock ID from the error message
terraform force-unlock <LOCK_ID>
```

### State File Corruption

S3 versioning allows recovery:

1. Go to S3 console
2. Navigate to `roxas-terraform-state` bucket
3. Find the corrupted state file
4. Restore a previous version

### Workspace Not Found

If cleanup fails and workspace still exists:

```bash
terraform workspace select dev-pr-<number>
terraform destroy -var-file=dev.tfvars -auto-approve
terraform workspace select default
terraform workspace delete dev-pr-<number>
```

## Cost

- **S3**: ~$0.023/GB/month + negligible request costs
- **DynamoDB**: On-demand, ~$1.25 per million requests
- **Expected monthly cost**: < $1

State files are small (KB), and locking operations are infrequent.
