# Shared RDS Infrastructure

This directory contains the Terraform configuration for the **shared RDS instance** used by PR deployments.

## Purpose

Instead of each PR deployment creating its own RDS instance (slow and expensive), this shared RDS instance hosts multiple databases - one per PR. Each PR gets its own database via `CREATE DATABASE pr_N`.

## Architecture

- **Single RDS instance**: `roxas-shared-pr-rds` (db.t4g.micro, 20GB)
- **Shared across**: All PR deployments
- **Cost savings**: ~$24/month for 3 concurrent PRs
- **Performance**: 200x faster PR deployments (6min → 30sec)

## Deployment

This is deployed **separately** from app resources and only needs to be deployed once:

```bash
# Initialize
terraform init \
  -backend-config="bucket=roxas-terraform-state-dev" \
  -backend-config="key=shared-rds/terraform.tfstate" \
  -backend-config="region=us-east-1" \
  -backend-config="dynamodb_table=roxas-terraform-locks-dev"

# Deploy
AWS_PROFILE=dev-admin terraform apply
```

## Dependencies

Requires existing VPC infrastructure from main app deployment:
- VPC: `roxas-webhook-handler-dev-vpc`
- Private subnets: `roxas-webhook-handler-dev-private-*`
- RDS security group: `roxas-webhook-handler-dev-rds-sg`

## Outputs

After deployment, outputs include connection details that PR workflows use to create per-PR databases.
