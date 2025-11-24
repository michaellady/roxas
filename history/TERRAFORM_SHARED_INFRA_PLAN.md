# Terraform Shared Infrastructure Architecture Plan

**Bead**: roxas-ozuh
**Date**: 2024-11-24
**Status**: Awaiting Approval

## Executive Summary

Separate "permanent" infrastructure (VPC, RDS, Security Groups) from "ephemeral" service infrastructure (Lambda, API Gateway). **Eliminate the concept of a separate "dev" environment** - dev account only has PR environments that all share the same infrastructure.

## Environment Model

| Account | Shared Infra | Service Deployments |
|---------|--------------|---------------------|
| **Dev** | VPC, shared RDS, SGs | PR environments only (`dev-pr-N`) |
| **Prod** | VPC, dedicated RDS, SGs | Single `prod` deployment |

**Key insight**: There is no standalone "dev" service. The dev account exists solely to support PR preview environments.

## Current vs Proposed Architecture

### Current (Complex)
```
terraform/
├── service/           # Mixed: creates VPC/RDS for dev/prod, references for PRs
│   ├── vpc.tf         # count = is_pr ? 0 : 1 (conditional creation)
│   ├── rds.tf         # count = is_pr ? 0 : 1 (conditional creation)
│   └── ...
├── shared-rds/        # Separate: shared RDS for PRs only
```

**Problems:**
- `service/` has complex conditional logic everywhere
- Two separate RDS concepts (dedicated vs shared)
- "dev" workspace creates redundant infrastructure

### Proposed (Simple)
```
terraform/
├── shared/            # All shared infra per account
│   ├── vpc.tf         # VPC, subnets, NAT
│   ├── rds.tf         # THE database for this account
│   ├── security_groups.tf
│   ├── cleanup_lambda.tf   # DB cleanup (dev only)
│   ├── ssm.tf         # Parameters for service/
│   └── ...
│
├── service/           # Lambda + API GW only (always uses data sources)
│   ├── main.tf        # Lambda, API Gateway
│   ├── data.tf        # Read from SSM (no conditionals!)
│   ├── secrets.tf     # Per-deployment secrets
│   ├── custom_domain.tf
│   └── ...
```

**Benefits:**
- No conditional resource creation in `service/`
- Single RDS per account (shared in dev, dedicated in prod)
- `shared-rds/` merges into `shared/` (it's all shared infra)
- ~50% less conditional logic

## Workspace Strategy

| Directory | Dev Account | Prod Account |
|-----------|-------------|--------------|
| `shared/` | `dev` workspace | `prod` workspace |
| `service/` | `dev-pr-N` workspaces only | `prod` workspace only |

**Note**: No `dev` workspace in `service/` - PRs are the dev environment.

## Resource Distribution

### `terraform/shared/` (per account)

| Resource | Dev Account | Prod Account |
|----------|-------------|--------------|
| VPC + Subnets | ✓ | ✓ |
| NAT (fck-nat) | ✓ | ✓ |
| RDS PostgreSQL | Shared (all PRs use it) | Dedicated |
| Lambda SG | ✓ | ✓ |
| RDS SG | ✓ | ✓ |
| Cleanup Lambda | ✓ (drops PR databases) | ✗ |
| SSM Parameters | ✓ | ✓ |

### `terraform/service/` (per deployment)

| Resource | All Environments |
|----------|------------------|
| Lambda Function | ✓ |
| API Gateway | ✓ |
| IAM Role/Policies | ✓ |
| CloudWatch Logs | ✓ |
| Secrets Manager (values) | ✓ |
| Route53 A Record | ✓ |
| ACM Certificate | ✓ |

## SSM Parameter Contract

`shared/` writes these parameters for `service/` to consume:

```
/roxas/{env}/shared/vpc-id
/roxas/{env}/shared/private-subnet-ids      # JSON array
/roxas/{env}/shared/lambda-sg-id
/roxas/{env}/shared/rds-endpoint
/roxas/{env}/shared/rds-port
/roxas/{env}/shared/db-credentials-secret-arn
/roxas/{env}/shared/db-master-username
/roxas/{env}/shared/db-master-database      # "roxas_shared" for dev, "roxas" for prod
```

## Service Module Simplification

### Before (current service/vpc.tf)
```hcl
# Complex conditional logic
data "aws_vpc" "existing" {
  count = local.is_pr_environment ? 1 : 0
  # ...
}

resource "aws_vpc" "main" {
  count = local.is_pr_environment ? 0 : 1
  # ...
}

locals {
  vpc_id = local.is_pr_environment ? data.aws_vpc.existing[0].id : aws_vpc.main[0].id
}
```

### After (new service/data.tf)
```hcl
# Simple - always read from SSM
data "aws_ssm_parameter" "vpc_id" {
  name = "/roxas/${var.environment}/shared/vpc-id"
}

data "aws_ssm_parameter" "private_subnets" {
  name = "/roxas/${var.environment}/shared/private-subnet-ids"
}

data "aws_ssm_parameter" "lambda_sg_id" {
  name = "/roxas/${var.environment}/shared/lambda-sg-id"
}

locals {
  vpc_id             = data.aws_ssm_parameter.vpc_id.value
  private_subnet_ids = jsondecode(data.aws_ssm_parameter.private_subnets.value)
  lambda_sg_id       = data.aws_ssm_parameter.lambda_sg_id.value
}
```

**No conditionals. No counts. Just data sources.**

## Database Strategy

### Dev Account (Shared RDS)
- Single RDS instance: `roxas-shared-rds`
- Master database: `roxas_shared`
- Each PR gets its own database: `pr_123`, `pr_124`, etc.
- Lambda auto-creates PR database on first startup
- Cleanup Lambda drops database when PR closes

### Prod Account (Dedicated RDS)
- Single RDS instance: `roxas-prod-rds`
- Single database: `roxas`
- No cleanup needed (persistent)

## GitHub Workflows

### New: `shared-infra.yml`
```yaml
name: Deploy Shared Infrastructure

on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Environment'
        required: true
        type: choice
        options: [dev, prod]
      action:
        description: 'Action'
        required: true
        type: choice
        options: [plan, apply]

  push:
    branches: [main]
    paths:
      - 'terraform/shared/**'

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: ${{ inputs.environment || 'dev' }}
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3

      - name: Configure AWS
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - name: Init & Plan
        working-directory: terraform/shared
        run: |
          terraform init -backend-config=../backend-${{ env.ENV }}.hcl
          terraform workspace select ${{ env.ENV }} || terraform workspace new ${{ env.ENV }}
          terraform plan -var-file=../${{ env.ENV }}.tfvars -out=tfplan

      - name: Apply
        if: inputs.action == 'apply' || github.event_name == 'push'
        working-directory: terraform/shared
        run: terraform apply -auto-approve tfplan
```

### Modified: `pr-deploy-dev.yml`
- Remove all VPC/RDS creation logic (it never runs for PRs anyway)
- Simplify to just Lambda + API Gateway deployment
- Remove `is_pr_environment` checks

### Modified: `main-deploy-prod.yml`
- Change to use data sources instead of creating VPC/RDS
- Same pattern as PR deployments

### Removed: `pr-cleanup-dev.yml` changes
- DB cleanup Lambda invocation stays (now in shared/)
- Terraform destroy stays (only destroys Lambda/API GW)

## Migration Plan

### Phase 1: Create `shared/` Module
1. Create `terraform/shared/` directory
2. Move VPC, RDS, SG code from `service/`
3. Merge `shared-rds/` cleanup Lambda into `shared/`
4. Add SSM parameter exports
5. Add dev-specific cleanup Lambda (conditional on environment)

### Phase 2: Import Dev Infrastructure
```bash
cd terraform/shared
terraform init -backend-config=../backend-dev.hcl
terraform workspace new dev

# Import existing resources
terraform import aws_vpc.main vpc-xxx
terraform import 'aws_subnet.private[0]' subnet-xxx
# ... all resources

terraform plan -var-file=../dev.tfvars  # Should show no changes
```

### Phase 3: Simplify `service/`
1. Delete `vpc.tf`, `security_groups.tf`
2. Simplify `rds.tf` (only data sources for credentials)
3. Create `data.tf` with SSM lookups
4. Remove all `is_pr_environment` conditionals
5. Remove `dev` workspace from service/

### Phase 4: Add GitHub Workflow
1. Create `shared-infra.yml`
2. Update `pr-deploy-dev.yml` (simplify)
3. Update `main-deploy-prod.yml` (use data sources)

### Phase 5: Deploy to Prod
1. `terraform apply` shared/ in prod account
2. `terraform apply` service/ in prod (now uses data sources)

## Files to Delete

After migration:
- `terraform/service/vpc.tf` - moved to shared/
- `terraform/service/security_groups.tf` - moved to shared/
- `terraform/shared-rds/` directory - merged into shared/

## Implementation Beads (to create after approval)

1. Create `terraform/shared/` module with VPC, RDS, SGs, SSM exports
2. Merge cleanup Lambda from `shared-rds/` into `shared/`
3. Import existing dev infrastructure into `shared/` state
4. Simplify `service/` to use SSM data sources (delete vpc.tf, security_groups.tf)
5. Create `shared-infra.yml` GitHub workflow
6. Deploy `shared/` to prod and migrate prod service/
7. Delete `terraform/shared-rds/` directory
8. Update README.md documentation

## Decision Points

1. **Cleanup Lambda in prod?** No - prod has persistent database, no PR cleanup needed
2. **Auto-apply shared/ on merge?** Recommend: Yes for dev, manual approval for prod
3. **ACM wildcard cert**: Keep in service/ (per-deployment) or move to shared/?

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| State migration | Medium | Do dev first, verify plan shows no changes |
| Service downtime | Low | Imports don't change infra, only state |
| PR deployments break | Medium | Test with one PR before full rollout |

## Success Criteria

1. `terraform/shared/` deploys VPC, RDS, SGs independently
2. `terraform/service/` has zero VPC/RDS/SG resources
3. No `is_pr_environment` conditionals in service/
4. PR deployments work unchanged
5. New `shared-infra.yml` workflow operational
6. Zero downtime during migration
