# Shared Infrastructure Module
# Deploys permanent resources shared across all service deployments:
# - VPC, Subnets, NAT
# - RDS PostgreSQL
# - Security Groups
# - ACM Certificate
# - Cleanup Lambda (dev only)
# - CloudWatch Monitoring

provider "aws" {
  region = var.aws_region
}

# Get current AWS account ID
data "aws_caller_identity" "current" {}

# Get available AZs
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  # Resource naming prefix
  name_prefix = "roxas-${var.environment}"

  # Common tags for all resources
  common_tags = merge(var.tags, {
    Environment = var.environment
    Module      = "shared"
  })

  # Dev-specific: enable cleanup lambda
  enable_cleanup_lambda = var.environment == "dev"

  # Database configuration differs by environment
  db_name     = var.environment == "dev" ? "roxas_shared" : "roxas"
  db_username = var.environment == "dev" ? "roxas_app" : "roxas_admin"

  # Hosted zone IDs
  hosted_zone_id = var.environment == "prod" ? var.prod_hosted_zone_id : var.dev_hosted_zone_id

  # ACM domain - wildcard for dev, apex for prod
  acm_domain_name = var.environment == "prod" ? var.prod_domain_name : "*.${var.dev_domain_name}"
  acm_san         = var.environment == "prod" ? [] : [var.dev_domain_name]
}
