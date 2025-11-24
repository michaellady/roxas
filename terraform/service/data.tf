# Data Sources - SSM Parameter Lookups for Shared Infrastructure
#
# All infrastructure (VPC, RDS, Security Groups, ACM) is managed by terraform/shared/
# and exported via SSM parameters. This module consumes those values.

# VPC and Networking
data "aws_ssm_parameter" "vpc_id" {
  name = "/roxas/${var.environment}/shared/vpc-id"
}

data "aws_ssm_parameter" "private_subnet_ids" {
  name = "/roxas/${var.environment}/shared/private-subnet-ids"
}

data "aws_ssm_parameter" "lambda_sg_id" {
  name = "/roxas/${var.environment}/shared/lambda-sg-id"
}

# RDS Database
data "aws_ssm_parameter" "rds_endpoint" {
  name = "/roxas/${var.environment}/shared/rds-endpoint"
}

data "aws_ssm_parameter" "rds_port" {
  name = "/roxas/${var.environment}/shared/rds-port"
}

data "aws_ssm_parameter" "db_credentials_secret_arn" {
  name = "/roxas/${var.environment}/shared/db-credentials-secret-arn"
}

data "aws_ssm_parameter" "db_credentials_secret_name" {
  name = "/roxas/${var.environment}/shared/db-credentials-secret-name"
}

data "aws_ssm_parameter" "db_master_username" {
  name = "/roxas/${var.environment}/shared/db-master-username"
}

data "aws_ssm_parameter" "db_master_database" {
  name = "/roxas/${var.environment}/shared/db-master-database"
}

# ACM Certificate and DNS
data "aws_ssm_parameter" "acm_certificate_arn" {
  name = "/roxas/${var.environment}/shared/acm-certificate-arn"
}

data "aws_ssm_parameter" "hosted_zone_id" {
  name = "/roxas/${var.environment}/shared/hosted-zone-id"
}

# Read shared DB credentials from Secrets Manager
data "aws_secretsmanager_secret" "shared_db" {
  arn = data.aws_ssm_parameter.db_credentials_secret_arn.value
}

data "aws_secretsmanager_secret_version" "shared_db" {
  secret_id = data.aws_secretsmanager_secret.shared_db.id
}

# Local values derived from SSM parameters
# Note: AWS provider 6.x marks SSM values as sensitive by default.
# Use nonsensitive() for values that are not secrets (VPC IDs, subnet IDs, etc.)
locals {
  # Parse JSON arrays from SSM (nonsensitive - these are infrastructure IDs, not secrets)
  private_subnet_ids = nonsensitive(jsondecode(data.aws_ssm_parameter.private_subnet_ids.value))

  # Shared infrastructure values (nonsensitive - these are not secrets)
  vpc_id                   = nonsensitive(data.aws_ssm_parameter.vpc_id.value)
  lambda_security_group_id = nonsensitive(data.aws_ssm_parameter.lambda_sg_id.value)
  rds_endpoint             = nonsensitive(data.aws_ssm_parameter.rds_endpoint.value)
  rds_port                 = nonsensitive(data.aws_ssm_parameter.rds_port.value)
  acm_certificate_arn      = nonsensitive(data.aws_ssm_parameter.acm_certificate_arn.value)
  hosted_zone_id           = nonsensitive(data.aws_ssm_parameter.hosted_zone_id.value)

  # Shared DB credentials (keep sensitive - this contains passwords)
  shared_db_credentials = jsondecode(data.aws_secretsmanager_secret_version.shared_db.secret_string)
}
