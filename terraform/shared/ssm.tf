# SSM Parameters
# Exports shared infrastructure values for service/ to consume

resource "aws_ssm_parameter" "vpc_id" {
  name        = "/roxas/${var.environment}/shared/vpc-id"
  description = "VPC ID for ${var.environment} environment"
  type        = "String"
  value       = aws_vpc.main.id

  tags = local.common_tags
}

resource "aws_ssm_parameter" "private_subnet_ids" {
  name        = "/roxas/${var.environment}/shared/private-subnet-ids"
  description = "Private subnet IDs for ${var.environment} environment (JSON array)"
  type        = "String"
  value       = jsonencode(aws_subnet.private[*].id)

  tags = local.common_tags
}

resource "aws_ssm_parameter" "public_subnet_ids" {
  name        = "/roxas/${var.environment}/shared/public-subnet-ids"
  description = "Public subnet IDs for ${var.environment} environment (JSON array)"
  type        = "String"
  value       = jsonencode(aws_subnet.public[*].id)

  tags = local.common_tags
}

resource "aws_ssm_parameter" "lambda_sg_id" {
  name        = "/roxas/${var.environment}/shared/lambda-sg-id"
  description = "Lambda security group ID for ${var.environment} environment"
  type        = "String"
  value       = aws_security_group.lambda.id

  tags = local.common_tags
}

resource "aws_ssm_parameter" "rds_sg_id" {
  name        = "/roxas/${var.environment}/shared/rds-sg-id"
  description = "RDS security group ID for ${var.environment} environment"
  type        = "String"
  value       = aws_security_group.rds.id

  tags = local.common_tags
}

resource "aws_ssm_parameter" "rds_endpoint" {
  name        = "/roxas/${var.environment}/shared/rds-endpoint"
  description = "RDS endpoint for ${var.environment} environment"
  type        = "String"
  value       = aws_db_instance.main.address

  tags = local.common_tags
}

resource "aws_ssm_parameter" "rds_port" {
  name        = "/roxas/${var.environment}/shared/rds-port"
  description = "RDS port for ${var.environment} environment"
  type        = "String"
  value       = tostring(aws_db_instance.main.port)

  tags = local.common_tags
}

resource "aws_ssm_parameter" "db_credentials_secret_arn" {
  name        = "/roxas/${var.environment}/shared/db-credentials-secret-arn"
  description = "Secrets Manager ARN for database credentials"
  type        = "String"
  value       = aws_secretsmanager_secret.db_credentials.arn

  tags = local.common_tags
}

resource "aws_ssm_parameter" "db_credentials_secret_name" {
  name        = "/roxas/${var.environment}/shared/db-credentials-secret-name"
  description = "Secrets Manager name for database credentials"
  type        = "String"
  value       = aws_secretsmanager_secret.db_credentials.name

  tags = local.common_tags
}

resource "aws_ssm_parameter" "db_master_username" {
  name        = "/roxas/${var.environment}/shared/db-master-username"
  description = "Database master username"
  type        = "String"
  value       = aws_db_instance.main.username

  tags = local.common_tags
}

resource "aws_ssm_parameter" "db_master_database" {
  name        = "/roxas/${var.environment}/shared/db-master-database"
  description = "Database master database name"
  type        = "String"
  value       = aws_db_instance.main.db_name

  tags = local.common_tags
}

resource "aws_ssm_parameter" "acm_certificate_arn" {
  name        = "/roxas/${var.environment}/shared/acm-certificate-arn"
  description = "ACM certificate ARN for ${var.environment} environment"
  type        = "String"
  value       = aws_acm_certificate_validation.main.certificate_arn

  tags = local.common_tags
}

resource "aws_ssm_parameter" "hosted_zone_id" {
  name        = "/roxas/${var.environment}/shared/hosted-zone-id"
  description = "Route53 hosted zone ID for ${var.environment} environment"
  type        = "String"
  value       = local.hosted_zone_id

  tags = local.common_tags
}
