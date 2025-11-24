# Security Groups for RDS and Lambda
# PR environments: Reference existing dev Lambda SG
# Non-PR environments: Create new Lambda SG

# Data source: Reference existing dev Lambda security group for PR environments
data "aws_security_group" "existing_lambda" {
  count = local.is_pr_environment ? 1 : 0

  vpc_id = local.vpc_id

  filter {
    name   = "tag:Name"
    values = ["roxas-webhook-handler-dev-lambda-sg"]
  }
}

# Security Group for RDS PostgreSQL
# Only create for non-PR environments (PR environments use shared RDS)
resource "aws_security_group" "rds" {
  count = local.is_pr_environment ? 0 : 1

  name_prefix = "${var.function_name}-${var.environment}-rds-"
  description = "Security group for RDS PostgreSQL instance"
  vpc_id      = local.vpc_id

  # Allow PostgreSQL access from Lambda
  ingress {
    description     = "PostgreSQL from Lambda"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [local.lambda_security_group_id]
  }

  # Allow all outbound traffic
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-rds-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Security Group for Lambda
# Only create for non-PR environments (PR environments use shared dev Lambda SG)
resource "aws_security_group" "lambda" {
  count = local.is_pr_environment ? 0 : 1

  name_prefix = "${var.function_name}-${var.environment}-lambda-"
  description = "Security group for Lambda function"
  vpc_id      = local.vpc_id

  # Allow all outbound traffic (for RDS, Secrets Manager, OpenAI API)
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-lambda-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Local: Unified Lambda security group reference
# Use existing dev Lambda SG for PRs, created SG otherwise
locals {
  lambda_security_group_id = local.is_pr_environment ? data.aws_security_group.existing_lambda[0].id : aws_security_group.lambda[0].id
}
