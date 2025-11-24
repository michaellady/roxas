terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Remote state backend for shared RDS
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region
}

# Reference existing VPC from dev environment
data "aws_vpc" "main" {
  filter {
    name   = "tag:Name"
    values = ["roxas-webhook-handler-dev-vpc"]
  }
}

# Reference existing private subnets
data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.main.id]
  }

  filter {
    name   = "tag:Name"
    values = ["roxas-webhook-handler-dev-private-*"]
  }
}

# Reference existing RDS security group
data "aws_security_group" "rds" {
  vpc_id = data.aws_vpc.main.id

  filter {
    name   = "tag:Name"
    values = ["roxas-webhook-handler-dev-rds-sg"]
  }
}

locals {
  common_tags = {
    Project     = "Roxas"
    Environment = "dev"
    ManagedBy   = "Terraform"
    Purpose     = "shared-pr-rds"
  }
}

# Shared RDS Infrastructure
# Provides a single RDS instance shared across multiple PR deployments
# Each PR gets its own database (CREATE DATABASE pr_N) instead of a dedicated RDS instance

# DB Subnet Group for shared RDS
resource "aws_db_subnet_group" "shared" {
  name       = "roxas-shared-pr-rds-subnet-group"
  subnet_ids = data.aws_subnets.private.ids

  tags = merge(local.common_tags, {
    Name = "roxas-shared-pr-rds-subnet-group"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Generate random password for shared RDS
resource "random_password" "shared_db_password" {
  length  = 32
  special = true
  # Exclude characters that might cause issues in connection strings
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Shared RDS PostgreSQL Instance
resource "aws_db_instance" "shared" {
  identifier = "roxas-shared-pr-rds"

  # Engine configuration
  engine            = "postgres"
  engine_version    = var.db_engine_version
  instance_class    = "db.t4g.micro" # Sufficient for 1-3 concurrent PRs
  allocated_storage = 20             # Room for ~5 PR databases
  storage_type      = "gp3"
  storage_encrypted = true

  # Database configuration
  db_name  = "roxas_shared" # Master database
  username = "roxas_app"    # Application user with CREATE DATABASE privilege
  password = random_password.shared_db_password.result
  port     = 5432

  # Network configuration
  db_subnet_group_name   = aws_db_subnet_group.shared.name
  vpc_security_group_ids = [data.aws_security_group.rds.id]
  publicly_accessible    = false
  multi_az               = false # Single-AZ for dev cost savings

  # Using default parameter group
  # max_connections for db.t4g.micro = 100 (sufficient for ~20 connections per PR)

  # Backup configuration
  backup_retention_period = 1                     # Minimal retention for dev
  backup_window           = "03:00-04:00"         # UTC
  maintenance_window      = "Mon:04:00-Mon:05:00" # UTC

  # Protection and monitoring
  deletion_protection             = false # Allow destruction for dev
  skip_final_snapshot             = true  # No final snapshot needed for dev
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  performance_insights_enabled    = false
  auto_minor_version_upgrade      = true

  tags = merge(local.common_tags, {
    Name        = "roxas-shared-pr-rds"
    Description = "Shared RDS instance for all PR deployments"
  })

  lifecycle {
    prevent_destroy = false
    ignore_changes = [
      # Ignore password changes after initial creation
      password,
    ]
  }
}

# Store shared RDS credentials in Secrets Manager
resource "aws_secretsmanager_secret" "shared_db_credentials" {
  name_prefix             = "roxas-shared-pr-rds-credentials-"
  description             = "Credentials for shared PR RDS instance"
  recovery_window_in_days = 0 # Immediate deletion for dev

  tags = merge(local.common_tags, {
    Name = "roxas-shared-pr-rds-credentials"
  })
}

resource "aws_secretsmanager_secret_version" "shared_db_credentials" {
  secret_id = aws_secretsmanager_secret.shared_db_credentials.id
  secret_string = jsonencode({
    username = aws_db_instance.shared.username
    password = random_password.shared_db_password.result
    engine   = "postgres"
    host     = aws_db_instance.shared.address
    port     = aws_db_instance.shared.port
    dbname   = aws_db_instance.shared.db_name
  })
}

# SSM Parameter to store the secret name for dynamic discovery by PR workspaces
resource "aws_ssm_parameter" "shared_db_secret_name" {
  name        = "/roxas/shared-rds/credentials-secret-name"
  description = "Name of the Secrets Manager secret containing shared RDS credentials"
  type        = "String"
  value       = aws_secretsmanager_secret.shared_db_credentials.name

  tags = merge(local.common_tags, {
    Purpose     = "shared-pr-rds"
    Environment = "dev"
  })
}

# CloudWatch alarm for high connection count
resource "aws_cloudwatch_metric_alarm" "shared_rds_connections" {
  alarm_name          = "roxas-shared-pr-rds-high-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 300 # 5 minutes
  statistic           = "Average"
  threshold           = 60 # Alert at 60 connections (~75% of 80 max for t4g.micro)
  alarm_description   = "Alert when shared RDS connections exceed 60. Max ~80 for t4g.micro. Each PR Lambda should use max 10 connections."

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.shared.id
  }

  tags = local.common_tags
}

# CloudWatch alarm for storage space
resource "aws_cloudwatch_metric_alarm" "shared_rds_storage" {
  alarm_name          = "roxas-shared-pr-rds-low-storage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300 # 5 minutes
  statistic           = "Average"
  threshold           = 4294967296 # 4 GB (20% of 20GB)
  alarm_description   = "Alert when shared RDS free storage drops below 4 GB. Scaling trigger: >16GB usage = upgrade to db.t4g.small"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.shared.id
  }

  tags = local.common_tags
}

# CloudWatch alarm for CPU utilization
resource "aws_cloudwatch_metric_alarm" "shared_rds_cpu" {
  alarm_name          = "roxas-shared-pr-rds-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300 # 5 minutes
  statistic           = "Average"
  threshold           = 80 # Alert at 80% CPU
  alarm_description   = "Alert when shared RDS CPU exceeds 80%. Sustained high CPU may indicate need to upgrade instance class."

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.shared.id
  }

  tags = local.common_tags
}

# CloudWatch alarm for freeable memory
resource "aws_cloudwatch_metric_alarm" "shared_rds_memory" {
  alarm_name          = "roxas-shared-pr-rds-low-memory"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "FreeableMemory"
  namespace           = "AWS/RDS"
  period              = 300 # 5 minutes
  statistic           = "Average"
  threshold           = 104857600 # 100 MB (t4g.micro has ~400MB available)
  alarm_description   = "Alert when shared RDS freeable memory drops below 100 MB. Low memory may indicate need to upgrade instance class."

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.shared.id
  }

  tags = local.common_tags
}

# CloudWatch Dashboard for shared RDS health monitoring
resource "aws_cloudwatch_dashboard" "shared_rds" {
  dashboard_name = "roxas-shared-rds-health"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Database Connections"
          region = var.aws_region
          metrics = [
            ["AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", aws_db_instance.shared.id, { label = "Active Connections" }]
          ]
          annotations = {
            horizontal = [
              { label = "Warning (60)", value = 60, color = "#ff7f0e" },
              { label = "Max (~80)", value = 80, color = "#d62728" }
            ]
          }
          yAxis  = { left = { min = 0, max = 100 } }
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "CPU Utilization"
          region = var.aws_region
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", aws_db_instance.shared.id, { label = "CPU %" }]
          ]
          annotations = {
            horizontal = [
              { label = "Warning (80%)", value = 80, color = "#ff7f0e" }
            ]
          }
          yAxis  = { left = { min = 0, max = 100 } }
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Free Storage Space"
          region = var.aws_region
          metrics = [
            ["AWS/RDS", "FreeStorageSpace", "DBInstanceIdentifier", aws_db_instance.shared.id, { label = "Free Space (bytes)" }]
          ]
          annotations = {
            horizontal = [
              { label = "Warning (4GB)", value = 4294967296, color = "#ff7f0e" }
            ]
          }
          period = 300
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Freeable Memory"
          region = var.aws_region
          metrics = [
            ["AWS/RDS", "FreeableMemory", "DBInstanceIdentifier", aws_db_instance.shared.id, { label = "Freeable Memory (bytes)" }]
          ]
          annotations = {
            horizontal = [
              { label = "Warning (100MB)", value = 104857600, color = "#ff7f0e" }
            ]
          }
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "Read/Write IOPS"
          region = var.aws_region
          metrics = [
            ["AWS/RDS", "ReadIOPS", "DBInstanceIdentifier", aws_db_instance.shared.id, { label = "Read IOPS" }],
            ["AWS/RDS", "WriteIOPS", "DBInstanceIdentifier", aws_db_instance.shared.id, { label = "Write IOPS" }]
          ]
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "Network Throughput"
          region = var.aws_region
          metrics = [
            ["AWS/RDS", "NetworkReceiveThroughput", "DBInstanceIdentifier", aws_db_instance.shared.id, { label = "Receive (bytes/sec)" }],
            ["AWS/RDS", "NetworkTransmitThroughput", "DBInstanceIdentifier", aws_db_instance.shared.id, { label = "Transmit (bytes/sec)" }]
          ]
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "text"
        x      = 0
        y      = 18
        width  = 24
        height = 3
        properties = {
          markdown = <<-EOT
## Shared RDS Capacity Guidelines
- **Instance**: db.t4g.micro (~80 max connections, ~400MB RAM)
- **Connection Pool**: Each PR Lambda should use max 10 connections
- **Comfortable capacity**: 3 concurrent PRs (30 connections + overhead)
- **Scaling trigger**: Consistently >3 PRs OR >16GB disk usage → upgrade to db.t4g.small
EOT
        }
      }
    ]
  })
}
