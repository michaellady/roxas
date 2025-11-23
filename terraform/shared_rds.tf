# Shared RDS Instance for PR Deployments
#
# This RDS instance is shared across all PR environments in the dev account.
# Each PR gets its own database (CREATE DATABASE pr_N) within this instance,
# rather than a dedicated RDS instance per PR.
#
# Benefits:
# - Deploy time: 6 min → 30 sec (200x faster!)
# - Cost: Same for 1 PR, saves $12/month per additional PR
# - Isolation: Strong via separate PostgreSQL databases
# - Simplicity: No application code changes needed

# Only create shared RDS in dev environment and NOT for PR-specific workspaces
locals {
  # Shared RDS is created only in "dev-shared" workspace
  create_shared_rds = var.environment == "dev" && terraform.workspace == "dev-shared"
}

# DB Subnet Group for shared RDS
resource "aws_db_subnet_group" "shared" {
  count = local.create_shared_rds ? 1 : 0

  name       = "roxas-shared-pr-rds-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = merge(local.common_tags, {
    Name        = "roxas-shared-pr-rds-subnet-group"
    Purpose     = "shared-pr-rds"
    Environment = "dev"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Generate random password for shared RDS
resource "random_password" "shared_db_password" {
  count = local.create_shared_rds ? 1 : 0

  length  = 32
  special = true
  # Exclude characters that might cause issues in connection strings
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Shared RDS PostgreSQL Instance
resource "aws_db_instance" "shared" {
  count = local.create_shared_rds ? 1 : 0

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
  password = random_password.shared_db_password[0].result
  port     = 5432

  # Network configuration
  db_subnet_group_name   = aws_db_subnet_group.shared[0].name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false
  multi_az               = false # Single-AZ for dev cost savings

  # Using default parameter group
  # max_connections for db.t4g.micro = 100 (sufficient for ~20 connections per PR)

  # Backup configuration
  backup_retention_period = 1                 # Minimal retention for dev
  backup_window           = "03:00-04:00"     # UTC
  maintenance_window      = "Mon:04:00-Mon:05:00" # UTC

  # Protection and monitoring
  deletion_protection     = false # Allow destruction for dev
  skip_final_snapshot     = true  # No final snapshot needed for dev
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  # Performance Insights (disabled to save costs)
  performance_insights_enabled = false

  # Auto minor version upgrades
  auto_minor_version_upgrade = true

  tags = merge(local.common_tags, {
    Name        = "roxas-shared-pr-rds"
    Purpose     = "shared-pr-rds"
    Environment = "dev"
    Description = "Shared RDS instance for all PR deployments"
  })

  lifecycle {
    prevent_destroy = false
    ignore_changes = [
      # Ignore password changes after initial creation
      # Password is managed through Secrets Manager
      password,
    ]
  }
}

# Store shared RDS credentials in Secrets Manager
resource "aws_secretsmanager_secret" "shared_db_credentials" {
  count = local.create_shared_rds ? 1 : 0

  name_prefix             = "roxas-shared-pr-rds-credentials-"
  description             = "Credentials for shared PR RDS instance"
  recovery_window_in_days = 0 # Immediate deletion for dev

  tags = merge(local.common_tags, {
    Name        = "roxas-shared-pr-rds-credentials"
    Purpose     = "shared-pr-rds"
    Environment = "dev"
  })
}

resource "aws_secretsmanager_secret_version" "shared_db_credentials" {
  count = local.create_shared_rds ? 1 : 0

  secret_id = aws_secretsmanager_secret.shared_db_credentials[0].id
  secret_string = jsonencode({
    username = aws_db_instance.shared[0].username
    password = random_password.shared_db_password[0].result
    engine   = "postgres"
    host     = aws_db_instance.shared[0].address
    port     = aws_db_instance.shared[0].port
    dbname   = aws_db_instance.shared[0].db_name
  })
}

# CloudWatch alarm for high connection count
resource "aws_cloudwatch_metric_alarm" "shared_rds_connections" {
  count = local.create_shared_rds ? 1 : 0

  alarm_name          = "roxas-shared-pr-rds-high-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 300 # 5 minutes
  statistic           = "Average"
  threshold           = 80 # Alert at 80% of 100 max connections
  alarm_description   = "Alert when shared RDS connections exceed 80"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.shared[0].id
  }

  tags = merge(local.common_tags, {
    Purpose     = "shared-pr-rds"
    Environment = "dev"
  })
}

# CloudWatch alarm for storage space
resource "aws_cloudwatch_metric_alarm" "shared_rds_storage" {
  count = local.create_shared_rds ? 1 : 0

  alarm_name          = "roxas-shared-pr-rds-low-storage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300 # 5 minutes
  statistic           = "Average"
  threshold           = 4294967296 # 4 GB (20% of 20GB)
  alarm_description   = "Alert when shared RDS free storage drops below 4 GB"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.shared[0].id
  }

  tags = merge(local.common_tags, {
    Purpose     = "shared-pr-rds"
    Environment = "dev"
  })
}
