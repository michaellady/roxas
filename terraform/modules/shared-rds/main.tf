# Shared RDS Module
# Provides a single RDS instance shared across multiple PR deployments
# Each PR gets its own database (CREATE DATABASE pr_N) instead of a dedicated RDS instance

# DB Subnet Group for shared RDS
resource "aws_db_subnet_group" "shared" {
  name       = "roxas-shared-pr-rds-subnet-group"
  subnet_ids = var.private_subnet_ids

  tags = merge(var.common_tags, {
    Name        = "roxas-shared-pr-rds-subnet-group"
    Purpose     = "shared-pr-rds"
    Environment = var.environment
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
  vpc_security_group_ids = [var.rds_security_group_id]
  publicly_accessible    = false
  multi_az               = false # Single-AZ for dev cost savings

  # Using default parameter group
  # max_connections for db.t4g.micro = 100 (sufficient for ~20 connections per PR)

  # Backup configuration
  backup_retention_period = 1                     # Minimal retention for dev
  backup_window           = "03:00-04:00"         # UTC
  maintenance_window      = "mon:04:00-mon:05:00" # UTC

  # Protection and monitoring
  deletion_protection                 = false # Allow destruction for dev
  skip_final_snapshot                 = true  # No final snapshot needed for dev
  enabled_cloudwatch_logs_exports     = ["postgresql", "upgrade"]
  performance_insights_enabled        = false
  auto_minor_version_upgrade          = true

  tags = merge(var.common_tags, {
    Name        = "roxas-shared-pr-rds"
    Purpose     = "shared-pr-rds"
    Environment = var.environment
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

  tags = merge(var.common_tags, {
    Name        = "roxas-shared-pr-rds-credentials"
    Purpose     = "shared-pr-rds"
    Environment = var.environment
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

# CloudWatch alarm for high connection count
resource "aws_cloudwatch_metric_alarm" "shared_rds_connections" {
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
    DBInstanceIdentifier = aws_db_instance.shared.id
  }

  tags = merge(var.common_tags, {
    Purpose     = "shared-pr-rds"
    Environment = var.environment
  })
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
  alarm_description   = "Alert when shared RDS free storage drops below 4 GB"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.shared.id
  }

  tags = merge(var.common_tags, {
    Purpose     = "shared-pr-rds"
    Environment = var.environment
  })
}
