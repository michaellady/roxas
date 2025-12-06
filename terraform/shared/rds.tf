# RDS PostgreSQL Instance
# Dev: Shared instance for all PRs (databases: pr_123, pr_124, etc.)
# Prod: Dedicated instance (database: roxas)

# DB Subnet Group (spans multiple AZs)
resource "aws_db_subnet_group" "main" {
  name_prefix = "${local.name_prefix}-"
  subnet_ids  = aws_subnet.private[*].id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db-subnet-group"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Generate random password for database
resource "random_password" "db_password" {
  length  = 32
  special = true
  # Exclude characters that might cause issues in connection strings
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# RDS PostgreSQL Instance
resource "aws_db_instance" "main" {
  identifier = "${local.name_prefix}-rds"

  # Engine configuration
  engine            = "postgres"
  engine_version    = var.db_engine_version
  instance_class    = var.db_instance_class
  allocated_storage = var.db_allocated_storage
  storage_type      = "gp3"
  storage_encrypted = true

  # Database configuration
  db_name  = local.db_name
  username = local.db_username
  password = random_password.db_password.result
  port     = 5432

  # Network configuration
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false
  multi_az               = var.db_multi_az

  # Backup configuration
  backup_retention_period = var.db_backup_retention_days
  backup_window           = "03:00-04:00"         # UTC
  maintenance_window      = "Mon:04:00-Mon:05:00" # UTC

  # Protection and monitoring
  deletion_protection             = var.environment == "prod"
  skip_final_snapshot             = var.environment == "dev"
  final_snapshot_identifier       = var.environment == "prod" ? "${local.name_prefix}-final-snapshot" : null
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  performance_insights_enabled    = false
  auto_minor_version_upgrade      = true

  # Apply changes immediately in dev (VPC/subnet changes need this)
  apply_immediately = var.environment == "dev"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rds"
  })

  lifecycle {
    prevent_destroy = false
    ignore_changes = [
      password,                  # Don't update password after initial creation
      final_snapshot_identifier, # Timestamp would always change
    ]
  }
}

# Store database credentials in Secrets Manager
resource "aws_secretsmanager_secret" "db_credentials" {
  name_prefix             = "${local.name_prefix}-db-credentials-"
  description             = "Database credentials for ${var.environment} environment"
  recovery_window_in_days = var.environment == "prod" ? 30 : 0

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db-credentials"
  })
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username          = aws_db_instance.main.username
    password          = random_password.db_password.result
    engine            = "postgres"
    host              = aws_db_instance.main.address
    port              = aws_db_instance.main.port
    dbname            = aws_db_instance.main.db_name
    connection_string = "postgres://${aws_db_instance.main.username}:${random_password.db_password.result}@${aws_db_instance.main.address}:${aws_db_instance.main.port}/${aws_db_instance.main.db_name}?sslmode=require"
  })
}
