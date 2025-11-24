# RDS PostgreSQL Database Configuration
#
# For PR environments: Uses shared RDS with per-PR database (CREATE DATABASE pr_N)
# For prod/staging: Creates dedicated RDS instance

# Data source: Reference shared RDS instance for PR environments
data "aws_db_instance" "shared" {
  count = local.is_pr_environment ? 1 : 0

  db_instance_identifier = "roxas-shared-pr-rds"
}

# Data source: Read SSM parameter containing the shared RDS secret name
data "aws_ssm_parameter" "shared_db_secret_name" {
  count = local.is_pr_environment ? 1 : 0

  name = "/roxas/shared-rds/credentials-secret-name"
}

# Data source: Reference shared RDS credentials for PR environments
# Using dynamic lookup via SSM parameter
data "aws_secretsmanager_secret" "shared_db_credentials" {
  count = local.is_pr_environment ? 1 : 0

  name = data.aws_ssm_parameter.shared_db_secret_name[0].value
}

data "aws_secretsmanager_secret_version" "shared_db_credentials" {
  count = local.is_pr_environment ? 1 : 0

  secret_id = data.aws_secretsmanager_secret.shared_db_credentials[0].id
}

# DB Subnet Group (spans multiple AZs for high availability)
# Only create for non-PR environments
resource "aws_db_subnet_group" "main" {
  count = local.is_pr_environment ? 0 : 1

  name_prefix = "${var.function_name}-${var.environment}-"
  subnet_ids  = local.private_subnet_ids

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-db-subnet-group"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Using default parameter group for simplicity
# Custom parameters can be added later if needed
# Default max_connections for db.t4g.micro is sufficient for MVP

# Generate random password for dedicated database
# Only create for non-PR environments
resource "random_password" "db_password" {
  count = local.is_pr_environment ? 0 : 1

  length  = 32
  special = true
  # Exclude characters that might cause issues in connection strings
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# RDS PostgreSQL Instance
# Only create for non-PR environments (prod, staging, etc.)
resource "aws_db_instance" "main" {
  count = local.is_pr_environment ? 0 : 1

  identifier_prefix = "${var.function_name}-${var.environment}-"

  # Engine configuration
  engine            = "postgres"
  engine_version    = var.db_engine_version
  instance_class    = var.db_instance_class
  allocated_storage = var.db_allocated_storage
  storage_type      = "gp3"
  storage_encrypted = true

  # Database configuration
  db_name  = var.db_name
  username = var.db_username
  password = random_password.db_password[0].result
  port     = 5432

  # Network configuration
  db_subnet_group_name   = aws_db_subnet_group.main[0].name
  vpc_security_group_ids = [aws_security_group.rds[0].id]
  publicly_accessible    = false

  # Using default parameter group (no custom parameters needed for MVP)

  # Backup configuration
  backup_retention_period = var.db_backup_retention_days
  backup_window           = "03:00-04:00"         # UTC
  maintenance_window      = "Mon:04:00-Mon:05:00" # UTC

  # Protection and monitoring
  deletion_protection       = var.environment == "prod" ? true : false
  skip_final_snapshot       = var.environment == "dev" ? true : false
  final_snapshot_identifier = var.environment == "prod" ? "${var.function_name}-${var.environment}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}" : null

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  # Performance Insights (optional, costs extra)
  performance_insights_enabled = false

  # Auto minor version upgrades
  auto_minor_version_upgrade = true

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-db"
  })

  lifecycle {
    # Prevent accidental deletion in production
    prevent_destroy = false # Set to true after initial creation
    ignore_changes = [
      final_snapshot_identifier, # Timestamp will always change
    ]
  }
}

# ============================================================================
# PR Database Provisioning on Shared RDS
# ============================================================================

# Create PR-specific database on shared RDS instance
# Only runs for PR environments (e.g., dev-pr-123)
resource "null_resource" "pr_database" {
  count = local.is_pr_environment ? 1 : 0

  # Trigger recreation if PR number changes
  triggers = {
    pr_database_name = local.pr_database_name
    shared_rds_host  = data.aws_db_instance.shared[0].address
  }

  provisioner "local-exec" {
    command = <<-EOT
      # Parse shared RDS credentials from Secrets Manager
      SECRET_JSON='${data.aws_secretsmanager_secret_version.shared_db_credentials[0].secret_string}'
      DB_HOST=$(echo $SECRET_JSON | jq -r '.host')
      DB_PORT=$(echo $SECRET_JSON | jq -r '.port')
      DB_USER=$(echo $SECRET_JSON | jq -r '.username')
      DB_PASS=$(echo $SECRET_JSON | jq -r '.password')
      DB_NAME='${local.pr_database_name}'

      # Check if database already exists
      EXISTS=$(PGPASSWORD=$DB_PASS psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'")

      if [ "$EXISTS" != "1" ]; then
        echo "Creating database $DB_NAME on shared RDS..."
        PGPASSWORD=$DB_PASS psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d postgres -c "CREATE DATABASE $DB_NAME OWNER $DB_USER"
        echo "Database $DB_NAME created successfully"
      else
        echo "Database $DB_NAME already exists"
      fi
    EOT
  }

  depends_on = [
    data.aws_db_instance.shared,
    data.aws_secretsmanager_secret_version.shared_db_credentials
  ]
}
