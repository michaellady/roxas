# RDS PostgreSQL Database Configuration

# DB Subnet Group (spans multiple AZs for high availability)
resource "aws_db_subnet_group" "main" {
  name_prefix = "${var.function_name}-${var.environment}-"
  subnet_ids  = aws_subnet.private[*].id

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-db-subnet-group"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# DB Parameter Group (PostgreSQL 15 optimizations)
resource "aws_db_parameter_group" "main" {
  name_prefix = "${var.function_name}-${var.environment}-"
  family      = "postgres15"
  description = "Custom parameter group for PostgreSQL 15"

  # Optimize for small instance
  parameter {
    name  = "shared_buffers"
    value = "{DBInstanceClassMemory/32768}"
  }

  parameter {
    name  = "max_connections"
    value = "100"
  }

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-pg"
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
  identifier_prefix = "${var.function_name}-${var.environment}-"

  # Engine configuration
  engine               = "postgres"
  engine_version       = var.db_engine_version
  instance_class       = var.db_instance_class
  allocated_storage    = var.db_allocated_storage
  storage_type         = "gp3"
  storage_encrypted    = true

  # Database configuration
  db_name  = var.db_name
  username = var.db_username
  password = random_password.db_password.result
  port     = 5432

  # Network configuration
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false

  # Parameter and option groups
  parameter_group_name = aws_db_parameter_group.main.name

  # Backup configuration
  backup_retention_period = var.db_backup_retention_days
  backup_window          = "03:00-04:00"  # UTC
  maintenance_window     = "Mon:04:00-Mon:05:00"  # UTC

  # Protection and monitoring
  deletion_protection = var.environment == "prod" ? true : false
  skip_final_snapshot = var.environment == "dev" ? true : false
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
    prevent_destroy = false  # Set to true after initial creation
    ignore_changes  = [
      final_snapshot_identifier,  # Timestamp will always change
    ]
  }
}
