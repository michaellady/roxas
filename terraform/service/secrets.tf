# AWS Secrets Manager for Database Credentials
#
# Creates a service-specific secret containing database connection details.
# For PR environments: Uses shared RDS with PR-specific database name
# For prod/dev: Uses shared RDS with master database name

# Local values for database connection details
locals {
  # Build database credentials from shared infrastructure
  db_credentials = {
    username = local.shared_db_credentials["username"]
    password = local.shared_db_credentials["password"]
    engine   = "postgres"
    host     = local.rds_endpoint
    port     = local.rds_port
    dbname   = local.database_name
  }

  # Connection string for the service
  db_connection_string = "postgres://${local.db_credentials.username}:${local.db_credentials.password}@${local.db_credentials.host}/${local.db_credentials.dbname}?sslmode=require"
}

# Secret for database connection information
# Each service deployment gets its own secret with appropriate database name
resource "aws_secretsmanager_secret" "database" {
  name_prefix             = "${var.function_name}-${var.environment}-db-"
  description             = "Database connection credentials for ${local.function_name_full}"
  recovery_window_in_days = var.environment == "prod" ? 30 : 7

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-db-secret"
  })
}

# Secret value containing all database connection details
resource "aws_secretsmanager_secret_version" "database" {
  secret_id = aws_secretsmanager_secret.database.id
  secret_string = jsonencode({
    username          = local.db_credentials.username
    password          = local.db_credentials.password
    engine            = local.db_credentials.engine
    host              = local.db_credentials.host
    port              = local.db_credentials.port
    dbname            = local.db_credentials.dbname
    connection_string = local.db_connection_string
  })
}

# Inline IAM Policy for Lambda to read database secrets
resource "aws_iam_role_policy" "lambda_secrets" {
  name_prefix = "secrets-access-"
  role        = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = aws_secretsmanager_secret.database.arn
      }
    ]
  })
}
