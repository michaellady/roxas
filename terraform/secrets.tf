# AWS Secrets Manager for Database Credentials
#
# For PR environments: Creates secret pointing to PR database on shared RDS
# For prod/staging: Creates secret pointing to dedicated RDS instance

# Local values for database connection details
locals {
  # Determine database credentials based on environment type
  db_credentials = local.is_pr_environment ? {
    # PR environment: Use shared RDS with PR-specific database
    username = jsondecode(data.aws_secretsmanager_secret_version.shared_db_credentials[0].secret_string)["username"]
    password = jsondecode(data.aws_secretsmanager_secret_version.shared_db_credentials[0].secret_string)["password"]
    engine   = "postgres"
    host     = data.aws_db_instance.shared[0].address
    port     = data.aws_db_instance.shared[0].port
    dbname   = local.pr_database_name
  } : {
    # Dedicated environment: Use dedicated RDS
    username = aws_db_instance.main[0].username
    password = random_password.db_password[0].result
    engine   = "postgres"
    host     = aws_db_instance.main[0].endpoint
    port     = aws_db_instance.main[0].port
    dbname   = aws_db_instance.main[0].db_name
  }

  # Connection string
  db_connection_string = "postgres://${local.db_credentials.username}:${local.db_credentials.password}@${local.db_credentials.host}/${local.db_credentials.dbname}?sslmode=require"
}

# Secret for database connection information
resource "aws_secretsmanager_secret" "database" {
  name_prefix             = "${var.function_name}-${var.environment}-db-"
  description             = local.is_pr_environment ? "PR database credentials (${local.pr_database_name} on shared RDS)" : "Database connection credentials for ${var.environment}"
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

  depends_on = local.is_pr_environment ? [
    null_resource.pr_database
  ] : [
    aws_db_instance.main
  ]
}

# Inline IAM Policy for Lambda to read database secrets
# Using inline policy to avoid IAM:CreatePolicy permission requirement
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
