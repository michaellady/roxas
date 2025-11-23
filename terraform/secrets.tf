# AWS Secrets Manager for Database Credentials

# Secret for database connection information
resource "aws_secretsmanager_secret" "database" {
  name_prefix             = "${var.function_name}-${var.environment}-db-"
  description             = "Database connection credentials for ${var.environment}"
  recovery_window_in_days = var.environment == "prod" ? 30 : 7

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-db-secret"
  })
}

# Secret value containing all database connection details
resource "aws_secretsmanager_secret_version" "database" {
  secret_id = aws_secretsmanager_secret.database.id
  secret_string = jsonencode({
    username = aws_db_instance.main.username
    password = random_password.db_password.result
    engine   = "postgres"
    host     = aws_db_instance.main.endpoint
    port     = aws_db_instance.main.port
    dbname   = aws_db_instance.main.db_name
    # Connection string for convenience
    connection_string = "postgres://${aws_db_instance.main.username}:${random_password.db_password.result}@${aws_db_instance.main.endpoint}/${aws_db_instance.main.db_name}?sslmode=require"
  })
}

# IAM Policy for Lambda to read database secrets
resource "aws_iam_policy" "lambda_secrets" {
  name_prefix = "${var.function_name}-${var.environment}-secrets-"
  description = "Allow Lambda to read database secrets"

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

  tags = local.common_tags
}

# Attach secrets policy to Lambda execution role
resource "aws_iam_role_policy_attachment" "lambda_secrets" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_secrets.arn
}
