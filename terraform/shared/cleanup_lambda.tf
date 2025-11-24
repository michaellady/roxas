# PR Database Cleanup Lambda (Dev Environment Only)
# Drops PR databases when PRs are closed
# Invoked by GitHub Actions workflow

# Security group for cleanup Lambda
resource "aws_security_group" "cleanup_lambda" {
  count = local.enable_cleanup_lambda ? 1 : 0

  name_prefix = "${local.name_prefix}-cleanup-lambda-"
  description = "Security group for DB cleanup Lambda function"
  vpc_id      = aws_vpc.main.id

  # Outbound to RDS
  egress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.rds.id]
    description     = "PostgreSQL to RDS"
  }

  # Outbound HTTPS for Secrets Manager API calls
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS for AWS API calls"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-cleanup-lambda-sg"
  })
}

# Allow cleanup Lambda to connect to RDS
resource "aws_security_group_rule" "rds_from_cleanup_lambda" {
  count = local.enable_cleanup_lambda ? 1 : 0

  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.cleanup_lambda[0].id
  security_group_id        = aws_security_group.rds.id
  description              = "PostgreSQL from cleanup Lambda"
}

# IAM role for cleanup Lambda
resource "aws_iam_role" "cleanup_lambda" {
  count = local.enable_cleanup_lambda ? 1 : 0

  name = "${local.name_prefix}-cleanup-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# Lambda basic execution + VPC access
resource "aws_iam_role_policy_attachment" "cleanup_lambda_vpc" {
  count = local.enable_cleanup_lambda ? 1 : 0

  role       = aws_iam_role.cleanup_lambda[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Secrets Manager read access for DB credentials
resource "aws_iam_role_policy" "cleanup_lambda_secrets" {
  count = local.enable_cleanup_lambda ? 1 : 0

  name = "secrets-manager-access"
  role = aws_iam_role.cleanup_lambda[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.db_credentials.arn
        ]
      }
    ]
  })
}

# CloudWatch log group for cleanup Lambda
resource "aws_cloudwatch_log_group" "cleanup_lambda" {
  count = local.enable_cleanup_lambda ? 1 : 0

  name              = "/aws/lambda/${local.name_prefix}-cleanup"
  retention_in_days = 7

  tags = local.common_tags
}

# Build Lambda layer with pg8000 dependency
resource "null_resource" "cleanup_lambda_layer" {
  count = local.enable_cleanup_lambda ? 1 : 0

  triggers = {
    requirements = filemd5("${path.module}/lambda/requirements.txt")
  }

  provisioner "local-exec" {
    command = <<-EOT
      cd ${path.module}/lambda
      rm -rf python layer.zip
      mkdir -p python
      pip3 install -r requirements.txt -t python 2>/dev/null || pip install -r requirements.txt -t python
      zip -r layer.zip python
    EOT
  }
}

# Lambda layer for pg8000
resource "aws_lambda_layer_version" "pg8000" {
  count = local.enable_cleanup_lambda ? 1 : 0

  filename            = "${path.module}/lambda/layer.zip"
  layer_name          = "${local.name_prefix}-pg8000"
  compatible_runtimes = ["python3.12"]

  depends_on = [null_resource.cleanup_lambda_layer]
}

# Package Lambda function code
data "archive_file" "cleanup_lambda" {
  count = local.enable_cleanup_lambda ? 1 : 0

  type        = "zip"
  source_file = "${path.module}/lambda/db_cleanup.py"
  output_path = "${path.module}/lambda/function.zip"
}

# Cleanup Lambda function
resource "aws_lambda_function" "cleanup" {
  count = local.enable_cleanup_lambda ? 1 : 0

  filename         = data.archive_file.cleanup_lambda[0].output_path
  function_name    = "${local.name_prefix}-cleanup"
  role             = aws_iam_role.cleanup_lambda[0].arn
  handler          = "db_cleanup.handler"
  source_code_hash = data.archive_file.cleanup_lambda[0].output_base64sha256
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 128
  architectures    = ["arm64"]

  layers = [aws_lambda_layer_version.pg8000[0].arn]

  environment {
    variables = {
      DB_SECRET_NAME = aws_secretsmanager_secret.db_credentials.name
    }
  }

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.cleanup_lambda[0].id]
  }

  depends_on = [
    aws_cloudwatch_log_group.cleanup_lambda,
    aws_iam_role_policy_attachment.cleanup_lambda_vpc,
    aws_iam_role_policy.cleanup_lambda_secrets
  ]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-cleanup"
  })
}

# Allow invocation from GitHub Actions (same AWS account)
resource "aws_lambda_permission" "cleanup_invoke" {
  count = local.enable_cleanup_lambda ? 1 : 0

  statement_id  = "AllowAccountInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cleanup[0].function_name
  principal     = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
}
