# PR Cleanup Lambda (Dev Environment Only)
# Cleans up PR resources when PRs are closed:
# - Drops PR databases from shared RDS
# - Deletes orphaned ENIs
# - Deletes orphaned security groups
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

# EC2 permissions for ENI and Security Group cleanup
resource "aws_iam_role_policy" "cleanup_lambda_ec2" {
  count = local.enable_cleanup_lambda ? 1 : 0

  name = "ec2-cleanup-access"
  role = aws_iam_role.cleanup_lambda[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DescribeENIsAndSGs"
        Effect = "Allow"
        Action = [
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeSecurityGroups"
        ]
        Resource = "*"
      },
      {
        Sid    = "DeleteOrphanedENIs"
        Effect = "Allow"
        Action = [
          "ec2:DeleteNetworkInterface"
        ]
        Resource = "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:network-interface/*"
        Condition = {
          StringLike = {
            "ec2:Description" = "*roxas*"
          }
        }
      },
      {
        Sid    = "DeleteOrphanedSecurityGroups"
        Effect = "Allow"
        Action = [
          "ec2:DeleteSecurityGroup"
        ]
        Resource = "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:security-group/*"
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

# Build cleanup Lambda binary (Go)
resource "null_resource" "cleanup_lambda_build" {
  count = local.enable_cleanup_lambda ? 1 : 0

  triggers = {
    source_hash = filemd5("${path.module}/../../cmd/pr-cleanup/main.go")
  }

  provisioner "local-exec" {
    command = <<-EOT
      cd ${path.module}/../..
      GOOS=linux GOARCH=arm64 go build -tags lambda.norpc -o ${path.module}/lambda/bootstrap ./cmd/pr-cleanup
      zip -j ${path.module}/lambda/pr_cleanup.zip ${path.module}/lambda/bootstrap
      rm -f ${path.module}/lambda/bootstrap
    EOT
  }
}

# Cleanup Lambda function (Go)
resource "aws_lambda_function" "cleanup" {
  count = local.enable_cleanup_lambda ? 1 : 0

  filename         = "${path.module}/lambda/pr_cleanup.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda/pr_cleanup.zip")
  function_name    = "${local.name_prefix}-cleanup"
  role             = aws_iam_role.cleanup_lambda[0].arn
  handler          = "bootstrap"
  runtime          = "provided.al2023"
  timeout          = 30
  memory_size      = 128
  architectures    = ["arm64"]

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
    null_resource.cleanup_lambda_build,
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

# ============================================================================
# Scheduled ENI Cleanup (EventBridge)
# ============================================================================
# Lambda ENIs stay "in-use" for 10-20 minutes after function deletion.
# The PR cleanup runs immediately on PR close, so it skips these ENIs.
# This daily schedule catches any orphaned ENIs that became available later.

resource "aws_cloudwatch_event_rule" "cleanup_schedule" {
  count = local.enable_cleanup_lambda ? 1 : 0

  name                = "${local.name_prefix}-eni-cleanup-schedule"
  description         = "Daily cleanup of orphaned Lambda ENIs"
  schedule_expression = "rate(1 day)"

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "cleanup_lambda" {
  count = local.enable_cleanup_lambda ? 1 : 0

  rule      = aws_cloudwatch_event_rule.cleanup_schedule[0].name
  target_id = "cleanup-lambda"
  arn       = aws_lambda_function.cleanup[0].arn
  input     = jsonencode({ action = "cleanup_orphaned_enis" })
}

resource "aws_lambda_permission" "cleanup_eventbridge" {
  count = local.enable_cleanup_lambda ? 1 : 0

  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cleanup[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cleanup_schedule[0].arn
}
