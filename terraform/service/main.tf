terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }

  # Remote state backend for safe concurrent deployments
  # State is stored in S3 with DynamoDB locking to prevent corruption
  # Backend config is provided via -backend-config flags in workflows
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region
}

# Local values for resource naming
locals {
  function_name_full = "${var.function_name}-${var.environment}"

  # Detect if this is a PR workspace (e.g., "dev-pr-123")
  is_pr_environment = var.environment == "dev" && can(regex("^dev-pr-[0-9]+$", terraform.workspace))

  # Extract PR number from workspace name (e.g., "dev-pr-123" -> "123")
  pr_number = local.is_pr_environment ? regex("^dev-pr-([0-9]+)$", terraform.workspace)[0] : ""

  # PR database name (e.g., "pr_123")
  pr_database_name = local.is_pr_environment ? "pr_${local.pr_number}" : ""

  common_tags = merge(var.tags, {
    Environment = var.environment
  })
}

# IAM Role for Lambda Execution
resource "aws_iam_role" "lambda_exec" {
  name = "${local.function_name_full}-exec-role"

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

# Attach basic Lambda execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Attach VPC execution policy (for Lambda to access RDS in VPC)
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${local.function_name_full}"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

# Lambda Function
resource "aws_lambda_function" "roxas" {
  filename         = var.lambda_zip_path
  function_name    = local.function_name_full
  role             = aws_iam_role.lambda_exec.arn
  handler          = "bootstrap"
  source_code_hash = fileexists(var.lambda_zip_path) ? filebase64sha256(var.lambda_zip_path) : null
  runtime          = "provided.al2023"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size

  # VPC configuration for RDS access
  vpc_config {
    subnet_ids         = local.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      OPENAI_API_KEY        = var.openai_api_key
      LINKEDIN_ACCESS_TOKEN = var.linkedin_access_token
      WEBHOOK_SECRET        = var.webhook_secret
      LOG_LEVEL             = var.log_level
      DB_SECRET_NAME        = aws_secretsmanager_secret.database.name
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_logs,
    aws_iam_role_policy_attachment.lambda_basic,
    aws_iam_role_policy_attachment.lambda_vpc
  ]

  tags = local.common_tags
}

# API Gateway HTTP API
resource "aws_apigatewayv2_api" "webhook" {
  name          = "${local.function_name_full}-api"
  protocol_type = "HTTP"
  description   = "GitHub webhook handler for Roxas (${var.environment})"

  tags = local.common_tags
}

# API Gateway Stage
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.webhook.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_logs.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }

  tags = local.common_tags
}

# CloudWatch Log Group for API Gateway
resource "aws_cloudwatch_log_group" "api_logs" {
  name              = "/aws/apigateway/${local.function_name_full}"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

# API Gateway Integration with Lambda
resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.webhook.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.roxas.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

# API Gateway Route - POST /webhook
resource "aws_apigatewayv2_route" "webhook_post" {
  api_id    = aws_apigatewayv2_api.webhook.id
  route_key = "POST /webhook"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

# Lambda Permission for API Gateway
resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.roxas.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.webhook.execution_arn}/*/*"
}
