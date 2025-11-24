output "lambda_function_name" {
  description = "Name of the deployed Lambda function"
  value       = aws_lambda_function.roxas.function_name
}

output "lambda_function_arn" {
  description = "ARN of the deployed Lambda function"
  value       = aws_lambda_function.roxas.arn
}

output "api_gateway_endpoint" {
  description = "API Gateway HTTP endpoint URL"
  value       = aws_apigatewayv2_api.webhook.api_endpoint
}

output "webhook_url" {
  description = "Full webhook URL to configure in GitHub"
  value       = local.create_custom_domain ? "https://${local.full_domain_name}/webhook" : "${aws_apigatewayv2_api.webhook.api_endpoint}/webhook"
}

output "api_gateway_id" {
  description = "ID of the API Gateway"
  value       = aws_apigatewayv2_api.webhook.id
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group name for Lambda logs"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "custom_domain_name" {
  description = "Custom domain name (if enabled)"
  value       = local.create_custom_domain ? local.full_domain_name : null
}

output "certificate_arn" {
  description = "ACM certificate ARN (from shared infrastructure)"
  value       = local.create_custom_domain ? local.acm_certificate_arn : null
}

# Database Outputs
output "db_endpoint" {
  description = "RDS instance endpoint (from shared infrastructure)"
  value       = local.rds_endpoint
}

output "db_name" {
  description = "Database name used by this service"
  value       = local.database_name
}

output "db_secret_arn" {
  description = "ARN of the Secrets Manager secret containing database credentials"
  value       = aws_secretsmanager_secret.database.arn
  sensitive   = true
}

# Network Outputs (from shared infrastructure)
output "vpc_id" {
  description = "ID of the VPC (from shared infrastructure)"
  value       = local.vpc_id
}

output "private_subnet_ids" {
  description = "IDs of private subnets (from shared infrastructure)"
  value       = local.private_subnet_ids
}
