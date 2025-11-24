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
  description = "ACM certificate ARN (if custom domain enabled)"
  value       = local.create_custom_domain ? aws_acm_certificate.webhook[0].arn : null
}

# Database Outputs
# For PR environments: Shows shared RDS info with PR database name
# For dedicated environments: Shows dedicated RDS info
output "db_instance_endpoint" {
  description = "RDS instance endpoint"
  value       = local.is_pr_environment ? data.aws_db_instance.shared[0].endpoint : aws_db_instance.main[0].endpoint
}

output "db_instance_name" {
  description = "Database name"
  value       = local.is_pr_environment ? local.pr_database_name : aws_db_instance.main[0].db_name
}

output "db_instance_arn" {
  description = "ARN of the RDS instance (not available for PR environments using shared RDS)"
  value       = local.is_pr_environment ? null : aws_db_instance.main[0].arn
}

output "db_secret_arn" {
  description = "ARN of the Secrets Manager secret containing database credentials"
  value       = aws_secretsmanager_secret.database.arn
  sensitive   = true
}

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "private_subnet_ids" {
  description = "IDs of private subnets"
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "IDs of public subnets"
  value       = aws_subnet.public[*].id
}

