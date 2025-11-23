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
output "db_instance_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.main.endpoint
}

output "db_instance_name" {
  description = "Database name"
  value       = aws_db_instance.main.db_name
}

output "db_instance_arn" {
  description = "ARN of the RDS instance"
  value       = aws_db_instance.main.arn
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

# Shared RDS Outputs (only available in dev-shared workspace)
output "shared_rds_endpoint" {
  description = "Shared RDS instance endpoint (dev-shared workspace only)"
  value       = local.create_shared_rds ? module.shared_rds[0].rds_endpoint : null
}

output "shared_rds_address" {
  description = "Shared RDS instance address (dev-shared workspace only)"
  value       = local.create_shared_rds ? module.shared_rds[0].rds_address : null
}

output "shared_rds_port" {
  description = "Shared RDS instance port (dev-shared workspace only)"
  value       = local.create_shared_rds ? module.shared_rds[0].rds_port : null
}

output "shared_rds_master_db" {
  description = "Shared RDS master database name (dev-shared workspace only)"
  value       = local.create_shared_rds ? module.shared_rds[0].rds_master_db : null
}

output "shared_rds_username" {
  description = "Shared RDS application username (dev-shared workspace only)"
  value       = local.create_shared_rds ? module.shared_rds[0].rds_username : null
  sensitive   = true
}

output "shared_rds_secret_arn" {
  description = "ARN of Secrets Manager secret for shared RDS credentials (dev-shared workspace only)"
  value       = local.create_shared_rds ? module.shared_rds[0].secret_arn : null
  sensitive   = true
}

output "shared_rds_connection_string_template" {
  description = "Connection string template for PR databases (replace {PR_NUMBER} with actual PR number)"
  value       = local.create_shared_rds ? module.shared_rds[0].connection_string_template : null
}
