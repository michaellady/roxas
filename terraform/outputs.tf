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
  value = local.create_custom_domain ? (
    var.environment == "prod" ? "https://roxas.ai/webhooks/webhook" : "https://${local.full_domain_name}/webhook"
  ) : "${aws_apigatewayv2_api.webhook.api_endpoint}/webhook"
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
