# Shared RDS Outputs
output "shared_rds_endpoint" {
  description = "Shared RDS instance endpoint"
  value       = aws_db_instance.shared.endpoint
}

output "shared_rds_address" {
  description = "Shared RDS instance address (hostname only)"
  value       = aws_db_instance.shared.address
}

output "shared_rds_port" {
  description = "Shared RDS instance port"
  value       = aws_db_instance.shared.port
}

output "shared_rds_master_db" {
  description = "Shared RDS master database name"
  value       = aws_db_instance.shared.db_name
}

output "shared_rds_username" {
  description = "Shared RDS application username"
  value       = aws_db_instance.shared.username
  sensitive   = true
}

output "shared_rds_secret_arn" {
  description = "ARN of Secrets Manager secret for shared RDS credentials"
  value       = aws_secretsmanager_secret.shared_db_credentials.arn
  sensitive   = true
}

output "shared_rds_connection_string_template" {
  description = "Connection string template for PR databases (replace {PR_NUMBER} with actual PR number)"
  value       = "postgres://${aws_db_instance.shared.username}:PASSWORD@${aws_db_instance.shared.address}:${aws_db_instance.shared.port}/pr_{PR_NUMBER}?sslmode=require"
}
