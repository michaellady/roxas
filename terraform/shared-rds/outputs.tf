# Shared RDS Outputs
output "shared_rds_endpoint" {
  description = "Shared RDS instance endpoint"
  value       = module.shared_rds.rds_endpoint
}

output "shared_rds_address" {
  description = "Shared RDS instance address (hostname only)"
  value       = module.shared_rds.rds_address
}

output "shared_rds_port" {
  description = "Shared RDS instance port"
  value       = module.shared_rds.rds_port
}

output "shared_rds_master_db" {
  description = "Shared RDS master database name"
  value       = module.shared_rds.rds_master_db
}

output "shared_rds_username" {
  description = "Shared RDS application username"
  value       = module.shared_rds.rds_username
  sensitive   = true
}

output "shared_rds_secret_arn" {
  description = "ARN of Secrets Manager secret for shared RDS credentials"
  value       = module.shared_rds.secret_arn
  sensitive   = true
}

output "shared_rds_connection_string_template" {
  description = "Connection string template for PR databases (replace {PR_NUMBER} with actual PR number)"
  value       = module.shared_rds.connection_string_template
}
