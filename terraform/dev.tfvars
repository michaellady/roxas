# Dev Environment Configuration
# These values will be overridden by GitHub Actions environment secrets

environment = "dev"
aws_region  = "us-east-1"

# Custom Domain Configuration
# Note: pr_number will be provided by GitHub Actions
custom_domain_enabled = true
domain_name           = "roxasapp.com"
hosted_zone_id        = "Z0661346HM6QI34BGFZ"

# Function configuration
function_name      = "roxas-webhook-handler"
lambda_timeout     = 60
lambda_memory_size = 256
log_retention_days = 7
log_level          = "debug"

# Sensitive values - will be provided via GitHub secrets in CI/CD
# For local testing, set these manually
openai_api_key        = "REPLACE_WITH_DEV_KEY"
linkedin_access_token = "REPLACE_WITH_DEV_TOKEN"
webhook_secret        = "REPLACE_WITH_DEV_SECRET"

# Database configuration
db_instance_class        = "db.t4g.micro"
db_allocated_storage     = 20
db_backup_retention_days = 7
