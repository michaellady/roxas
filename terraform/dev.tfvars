# Dev Environment Configuration
# These values will be overridden by GitHub Actions environment secrets

environment = "dev"
aws_region  = "us-east-1"

# Custom Domain Configuration
# Note: pr_number will be provided by GitHub Actions
custom_domain_enabled = true
domain_name           = "getroxas.com"
hosted_zone_id        = "Z06579361DMB1AK1VDFFZ"

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
