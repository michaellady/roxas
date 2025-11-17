# Prod Environment Configuration
# These values will be overridden by GitHub Actions environment secrets

environment = "prod"
aws_region  = "us-east-1"

# Custom Domain Configuration
custom_domain_enabled = true
domain_name           = "roxas.ai"
hosted_zone_id        = "Z04315832ENRI8EX7SUBL"

# Function configuration
function_name      = "roxas-webhook-handler"
lambda_timeout     = 60
lambda_memory_size = 512
log_retention_days = 30
log_level          = "info"

# Sensitive values - will be provided via GitHub secrets in CI/CD
# For local testing, set these manually
openai_api_key        = "REPLACE_WITH_PROD_KEY"
linkedin_access_token = "REPLACE_WITH_PROD_TOKEN"
webhook_secret        = "REPLACE_WITH_PROD_SECRET"
