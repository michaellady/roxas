# Example Terraform variables file
# Copy this to terraform.tfvars and fill in your actual values
# DO NOT commit terraform.tfvars (it's in .gitignore)

aws_region    = "us-east-1"
function_name = "roxas-webhook-handler"

# Sensitive values - replace with actual credentials
openai_api_key        = "sk-your-api-key-here"
linkedin_access_token = "your-linkedin-access-token"
github_webhook_secret = "your-webhook-secret"

# Optional overrides
# lambda_timeout       = 30
# lambda_memory_size   = 256
# log_retention_days   = 7
# log_level           = "info"
