# Example Terraform variables file
# For multi-account deployment, use dev.tfvars or prod.tfvars instead
# DO NOT commit files with real credentials (*.tfvars is in .gitignore)

environment   = "dev" # or "prod"
aws_region    = "us-east-1"
function_name = "roxas-webhook-handler"

# Sensitive values - replace with actual credentials
openai_api_key        = "sk-your-openai-api-key"
linkedin_access_token = "your-linkedin-access-token"
webhook_secret        = "your-webhook-secret"

# Optional overrides
# lambda_timeout       = 60
# lambda_memory_size   = 256  # dev: 256, prod: 512
# log_retention_days   = 7    # dev: 7, prod: 30
# log_level            = "info"  # dev: debug, prod: info
