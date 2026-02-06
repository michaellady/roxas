variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev or prod)"
  type        = string
  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "Environment must be either 'dev' or 'prod'."
  }
}

variable "function_name" {
  description = "Name of the Lambda function (will be suffixed with environment)"
  type        = string
  default     = "roxas-webhook-handler"
}

variable "lambda_zip_path" {
  description = "Path to the Lambda deployment package (ZIP file)"
  type        = string
  default     = "../../bin/bootstrap.zip"
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 60
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 256
}

variable "log_retention_days" {
  description = "CloudWatch log retention period in days"
  type        = number
  default     = 7
}

variable "log_level" {
  description = "Application log level"
  type        = string
  default     = "info"
}

# Sensitive variables - must be provided via environment or tfvars
variable "openai_api_key" {
  description = "OpenAI API key for GPT-4 access"
  type        = string
  sensitive   = true
}

variable "linkedin_access_token" {
  description = "LinkedIn OAuth access token"
  type        = string
  sensitive   = true
}

variable "webhook_secret" {
  description = "Webhook secret for HMAC validation"
  type        = string
  sensitive   = true
}

variable "credential_encryption_key" {
  description = "32-byte hex key for encrypting stored credentials (Bluesky, Threads)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "github_app_id" {
  description = "GitHub App ID"
  type        = string
  default     = ""
}

variable "github_app_webhook_secret" {
  description = "GitHub App webhook secret for HMAC validation"
  type        = string
  sensitive   = true
  default     = ""
}

variable "github_app_private_key" {
  description = "GitHub App private key (base64-encoded PEM)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "github_app_url" {
  description = "URL for installing the GitHub App (e.g. https://github.com/apps/roxas/installations/new)"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    Project   = "Roxas"
    ManagedBy = "Terraform"
  }
}

# Custom Domain Configuration
variable "custom_domain_enabled" {
  description = "Enable custom domain for API Gateway"
  type        = bool
  default     = true
}

variable "pr_number" {
  description = "Pull request number for dev environment (used for subdomain)"
  type        = string
  default     = ""
}
