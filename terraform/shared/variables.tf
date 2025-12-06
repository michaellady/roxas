# Input Variables for Shared Infrastructure

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

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    Project   = "Roxas"
    ManagedBy = "Terraform"
  }
}

# VPC Configuration
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "nat_instance_type" {
  description = "Instance type for NAT instance (fck-nat)"
  type        = string
  default     = "t4g.nano"
}

# Database Configuration
variable "db_engine_version" {
  description = "PostgreSQL engine version"
  type        = string
  default     = "17"
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  description = "Allocated storage in GB"
  type        = number
  default     = 20
}

variable "db_backup_retention_days" {
  description = "Number of days to retain automated backups"
  type        = number
  default     = 7
}

variable "db_multi_az" {
  description = "Enable Multi-AZ deployment for RDS"
  type        = bool
  default     = false
}

# Domain Configuration
variable "dev_domain_name" {
  description = "Domain name for dev environment (used for wildcard cert)"
  type        = string
  default     = "roxasapp.com"
}

variable "dev_hosted_zone_id" {
  description = "Route53 hosted zone ID for dev domain"
  type        = string
  default     = "Z0661346HM6QI34BGFZ"
}

variable "prod_domain_name" {
  description = "Domain name for prod environment"
  type        = string
  default     = "roxas.ai"
}

variable "prod_hosted_zone_id" {
  description = "Route53 hosted zone ID for prod domain"
  type        = string
  default     = "Z04315832ENRI8EX7SUBL"
}

# Budget Configuration
variable "monthly_budget_limit" {
  description = "Monthly budget limit in USD"
  type        = string
  default     = "100"
}

variable "budget_alert_emails" {
  description = "Email addresses to receive budget alerts"
  type        = list(string)
  default     = []
  validation {
    condition     = length(var.budget_alert_emails) > 0
    error_message = "At least one email address is required for budget alerts."
  }
}

variable "circuit_breaker_threshold" {
  description = "Percentage of budget at which circuit breaker activates (stops services)"
  type        = number
  default     = 200
}
