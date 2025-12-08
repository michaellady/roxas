# Backend configuration for shared RDS infrastructure (dev environment)
# Separate state file from shared/ to allow independent management

bucket         = "roxas-terraform-state-dev"
key            = "shared-rds/terraform.tfstate"
region         = "us-east-1"
encrypt        = true
dynamodb_table = "roxas-terraform-locks-dev"
