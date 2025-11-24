# Backend configuration for shared infrastructure (dev environment)
# Uses separate state file from service/ to manage infrastructure independently

bucket         = "roxas-terraform-state-dev"
key            = "shared/terraform.tfstate"
region         = "us-east-1"
encrypt        = true
dynamodb_table = "roxas-terraform-locks-dev"
