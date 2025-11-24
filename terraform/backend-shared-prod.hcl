# Backend configuration for shared infrastructure (prod environment)
# Uses separate state file from service/ to manage infrastructure independently

bucket         = "roxas-terraform-state-prod"
key            = "shared/terraform.tfstate"
region         = "us-east-1"
encrypt        = true
dynamodb_table = "roxas-terraform-locks-prod"
