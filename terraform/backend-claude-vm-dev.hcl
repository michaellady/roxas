# Backend configuration for Claude Code VM (dev environment)
# Separate state file from shared/ and service/ — can be destroyed independently

bucket         = "roxas-terraform-state-dev"
key            = "claude-vm/terraform.tfstate"
region         = "us-east-1"
encrypt        = true
dynamodb_table = "roxas-terraform-locks-dev"
