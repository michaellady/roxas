# Backend configuration for dev environment
# Run setup script first: ENVIRONMENT=dev ./scripts/setup-terraform-backend.sh
# Then: terraform init -backend-config=backend-dev.hcl

bucket         = "roxas-terraform-state-dev"
key            = "terraform.tfstate"
region         = "us-east-1"
encrypt        = true
dynamodb_table = "roxas-terraform-locks-dev"
