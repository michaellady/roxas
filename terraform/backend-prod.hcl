# Backend configuration for prod environment
# Run setup script first: ENVIRONMENT=prod ./scripts/setup-terraform-backend.sh
# Then: terraform init -backend-config=backend-prod.hcl

bucket         = "roxas-terraform-state-prod"
key            = "terraform.tfstate"
region         = "us-east-1"
encrypt        = true
dynamodb_table = "roxas-terraform-locks-prod"
