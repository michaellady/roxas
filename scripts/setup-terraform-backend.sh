#!/bin/bash
set -e

# Setup Terraform Remote State Backend
# Creates S3 bucket and DynamoDB table for Terraform state storage and locking
#
# Usage:
#   # For dev environment
#   ENVIRONMENT=dev ./scripts/setup-terraform-backend.sh
#
#   # For prod environment
#   ENVIRONMENT=prod ./scripts/setup-terraform-backend.sh
#
#   # With specific AWS profile
#   AWS_PROFILE=dev-admin ENVIRONMENT=dev ./scripts/setup-terraform-backend.sh
#
# Requirements:
#   - AWS CLI installed
#   - AWS credentials with permissions to create S3 buckets and DynamoDB tables
#   - ENVIRONMENT variable set to 'dev' or 'prod'

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check ENVIRONMENT variable
if [ -z "$ENVIRONMENT" ]; then
  echo -e "${RED}Error: ENVIRONMENT variable is required${NC}"
  echo "Usage: ENVIRONMENT=dev ./scripts/setup-terraform-backend.sh"
  echo "       ENVIRONMENT=prod ./scripts/setup-terraform-backend.sh"
  exit 1
fi

if [[ "$ENVIRONMENT" != "dev" && "$ENVIRONMENT" != "prod" ]]; then
  echo -e "${RED}Error: ENVIRONMENT must be 'dev' or 'prod'${NC}"
  exit 1
fi

# Configuration - environment-specific naming
S3_BUCKET="roxas-terraform-state-${ENVIRONMENT}"
DYNAMODB_TABLE="roxas-terraform-locks-${ENVIRONMENT}"
AWS_REGION="us-east-1"

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}Terraform Remote State Backend Setup${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Configuration:"
echo "  S3 Bucket: $S3_BUCKET"
echo "  DynamoDB Table: $DYNAMODB_TABLE"
echo "  Region: $AWS_REGION"
echo ""

# Check AWS CLI is installed
if ! command -v aws &> /dev/null; then
  echo -e "${RED}Error: AWS CLI is not installed${NC}"
  echo "Install from: https://aws.amazon.com/cli/"
  exit 1
fi

# Check AWS credentials are configured
if ! aws sts get-caller-identity &> /dev/null; then
  echo -e "${RED}Error: AWS credentials are not configured${NC}"
  echo "Run: aws configure"
  exit 1
fi

echo -e "${YELLOW}Step 1: Create S3 bucket for state storage${NC}"

# Check if bucket exists
if aws s3api head-bucket --bucket "$S3_BUCKET" 2>/dev/null; then
  echo -e "${GREEN}✓ S3 bucket already exists: $S3_BUCKET${NC}"
else
  echo "Creating S3 bucket..."
  aws s3api create-bucket \
    --bucket "$S3_BUCKET" \
    --region "$AWS_REGION" \
    2>/dev/null || {
      # If region is us-east-1, retry without location constraint
      aws s3api create-bucket \
        --bucket "$S3_BUCKET" \
        2>/dev/null
    }
  echo -e "${GREEN}✓ Created S3 bucket: $S3_BUCKET${NC}"
fi

echo ""
echo -e "${YELLOW}Step 2: Enable versioning on S3 bucket${NC}"
aws s3api put-bucket-versioning \
  --bucket "$S3_BUCKET" \
  --versioning-configuration Status=Enabled
echo -e "${GREEN}✓ Enabled versioning${NC}"

echo ""
echo -e "${YELLOW}Step 3: Enable encryption on S3 bucket${NC}"
aws s3api put-bucket-encryption \
  --bucket "$S3_BUCKET" \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'
echo -e "${GREEN}✓ Enabled encryption (AES256)${NC}"

echo ""
echo -e "${YELLOW}Step 4: Block public access on S3 bucket${NC}"
aws s3api put-public-access-block \
  --bucket "$S3_BUCKET" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
echo -e "${GREEN}✓ Blocked all public access${NC}"

echo ""
echo -e "${YELLOW}Step 5: Create DynamoDB table for state locking${NC}"

# Check if table exists
if aws dynamodb describe-table --table-name "$DYNAMODB_TABLE" --region "$AWS_REGION" &>/dev/null; then
  echo -e "${GREEN}✓ DynamoDB table already exists: $DYNAMODB_TABLE${NC}"
else
  echo "Creating DynamoDB table..."
  aws dynamodb create-table \
    --table-name "$DYNAMODB_TABLE" \
    --attribute-definitions AttributeName=LockID,AttributeType=S \
    --key-schema AttributeName=LockID,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region "$AWS_REGION" \
    &>/dev/null

  echo "Waiting for table to become active..."
  aws dynamodb wait table-exists \
    --table-name "$DYNAMODB_TABLE" \
    --region "$AWS_REGION"

  echo -e "${GREEN}✓ Created DynamoDB table: $DYNAMODB_TABLE${NC}"
fi

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ Backend Setup Complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Resources created:"
echo "  ✓ S3 Bucket: $S3_BUCKET (versioned, encrypted)"
echo "  ✓ DynamoDB Table: $DYNAMODB_TABLE (on-demand billing)"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. Add backend configuration to terraform/main.tf"
echo "2. Run 'terraform init' to migrate to remote backend"
echo "3. Update IAM permissions for github-actions-ci user"
echo ""
echo -e "${YELLOW}Backend configuration for ${ENVIRONMENT}:${NC}"
echo ""
cat <<EOF
terraform {
  backend "s3" {
    bucket         = "${S3_BUCKET}"
    key            = "terraform.tfstate"
    region         = "${AWS_REGION}"
    encrypt        = true
    dynamodb_table = "${DYNAMODB_TABLE}"
  }
}
EOF
echo ""
echo -e "${BLUE}Note:${NC} You'll need to create separate backend configs for dev and prod"
echo "or use backend configuration variables in your workflows."
echo ""
