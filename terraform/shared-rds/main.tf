terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Remote state backend for shared RDS
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region
}

# Reference existing VPC from dev environment
data "aws_vpc" "main" {
  filter {
    name   = "tag:Name"
    values = ["roxas-webhook-handler-dev-vpc"]
  }
}

# Reference existing private subnets
data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.main.id]
  }

  filter {
    name   = "tag:Name"
    values = ["roxas-webhook-handler-dev-private-*"]
  }
}

# Reference existing RDS security group
data "aws_security_group" "rds" {
  vpc_id = data.aws_vpc.main.id

  filter {
    name   = "tag:Name"
    values = ["roxas-webhook-handler-dev-rds-sg"]
  }
}

locals {
  common_tags = {
    Project     = "Roxas"
    Environment = "dev"
    ManagedBy   = "Terraform"
    Purpose     = "shared-pr-rds"
  }
}

# Shared RDS Module
module "shared_rds" {
  source = "../modules/shared-rds"

  environment            = "dev"
  private_subnet_ids     = data.aws_subnets.private.ids
  rds_security_group_id  = data.aws_security_group.rds.id
  db_engine_version      = var.db_engine_version
  common_tags            = local.common_tags
}
