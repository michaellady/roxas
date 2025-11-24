# VPC Configuration for RDS PostgreSQL
# PR environments: Reference existing dev VPC (shared with RDS)
# Non-PR environments: Create isolated network with public/private subnets across 2 AZs

# Data sources: Reference existing dev VPC for PR environments
data "aws_vpc" "existing" {
  count = local.is_pr_environment ? 1 : 0

  filter {
    name   = "tag:Name"
    values = ["roxas-webhook-handler-dev-vpc"]
  }
}

data "aws_subnets" "existing_private" {
  count = local.is_pr_environment ? 1 : 0

  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.existing[0].id]
  }

  filter {
    name   = "tag:Name"
    values = ["roxas-webhook-handler-dev-private-*"]
  }
}

# Main VPC (only for non-PR environments)
resource "aws_vpc" "main" {
  count = local.is_pr_environment ? 0 : 1

  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-vpc"
  })
}

# Internet Gateway for public subnet access (only for non-PR environments)
resource "aws_internet_gateway" "main" {
  count = local.is_pr_environment ? 0 : 1

  vpc_id = aws_vpc.main[0].id

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-igw"
  })
}

# Public Subnets (for NAT Gateway if needed later) (only for non-PR environments)
resource "aws_subnet" "public" {
  count = local.is_pr_environment ? 0 : 2

  vpc_id            = aws_vpc.main[0].id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-public-${count.index + 1}"
    Type = "public"
  })
}

# Private Subnets (for RDS) (only for non-PR environments)
resource "aws_subnet" "private" {
  count = local.is_pr_environment ? 0 : 2

  vpc_id            = aws_vpc.main[0].id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-private-${count.index + 1}"
    Type = "private"
  })
}

# Route Table for Public Subnets (only for non-PR environments)
resource "aws_route_table" "public" {
  count = local.is_pr_environment ? 0 : 1

  vpc_id = aws_vpc.main[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main[0].id
  }

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-public-rt"
  })
}

# Route Table Associations for Public Subnets (only for non-PR environments)
resource "aws_route_table_association" "public" {
  count = local.is_pr_environment ? 0 : 2

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

# fck-nat: Cost-effective NAT instance (instead of $32/month NAT Gateway)
# Uses t4g.nano ARM instance (~$3/month on-demand) for Lambda internet access
# Only for non-PR environments (PR environments use existing dev NAT)
module "fck_nat" {
  source  = "RaJiska/fck-nat/aws"
  version = "1.4.0"

  count = local.is_pr_environment ? 0 : 1

  name               = "${var.function_name}-${var.environment}-nat"
  vpc_id             = aws_vpc.main[0].id
  subnet_id          = aws_subnet.public[0].id
  instance_type      = "t4g.nano"
  use_spot_instances = false # Spot capacity not always available

  tags = local.common_tags
}

# Route Table for Private Subnets (routes internet traffic through NAT)
# Only for non-PR environments
resource "aws_route_table" "private" {
  count = local.is_pr_environment ? 0 : 1

  vpc_id = aws_vpc.main[0].id

  route {
    cidr_block           = "0.0.0.0/0"
    network_interface_id = module.fck_nat[0].eni_id
  }

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-private-rt"
  })
}

# Route Table Associations for Private Subnets (only for non-PR environments)
resource "aws_route_table_association" "private" {
  count = local.is_pr_environment ? 0 : 2

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}

# Data source for availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# Locals: Unified VPC and subnet references
# These locals abstract whether we're using existing or created resources
locals {
  # VPC ID: Use existing dev VPC for PRs, created VPC otherwise
  vpc_id = local.is_pr_environment ? data.aws_vpc.existing[0].id : aws_vpc.main[0].id

  # Private subnet IDs: Use existing dev subnets for PRs, created subnets otherwise
  private_subnet_ids = local.is_pr_environment ? data.aws_subnets.existing_private[0].ids : aws_subnet.private[*].id

  # Public subnet IDs: Only exist for non-PR environments
  public_subnet_ids = local.is_pr_environment ? [] : aws_subnet.public[*].id
}
