# VPC Configuration for RDS PostgreSQL
# Creates isolated network with public/private subnets across 2 AZs

# Main VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-vpc"
  })
}

# Internet Gateway for public subnet access
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-igw"
  })
}

# Public Subnets (for NAT Gateway if needed later)
resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-public-${count.index + 1}"
    Type = "public"
  })
}

# Private Subnets (for RDS)
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-private-${count.index + 1}"
    Type = "private"
  })
}

# Route Table for Public Subnets
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-public-rt"
  })
}

# Route Table Associations for Public Subnets
resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# fck-nat: Cost-effective NAT instance (instead of $32/month NAT Gateway)
# Uses t4g.nano ARM instance (~$3/month) for Lambda internet access
module "fck_nat" {
  source  = "RaJiska/fck-nat/aws"
  version = "1.4.0"

  name               = "${var.function_name}-${var.environment}-nat"
  vpc_id             = aws_vpc.main.id
  subnet_id          = aws_subnet.public[0].id
  instance_type      = "t4g.nano"
  use_spot_instances = true

  tags = local.common_tags
}

# Route Table for Private Subnets (routes internet traffic through NAT)
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block           = "0.0.0.0/0"
    network_interface_id = module.fck_nat.eni_id
  }

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-private-rt"
  })
}

# Route Table Associations for Private Subnets
resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Data source for availability zones
data "aws_availability_zones" "available" {
  state = "available"
}
