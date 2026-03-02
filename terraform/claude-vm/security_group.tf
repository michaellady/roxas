# Security group for Claude Code VM
# Inbound: SSH from allowed CIDRs only
# Outbound: HTTPS (443) + SSH (22) only — blocks all other egress

data "terraform_remote_state" "shared" {
  backend = "s3"
  config = {
    bucket = "roxas-terraform-state-dev"
    key    = "shared/terraform.tfstate"
    region = var.aws_region
  }
  # Shared infra uses workspaces; dev workspace for the VPC
  workspace = "dev"
}

resource "aws_security_group" "claude_vm" {
  name        = "claude-code-vm-sg"
  description = "Security group for Claude Code VM"
  vpc_id      = data.terraform_remote_state.shared.outputs.vpc_id

  tags = {
    Name      = "claude-code-vm-sg"
    Project   = "claude-code-vm"
    ManagedBy = "Terraform"
  }
}

# Inbound: SSH from allowed CIDRs
resource "aws_vpc_security_group_ingress_rule" "ssh" {
  count = length(var.allowed_ssh_cidrs)

  security_group_id = aws_security_group.claude_vm.id
  description       = "SSH from allowed CIDR"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = var.allowed_ssh_cidrs[count.index]

  tags = {
    Name = "claude-code-vm-ssh-${count.index}"
  }
}

# Outbound: HTTPS (443) — required for Anthropic API, GitHub, npm, package repos
resource "aws_vpc_security_group_egress_rule" "https" {
  security_group_id = aws_security_group.claude_vm.id
  description       = "HTTPS outbound (Anthropic API, GitHub, npm)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "claude-code-vm-https-out"
  }
}

# Outbound: SSH (22) — required for git clone over SSH
resource "aws_vpc_security_group_egress_rule" "ssh_out" {
  security_group_id = aws_security_group.claude_vm.id
  description       = "SSH outbound (git clone over SSH)"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "claude-code-vm-ssh-out"
  }
}

# Outbound: HTTP (80) — required for yum package manager during user_data bootstrap
resource "aws_vpc_security_group_egress_rule" "http_out" {
  security_group_id = aws_security_group.claude_vm.id
  description       = "HTTP outbound (yum repos, package downloads during bootstrap)"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "claude-code-vm-http-out"
  }
}
