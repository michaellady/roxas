provider "aws" {
  region = var.aws_region
}

# Latest Amazon Linux 2023 ARM64 AMI
data "aws_ami" "al2023_arm64" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-arm64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }
}

# Place VM in first public subnet from shared VPC
resource "aws_instance" "claude_vm" {
  ami                    = data.aws_ami.al2023_arm64.id
  instance_type          = var.instance_type
  key_name               = var.key_pair_name
  vpc_security_group_ids = [aws_security_group.claude_vm.id]
  subnet_id              = data.terraform_remote_state.shared.outputs.public_subnet_ids[0]
  iam_instance_profile   = aws_iam_instance_profile.claude_vm.name
  user_data              = file("${path.module}/user_data.sh")

  root_block_device {
    volume_size           = var.volume_size
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  # Require IMDSv2 — prevents SSRF attacks on instance metadata
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = {
    Name      = "claude-code-vm"
    Project   = "claude-code-vm"
    ManagedBy = "Terraform"
  }

  volume_tags = {
    Name      = "claude-code-vm-root"
    Project   = "claude-code-vm"
    ManagedBy = "Terraform"
  }
}

# Elastic IP for stable public address across stop/start cycles
resource "aws_eip" "claude_vm" {
  domain = "vpc"

  tags = {
    Name      = "claude-code-vm-eip"
    Project   = "claude-code-vm"
    ManagedBy = "Terraform"
  }
}

resource "aws_eip_association" "claude_vm" {
  instance_id   = aws_instance.claude_vm.id
  allocation_id = aws_eip.claude_vm.id
}
