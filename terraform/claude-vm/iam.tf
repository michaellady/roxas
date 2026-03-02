# IAM role for Claude Code VM
# Minimal permissions: SSM Session Manager only + explicit Deny on all roxas-* resources

resource "aws_iam_role" "claude_vm" {
  name = "claude-code-vm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name      = "claude-code-vm-role"
    Project   = "claude-code-vm"
    ManagedBy = "Terraform"
  }
}

resource "aws_iam_role_policy" "claude_vm_ssm" {
  name = "claude-code-vm-ssm"
  role = aws_iam_role.claude_vm.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSSMSessionManager"
        Effect = "Allow"
        Action = [
          "ssm:UpdateInstanceInformation",
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "claude_vm_deny_roxas" {
  name = "claude-code-vm-deny-roxas"
  role = aws_iam_role.claude_vm.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyAllRoxasResources"
        Effect   = "Deny"
        Action   = "*"
        Resource = [
          "arn:aws:lambda:*:*:function:roxas-*",
          "arn:aws:rds:*:*:db:roxas-*",
          "arn:aws:rds:*:*:cluster:roxas-*",
          "arn:aws:secretsmanager:*:*:secret:roxas-*",
          "arn:aws:s3:::roxas-terraform-state-*",
          "arn:aws:s3:::roxas-terraform-state-*/*",
          "arn:aws:dynamodb:*:*:table/roxas-terraform-locks-*",
          "arn:aws:sns:*:*:roxas-*",
          "arn:aws:iam::*:role/roxas-*",
          "arn:aws:iam::*:policy/roxas-*",
          "arn:aws:execute-api:*:*:*/roxas-*",
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "claude_vm" {
  name = "claude-code-vm-profile"
  role = aws_iam_role.claude_vm.name

  tags = {
    Name      = "claude-code-vm-profile"
    Project   = "claude-code-vm"
    ManagedBy = "Terraform"
  }
}
