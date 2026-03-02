output "public_ip" {
  description = "Public IP address of the Claude Code VM (Elastic IP)"
  value       = aws_eip.claude_vm.public_ip
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.claude_vm.id
}

output "ssh_command" {
  description = "SSH command to connect as claude-user (only useful if key_pair_name was set)"
  value       = var.key_pair_name != null ? "ssh -i ${var.key_pair_name}.pem claude-user@${aws_eip.claude_vm.public_ip}" : "N/A — no key pair configured, use SSM Session Manager"
}

output "ssm_command" {
  description = "SSM Session Manager command (no SSH key needed)"
  value       = "aws ssm start-session --target ${aws_instance.claude_vm.id}"
}
