variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type (t4g.medium = 4GB, t4g.large = 8GB)"
  type        = string
  default     = "t4g.medium"
}

variable "key_pair_name" {
  description = "Name of an existing EC2 key pair for SSH access (optional — use SSM Session Manager instead)"
  type        = string
  default     = null
}

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed to SSH into the VM"
  type        = list(string)
  default     = []
}

variable "volume_size" {
  description = "Root EBS volume size in GB"
  type        = number
  default     = 20
}
