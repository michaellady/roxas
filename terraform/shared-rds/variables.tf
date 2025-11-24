variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "db_engine_version" {
  description = "PostgreSQL engine version"
  type        = string
  default     = "18"
}
