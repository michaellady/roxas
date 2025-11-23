# Security Groups for RDS and Lambda

# Security Group for RDS PostgreSQL
resource "aws_security_group" "rds" {
  name_prefix = "${var.function_name}-${var.environment}-rds-"
  description = "Security group for RDS PostgreSQL instance"
  vpc_id      = aws_vpc.main.id

  # Allow PostgreSQL access from Lambda
  ingress {
    description     = "PostgreSQL from Lambda"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
  }

  # Allow all outbound traffic
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-rds-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Security Group for Lambda
resource "aws_security_group" "lambda" {
  name_prefix = "${var.function_name}-${var.environment}-lambda-"
  description = "Security group for Lambda function"
  vpc_id      = aws_vpc.main.id

  # Allow all outbound traffic (for RDS, Secrets Manager, OpenAI API)
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.function_name}-${var.environment}-lambda-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}
