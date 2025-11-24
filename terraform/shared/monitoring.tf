# CloudWatch Monitoring for Shared Infrastructure
# Alarms and dashboard for RDS health

# CloudWatch alarm for high connection count
resource "aws_cloudwatch_metric_alarm" "rds_connections" {
  alarm_name          = "${local.name_prefix}-rds-high-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 300 # 5 minutes
  statistic           = "Average"
  threshold           = 60 # Alert at 60 connections (~75% of 80 max for t4g.micro)
  alarm_description   = "Alert when RDS connections exceed 60. Max ~80 for t4g.micro."

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }

  tags = local.common_tags
}

# CloudWatch alarm for storage space
resource "aws_cloudwatch_metric_alarm" "rds_storage" {
  alarm_name          = "${local.name_prefix}-rds-low-storage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300 # 5 minutes
  statistic           = "Average"
  threshold           = 4294967296 # 4 GB (20% of 20GB)
  alarm_description   = "Alert when RDS free storage drops below 4 GB."

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }

  tags = local.common_tags
}

# CloudWatch alarm for CPU utilization
resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${local.name_prefix}-rds-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300 # 5 minutes
  statistic           = "Average"
  threshold           = 80 # Alert at 80% CPU
  alarm_description   = "Alert when RDS CPU exceeds 80%."

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }

  tags = local.common_tags
}

# CloudWatch alarm for freeable memory
resource "aws_cloudwatch_metric_alarm" "rds_memory" {
  alarm_name          = "${local.name_prefix}-rds-low-memory"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "FreeableMemory"
  namespace           = "AWS/RDS"
  period              = 300 # 5 minutes
  statistic           = "Average"
  threshold           = 104857600 # 100 MB
  alarm_description   = "Alert when RDS freeable memory drops below 100 MB."

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }

  tags = local.common_tags
}

# CloudWatch Dashboard for RDS health monitoring
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${local.name_prefix}-health"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Database Connections"
          region = var.aws_region
          metrics = [
            ["AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", aws_db_instance.main.id, { label = "Active Connections" }]
          ]
          annotations = {
            horizontal = [
              { label = "Warning (60)", value = 60, color = "#ff7f0e" },
              { label = "Max (~80)", value = 80, color = "#d62728" }
            ]
          }
          yAxis  = { left = { min = 0, max = 100 } }
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "CPU Utilization"
          region = var.aws_region
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", aws_db_instance.main.id, { label = "CPU %" }]
          ]
          annotations = {
            horizontal = [
              { label = "Warning (80%)", value = 80, color = "#ff7f0e" }
            ]
          }
          yAxis  = { left = { min = 0, max = 100 } }
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Free Storage Space"
          region = var.aws_region
          metrics = [
            ["AWS/RDS", "FreeStorageSpace", "DBInstanceIdentifier", aws_db_instance.main.id, { label = "Free Space (bytes)" }]
          ]
          annotations = {
            horizontal = [
              { label = "Warning (4GB)", value = 4294967296, color = "#ff7f0e" }
            ]
          }
          period = 300
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Freeable Memory"
          region = var.aws_region
          metrics = [
            ["AWS/RDS", "FreeableMemory", "DBInstanceIdentifier", aws_db_instance.main.id, { label = "Freeable Memory (bytes)" }]
          ]
          annotations = {
            horizontal = [
              { label = "Warning (100MB)", value = 104857600, color = "#ff7f0e" }
            ]
          }
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "Read/Write IOPS"
          region = var.aws_region
          metrics = [
            ["AWS/RDS", "ReadIOPS", "DBInstanceIdentifier", aws_db_instance.main.id, { label = "Read IOPS" }],
            ["AWS/RDS", "WriteIOPS", "DBInstanceIdentifier", aws_db_instance.main.id, { label = "Write IOPS" }]
          ]
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "Network Throughput"
          region = var.aws_region
          metrics = [
            ["AWS/RDS", "NetworkReceiveThroughput", "DBInstanceIdentifier", aws_db_instance.main.id, { label = "Receive (bytes/sec)" }],
            ["AWS/RDS", "NetworkTransmitThroughput", "DBInstanceIdentifier", aws_db_instance.main.id, { label = "Transmit (bytes/sec)" }]
          ]
          period = 60
          stat   = "Average"
        }
      },
      {
        type   = "text"
        x      = 0
        y      = 18
        width  = 24
        height = 3
        properties = {
          markdown = <<-EOT
## ${var.environment == "dev" ? "Shared RDS" : "Production RDS"} Capacity Guidelines
- **Instance**: ${var.db_instance_class} (~80 max connections for t4g.micro)
- **Environment**: ${var.environment}
${var.environment == "dev" ? "- **PR Capacity**: Each PR Lambda should use max 10 connections\n- **Comfortable capacity**: 3 concurrent PRs (30 connections + overhead)" : "- **Production database**: Single dedicated instance"}
EOT
        }
      }
    ]
  })
}
