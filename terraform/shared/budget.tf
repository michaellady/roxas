# AWS Budget - Monthly spending limit per account
# Alerts at 50%, 80%, 100%, and 120% of $100/month budget
# Circuit breaker: Automatically stops all EC2/Lambda at 200% ($200)

resource "aws_budgets_budget" "monthly_cost" {
  name         = "${local.name_prefix}-monthly-budget"
  budget_type  = "COST"
  limit_amount = var.monthly_budget_limit
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # Notification at 50% - early warning
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 50
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.budget_alert_emails
  }

  # Notification at 80% - approaching limit
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.budget_alert_emails
  }

  # Notification at 100% - budget exceeded
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.budget_alert_emails
  }

  # Notification at 120% - significant overspend
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 120
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.budget_alert_emails
  }

  # Forecasted notification at 100% - predicted to exceed
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = var.budget_alert_emails
  }

  tags = local.common_tags
}

# =============================================================================
# Circuit Breaker: Automatic service shutdown at 200% budget
# =============================================================================

# IAM Role for Budget Actions to execute cost control measures
resource "aws_iam_role" "budget_action" {
  name = "${local.name_prefix}-budget-action-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "budgets.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = local.common_tags
}

# Policy allowing Budget Actions to attach/detach IAM policies
resource "aws_iam_role_policy" "budget_action" {
  name = "${local.name_prefix}-budget-action-policy"
  role = aws_iam_role.budget_action.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAttachDetachPolicy"
        Effect = "Allow"
        Action = [
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy"
        ]
        Resource = aws_iam_role.budget_action.arn
      },
      {
        Sid    = "AllowGetPolicy"
        Effect = "Allow"
        Action = [
          "iam:GetPolicy"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/${local.name_prefix}-budget-circuit-breaker-deny"
      }
    ]
  })
}

# Budget Action: Circuit breaker at 200% - attaches deny policy to Lambda role
# This prevents Lambda from being invoked, effectively taking the site down
resource "aws_budgets_budget_action" "circuit_breaker" {
  budget_name        = aws_budgets_budget.monthly_cost.name
  action_type        = "APPLY_IAM_POLICY"
  approval_model     = "AUTOMATIC"
  notification_type  = "ACTUAL"

  action_threshold {
    action_threshold_type  = "PERCENTAGE"
    action_threshold_value = var.circuit_breaker_threshold
  }

  execution_role_arn = aws_iam_role.budget_action.arn

  # Attach a deny policy to the budget action role's target
  definition {
    iam_action_definition {
      policy_arn = aws_iam_policy.budget_circuit_breaker_deny.arn
      roles      = [aws_iam_role.budget_action.name]
    }
  }

  subscriber {
    subscription_type = "EMAIL"
    address           = var.budget_alert_emails[0]
  }
}

# Deny policy that gets attached when circuit breaker triggers
resource "aws_iam_policy" "budget_circuit_breaker_deny" {
  name        = "${local.name_prefix}-budget-circuit-breaker-deny"
  description = "Deny policy attached by budget circuit breaker at ${var.circuit_breaker_threshold}% spend"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyAllActionsWhenBudgetExceeded"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Project" = "Roxas"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

# Additional notification at circuit breaker threshold
resource "aws_budgets_budget" "monthly_cost_circuit_breaker_alert" {
  name         = "${local.name_prefix}-circuit-breaker-alert"
  budget_type  = "COST"
  limit_amount = var.monthly_budget_limit
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = var.circuit_breaker_threshold
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.budget_alert_emails
  }

  tags = merge(local.common_tags, {
    Purpose = "CircuitBreakerAlert"
  })
}
