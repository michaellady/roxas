# AWS Budget - Monthly spending limit per account
# Alerts at 50%, 80%, 100%, 120%, and 200% of budget
# Circuit breaker at 200%: Attaches deny policy to Lambda execution role (prod only)
# Note: Dev PR environments require manual intervention - see roxas-b2gx for SNS-based solution

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

  # Notification at circuit breaker threshold (200%) - critical
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = var.circuit_breaker_threshold
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
#
# LIMITATION: AWS Budget Actions with APPLY_IAM_POLICY require specifying
# exact role names at deploy time. This works for prod (known role name) but
# not for dev PR environments (dynamic role names).
#
# For comprehensive circuit breaker coverage, see roxas-b2gx which implements
# an SNS-triggered Lambda that can discover and disable all roxas-* functions.
# =============================================================================

locals {
  # Lambda execution role name follows convention: {function}-{env}-exec-role
  # For prod: roxas-webhook-handler-prod-exec-role
  # For dev: Role names are dynamic per PR, so circuit breaker only sends alerts
  lambda_exec_role_name = var.environment == "prod" ? "roxas-webhook-handler-prod-exec-role" : null

  # Only enable circuit breaker action for prod where we know the role name
  enable_circuit_breaker_action = var.environment == "prod"
}

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
        # Allow attaching to Lambda execution role (prod only)
        Resource = local.enable_circuit_breaker_action ? "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.lambda_exec_role_name}" : aws_iam_role.budget_action.arn
      },
      {
        Sid    = "AllowGetPolicy"
        Effect = "Allow"
        Action = [
          "iam:GetPolicy"
        ]
        Resource = aws_iam_policy.budget_circuit_breaker_deny.arn
      }
    ]
  })
}

# Budget Action: Circuit breaker at 200% - attaches deny policy to Lambda role
# Only enabled for prod environment where Lambda role name is known
resource "aws_budgets_budget_action" "circuit_breaker" {
  count = local.enable_circuit_breaker_action ? 1 : 0

  budget_name        = aws_budgets_budget.monthly_cost.name
  action_type        = "APPLY_IAM_POLICY"
  approval_model     = "AUTOMATIC"
  notification_type  = "ACTUAL"

  action_threshold {
    action_threshold_type  = "PERCENTAGE"
    action_threshold_value = var.circuit_breaker_threshold
  }

  execution_role_arn = aws_iam_role.budget_action.arn

  # Attach deny policy to Lambda execution role
  definition {
    iam_action_definition {
      policy_arn = aws_iam_policy.budget_circuit_breaker_deny.arn
      roles      = [local.lambda_exec_role_name]
    }
  }

  subscriber {
    subscription_type = "EMAIL"
    address           = var.budget_alert_emails[0]
  }
}

# Deny policy that gets attached when circuit breaker triggers
# Specifically denies Lambda invocation and API Gateway access
resource "aws_iam_policy" "budget_circuit_breaker_deny" {
  name        = "${local.name_prefix}-budget-circuit-breaker-deny"
  description = "Deny policy attached by budget circuit breaker at ${var.circuit_breaker_threshold}% spend"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyLambdaInvocation"
        Effect = "Deny"
        Action = [
          "lambda:InvokeFunction",
          "lambda:InvokeAsync"
        ]
        Resource = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:roxas-*"
      },
      {
        Sid    = "DenySecretsAccess"
        Effect = "Deny"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:roxas-*"
      },
      {
        Sid    = "DenyRDSAccess"
        Effect = "Deny"
        Action = [
          "rds-db:connect"
        ]
        Resource = "arn:aws:rds-db:${var.aws_region}:${data.aws_caller_identity.current.account_id}:dbuser:*/roxas_*"
      }
    ]
  })

  tags = local.common_tags
}
