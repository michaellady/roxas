# AWS Budget - Monthly spending limit
# TDD RED PHASE: This resource is intentionally incomplete and will fail validation
# Required fields are commented out to demonstrate the failing test state

resource "aws_budgets_budget" "monthly_cost" {
  name         = "${local.name_prefix}-monthly-budget"
  budget_type  = "COST"
  limit_amount = # TODO: Add limit amount
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # TODO: Add notification configuration
}
