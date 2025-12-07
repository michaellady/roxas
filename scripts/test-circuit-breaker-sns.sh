#!/bin/bash
# Test the circuit breaker SNS trigger
# This publishes a message to the SNS topic, simulating what AWS Budgets does
#
# Usage:
#   ./scripts/test-circuit-breaker-sns.sh dev   # Test in dev account
#   ./scripts/test-circuit-breaker-sns.sh prod  # Test in prod account
#
# NOTE: Ensure DRY_RUN=true is set on the Lambda before running this!

set -euo pipefail

ENV="${1:-dev}"

if [[ "$ENV" == "dev" ]]; then
    PROFILE="dev-admin"
    TOPIC_NAME="roxas-dev-budget-circuit-breaker"
elif [[ "$ENV" == "prod" ]]; then
    PROFILE="prod-admin"
    TOPIC_NAME="roxas-prod-budget-circuit-breaker"
else
    echo "Usage: $0 <dev|prod>"
    exit 1
fi

echo "============================================"
echo "Circuit Breaker SNS Trigger Test"
echo "============================================"
echo "Environment: $ENV"
echo "AWS Profile: $PROFILE"
echo "Topic:       $TOPIC_NAME"
echo "============================================"
echo

# Get the SNS topic ARN
echo "Looking up SNS topic..."
TOPIC_ARN=$(AWS_PROFILE=$PROFILE aws sns list-topics --query "Topics[?contains(TopicArn, '$TOPIC_NAME')].TopicArn" --output text)

if [[ -z "$TOPIC_ARN" ]]; then
    echo "ERROR: SNS topic $TOPIC_NAME not found"
    exit 1
fi
echo "✓ Found topic: $TOPIC_ARN"
echo

# Check Lambda DRY_RUN setting
FUNCTION_NAME="roxas-$ENV-circuit-breaker"
echo "Checking Lambda DRY_RUN setting..."
DRY_RUN_VALUE=$(AWS_PROFILE=$PROFILE aws lambda get-function-configuration \
    --function-name "$FUNCTION_NAME" \
    --query 'Environment.Variables.DRY_RUN' --output text 2>/dev/null || echo "")

if [[ "$DRY_RUN_VALUE" != "true" ]]; then
    echo "⚠️  WARNING: DRY_RUN is not set to 'true' on the Lambda!"
    echo "   Current value: $DRY_RUN_VALUE"
    echo
    echo "This will ACTUALLY STOP your resources!"
    read -p "Type 'yes' to continue anyway: " confirm
    if [[ "$confirm" != "yes" ]]; then
        echo "Aborted. Set DRY_RUN=true first:"
        echo "  AWS_PROFILE=$PROFILE aws lambda update-function-configuration \\"
        echo "    --function-name $FUNCTION_NAME \\"
        echo "    --environment 'Variables={FUNCTION_PREFIX=roxas-,DRY_RUN=true}'"
        exit 1
    fi
else
    echo "✓ DRY_RUN=true (safe to test)"
fi
echo

# Create a budget alert message (similar to what AWS Budgets sends)
MESSAGE=$(cat <<EOF
{
  "budgetName": "roxas-$ENV-monthly-budget",
  "notificationType": "ACTUAL",
  "threshold": 200,
  "thresholdType": "PERCENTAGE",
  "actualSpend": "200.00",
  "budgetLimit": "100.00",
  "source": "manual_sns_test"
}
EOF
)

echo "Publishing test message to SNS..."
echo "Message: $MESSAGE"
echo

MESSAGE_ID=$(AWS_PROFILE=$PROFILE aws sns publish \
    --topic-arn "$TOPIC_ARN" \
    --message "$MESSAGE" \
    --subject "Budget Circuit Breaker Test" \
    --query 'MessageId' --output text)

echo "✓ Published message: $MESSAGE_ID"
echo

echo "Waiting 5 seconds for Lambda to process..."
sleep 5

echo
echo "============================================"
echo "Recent CloudWatch Logs:"
echo "============================================"
LOG_GROUP="/aws/lambda/$FUNCTION_NAME"
START_TIME=$(($(date +%s) - 30))000

AWS_PROFILE=$PROFILE aws logs filter-log-events \
    --log-group-name "$LOG_GROUP" \
    --start-time "$START_TIME" \
    --query 'events[*].message' \
    --output text 2>/dev/null | head -40 || echo "(no recent logs - Lambda may not have triggered yet)"

echo
echo "============================================"
echo "Test complete!"
echo "============================================"
echo
echo "If no logs appeared, wait a moment and check manually:"
echo "  AWS_PROFILE=$PROFILE aws logs tail $LOG_GROUP --since 1m"
