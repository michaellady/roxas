#!/bin/bash
# Test script for the circuit breaker Lambda
#
# Usage:
#   ./scripts/test-circuit-breaker.sh dev      # Test in dev account (dry run)
#   ./scripts/test-circuit-breaker.sh dev live # Test in dev account (REAL - will stop resources!)
#   ./scripts/test-circuit-breaker.sh prod     # Test in prod account (dry run)
#
# Prerequisites:
#   - AWS CLI configured with appropriate profile
#   - Lambda deployed via Terraform

set -euo pipefail

ENV="${1:-dev}"
MODE="${2:-dry}"

if [[ "$ENV" == "dev" ]]; then
    PROFILE="dev-admin"
    FUNCTION_NAME="roxas-dev-circuit-breaker"
elif [[ "$ENV" == "prod" ]]; then
    PROFILE="prod-admin"
    FUNCTION_NAME="roxas-prod-circuit-breaker"
else
    echo "Usage: $0 <dev|prod> [dry|live]"
    exit 1
fi

echo "============================================"
echo "Circuit Breaker Test"
echo "============================================"
echo "Environment: $ENV"
echo "AWS Profile: $PROFILE"
echo "Function:    $FUNCTION_NAME"
echo "Mode:        $MODE"
echo "============================================"
echo

# Check if function exists
echo "Checking Lambda function exists..."
if ! AWS_PROFILE=$PROFILE aws lambda get-function --function-name "$FUNCTION_NAME" > /dev/null 2>&1; then
    echo "ERROR: Lambda function $FUNCTION_NAME not found"
    echo "Have you deployed the shared infrastructure?"
    exit 1
fi
echo "✓ Lambda function exists"
echo

# If dry run, update the environment variable
if [[ "$MODE" == "dry" ]]; then
    echo "Setting DRY_RUN=true on Lambda..."
    AWS_PROFILE=$PROFILE aws lambda update-function-configuration \
        --function-name "$FUNCTION_NAME" \
        --environment "Variables={FUNCTION_PREFIX=roxas-,DRY_RUN=true}" \
        --query 'FunctionArn' --output text
    echo "✓ Dry run mode enabled"
    echo

    # Wait for update to complete
    echo "Waiting for configuration update..."
    AWS_PROFILE=$PROFILE aws lambda wait function-updated --function-name "$FUNCTION_NAME"
    echo "✓ Configuration updated"
    echo
else
    echo "⚠️  WARNING: LIVE MODE - Resources will be stopped!"
    echo "Setting DRY_RUN=false on Lambda..."
    AWS_PROFILE=$PROFILE aws lambda update-function-configuration \
        --function-name "$FUNCTION_NAME" \
        --environment "Variables={FUNCTION_PREFIX=roxas-,DRY_RUN=false}" \
        --query 'FunctionArn' --output text

    echo
    read -p "Type 'yes' to continue with LIVE mode: " confirm
    if [[ "$confirm" != "yes" ]]; then
        echo "Aborted."
        exit 1
    fi
fi

# Create test SNS event payload
PAYLOAD=$(cat <<EOF
{
  "Records": [
    {
      "Sns": {
        "Message": "{\"test\": true, \"source\": \"manual_test\", \"mode\": \"$MODE\"}"
      }
    }
  ]
}
EOF
)

echo "Invoking Lambda with test payload..."
echo

RESPONSE_FILE=$(mktemp)
AWS_PROFILE=$PROFILE aws lambda invoke \
    --function-name "$FUNCTION_NAME" \
    --cli-binary-format raw-in-base64-out \
    --payload "$PAYLOAD" \
    "$RESPONSE_FILE"

echo
echo "============================================"
echo "Lambda Response:"
echo "============================================"
cat "$RESPONSE_FILE" | jq .
rm "$RESPONSE_FILE"

echo
echo "============================================"
echo "Recent CloudWatch Logs:"
echo "============================================"
LOG_GROUP="/aws/lambda/$FUNCTION_NAME"
START_TIME=$(($(date +%s) - 60))000

AWS_PROFILE=$PROFILE aws logs filter-log-events \
    --log-group-name "$LOG_GROUP" \
    --start-time "$START_TIME" \
    --query 'events[*].message' \
    --output text 2>/dev/null | head -30 || echo "(no recent logs)"

echo
echo "============================================"
echo "Test complete!"
echo "============================================"

if [[ "$MODE" == "dry" ]]; then
    echo
    echo "This was a DRY RUN - no resources were actually stopped."
    echo "To run for real: $0 $ENV live"
fi
