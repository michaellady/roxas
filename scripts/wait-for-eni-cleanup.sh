#!/bin/bash
set -euo pipefail

# wait-for-eni-cleanup.sh
# Waits for Lambda ENIs to be released after function deletion
# This prevents VPC deletion failures due to attached network interfaces

FUNCTION_NAME="${1:-}"
MAX_WAIT_SECONDS="${2:-1200}"  # 20 minutes default
INITIAL_WAIT=15  # Start with 15 seconds between checks

if [ -z "$FUNCTION_NAME" ]; then
  echo "Usage: $0 <lambda-function-name> [max-wait-seconds]"
  echo "Example: $0 roxas-webhook-handler-pr-123 1200"
  exit 1
fi

echo "🔍 Checking for Lambda ENIs associated with function: $FUNCTION_NAME"

# Get Lambda function details to find VPC configuration
FUNCTION_INFO=$(aws lambda get-function --function-name "$FUNCTION_NAME" 2>/dev/null || echo "{}")

if [ "$FUNCTION_INFO" = "{}" ]; then
  echo "⚠️  Lambda function not found (already deleted). Checking for orphaned ENIs..."
  VPC_ID=""
else
  VPC_ID=$(echo "$FUNCTION_INFO" | jq -r '.Configuration.VpcConfig.VpcId // empty')

  if [ -z "$VPC_ID" ]; then
    echo "✅ Lambda function is not VPC-attached. No ENI cleanup needed."
    exit 0
  fi

  echo "📍 Function is in VPC: $VPC_ID"
fi

# Function to check for Lambda ENIs
check_enis() {
  local description_filter="$1"

  # Search for ENIs with Lambda-specific description patterns
  # Lambda ENIs have descriptions like "AWS Lambda VPC ENI-..."
  ENI_COUNT=$(aws ec2 describe-network-interfaces \
    --filters \
      "Name=description,Values=AWS Lambda VPC ENI-*" \
      "Name=description,Values=*$description_filter*" \
    --query 'NetworkInterfaces[?Status!=`available`].NetworkInterfaceId' \
    --output json 2>/dev/null | jq '. | length')

  echo "$ENI_COUNT"
}

# Extract function base name for ENI search
# Lambda ENIs often contain function name fragments in their descriptions
FUNCTION_BASE=$(echo "$FUNCTION_NAME" | sed 's/roxas-webhook-handler-//')

echo "🔎 Searching for ENIs with pattern: *$FUNCTION_BASE*"

# Initial check
ENI_COUNT=$(check_enis "$FUNCTION_BASE")

if [ "$ENI_COUNT" -eq 0 ]; then
  echo "✅ No Lambda ENIs found or all ENIs are already available. Safe to proceed."
  exit 0
fi

echo "⏳ Found $ENI_COUNT Lambda ENI(s) still detaching. Waiting for cleanup..."
echo "   (Lambda ENIs typically take 8-12 minutes to release after function deletion)"

# Polling loop with exponential backoff
ELAPSED=0
WAIT_INTERVAL=$INITIAL_WAIT
CHECK_COUNT=1

while [ "$ENI_COUNT" -gt 0 ] && [ "$ELAPSED" -lt "$MAX_WAIT_SECONDS" ]; do
  echo "   ⏱️  Check #$CHECK_COUNT: $ENI_COUNT ENI(s) remaining | Elapsed: ${ELAPSED}s/${MAX_WAIT_SECONDS}s | Next check in ${WAIT_INTERVAL}s"

  sleep "$WAIT_INTERVAL"
  ELAPSED=$((ELAPSED + WAIT_INTERVAL))
  CHECK_COUNT=$((CHECK_COUNT + 1))

  ENI_COUNT=$(check_enis "$FUNCTION_BASE")

  # Exponential backoff: 15s, 30s, 60s, 120s, then stay at 120s
  if [ "$WAIT_INTERVAL" -lt 120 ]; then
    WAIT_INTERVAL=$((WAIT_INTERVAL * 2))
    if [ "$WAIT_INTERVAL" -gt 120 ]; then
      WAIT_INTERVAL=120
    fi
  fi
done

# Final status
if [ "$ENI_COUNT" -eq 0 ]; then
  echo "✅ All Lambda ENIs released after ${ELAPSED}s. VPC resources can now be safely deleted."
  exit 0
else
  echo "⚠️  Timeout: $ENI_COUNT ENI(s) still attached after ${ELAPSED}s"
  echo "   AWS may still be releasing these ENIs. VPC deletion might fail."
  echo "   This is a known AWS limitation with Lambda ENI cleanup."

  # List remaining ENIs for debugging
  echo ""
  echo "🔍 Remaining ENI details:"
  aws ec2 describe-network-interfaces \
    --filters \
      "Name=description,Values=AWS Lambda VPC ENI-*" \
      "Name=description,Values=*$FUNCTION_BASE*" \
    --query 'NetworkInterfaces[?Status!=`available`].[NetworkInterfaceId,Status,Description]' \
    --output table 2>/dev/null || echo "Failed to retrieve ENI details"

  # Non-zero exit to signal timeout, but workflow can continue
  exit 1
fi
