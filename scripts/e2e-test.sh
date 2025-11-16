#!/bin/bash
set -e

# E2E Test Script for Roxas Webhook Handler
# Sends a real webhook to deployed Lambda and validates the response
#
# Usage:
#   LAMBDA_URL=https://... WEBHOOK_SECRET=... ./scripts/e2e-test.sh
#
# Required environment variables:
#   LAMBDA_URL - The deployed Lambda function URL
#   WEBHOOK_SECRET - GitHub webhook secret for HMAC signature

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check required environment variables
if [ -z "$LAMBDA_URL" ]; then
  echo -e "${RED}Error: LAMBDA_URL environment variable is required${NC}"
  echo "Usage: LAMBDA_URL=https://... WEBHOOK_SECRET=... $0"
  exit 1
fi

if [ -z "$WEBHOOK_SECRET" ]; then
  echo -e "${RED}Error: WEBHOOK_SECRET environment variable is required${NC}"
  echo "Usage: LAMBDA_URL=https://... WEBHOOK_SECRET=... $0"
  exit 1
fi

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PAYLOAD_FILE="$PROJECT_ROOT/tests/testdata/commit_webhook.json"

# Verify payload file exists
if [ ! -f "$PAYLOAD_FILE" ]; then
  echo -e "${RED}Error: Test payload not found at $PAYLOAD_FILE${NC}"
  exit 1
fi

echo -e "${YELLOW}=== E2E Test: Roxas Webhook Handler ===${NC}"
echo "Lambda URL: $LAMBDA_URL"
echo "Payload: $PAYLOAD_FILE"
echo ""

# Read payload
PAYLOAD=$(cat "$PAYLOAD_FILE")

# Generate HMAC signature
# GitHub sends: X-Hub-Signature-256: sha256=<hmac>
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | sed 's/^.* //')

echo -e "${YELLOW}Sending webhook request...${NC}"

# Send webhook request
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$LAMBDA_URL" \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
  -H "X-GitHub-Event: push" \
  -d "$PAYLOAD")

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
# Extract response body (all but last line)
BODY=$(echo "$RESPONSE" | sed '$d')

echo ""
echo -e "${YELLOW}Response:${NC}"
echo "HTTP Status: $HTTP_CODE"
echo "Body: $BODY"
echo ""

# Validate response
if [ "$HTTP_CODE" -eq 200 ]; then
  # Check if response contains success indicator
  if echo "$BODY" | grep -q "successfully\|success"; then
    echo -e "${GREEN}✓ E2E Test PASSED${NC}"
    echo -e "${GREEN}  - HTTP 200 received${NC}"
    echo -e "${GREEN}  - Success message confirmed${NC}"
    exit 0
  else
    echo -e "${RED}✗ E2E Test FAILED${NC}"
    echo -e "${RED}  - HTTP 200 received but success message missing${NC}"
    exit 1
  fi
elif [ "$HTTP_CODE" -eq 401 ]; then
  echo -e "${RED}✗ E2E Test FAILED${NC}"
  echo -e "${RED}  - Authentication failed (invalid webhook secret?)${NC}"
  exit 1
elif [ "$HTTP_CODE" -eq 500 ]; then
  echo -e "${RED}✗ E2E Test FAILED${NC}"
  echo -e "${RED}  - Internal server error (check Lambda logs)${NC}"
  exit 1
else
  echo -e "${RED}✗ E2E Test FAILED${NC}"
  echo -e "${RED}  - Unexpected HTTP status: $HTTP_CODE${NC}"
  exit 1
fi
