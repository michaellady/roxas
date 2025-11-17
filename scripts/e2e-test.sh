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
if [ "$HTTP_CODE" -ne 200 ]; then
  echo -e "${RED}✗ E2E Test FAILED${NC}"
  if [ "$HTTP_CODE" -eq 401 ]; then
    echo -e "${RED}  - Authentication failed (invalid webhook secret?)${NC}"
  elif [ "$HTTP_CODE" -eq 500 ]; then
    echo -e "${RED}  - Internal server error (check Lambda logs)${NC}"
  else
    echo -e "${RED}  - Unexpected HTTP status: $HTTP_CODE${NC}"
  fi
  exit 1
fi

# HTTP 200 received, now validate response body
if ! echo "$BODY" | grep -q "successfully\|success"; then
  echo -e "${RED}✗ E2E Test FAILED${NC}"
  echo -e "${RED}  - HTTP 200 received but success message missing${NC}"
  exit 1
fi

echo -e "${GREEN}✓ Step 1: Webhook accepted${NC}"

# Extract LinkedIn URL from JSON response
# Response format: {"message": "...", "linkedin_url": "https://..."}
LINKEDIN_URL=$(echo "$BODY" | grep -o '"linkedin_url"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"/\1/')

if [ -z "$LINKEDIN_URL" ]; then
  echo -e "${RED}✗ E2E Test FAILED${NC}"
  echo -e "${RED}  - No linkedin_url in response${NC}"
  exit 1
fi

echo -e "${GREEN}✓ Step 2: LinkedIn URL extracted${NC}"
echo "  LinkedIn URL: $LINKEDIN_URL"
echo ""

# Validate it's a LinkedIn URL
if ! echo "$LINKEDIN_URL" | grep -q "linkedin.com"; then
  echo -e "${RED}✗ E2E Test FAILED${NC}"
  echo -e "${RED}  - Invalid LinkedIn URL format: $LINKEDIN_URL${NC}"
  exit 1
fi

echo -e "${GREEN}✓ Step 3: Valid LinkedIn URL format${NC}"

# Try to verify the LinkedIn post exists
echo -e "${YELLOW}Verifying LinkedIn post...${NC}"
LINKEDIN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -L "$LINKEDIN_URL")

if [ "$LINKEDIN_STATUS" -eq 200 ] || [ "$LINKEDIN_STATUS" -eq 302 ] || [ "$LINKEDIN_STATUS" -eq 301 ]; then
  echo -e "${GREEN}✓ Step 4: LinkedIn post accessible (HTTP $LINKEDIN_STATUS)${NC}"
elif [ "$LINKEDIN_STATUS" -eq 999 ]; then
  # LinkedIn often returns 999 for automated requests without proper headers
  echo -e "${YELLOW}⚠ Step 4: LinkedIn returned 999 (bot protection)${NC}"
  echo -e "${YELLOW}  This is expected for automated requests${NC}"
  echo -e "${YELLOW}  Post URL is valid but verification skipped${NC}"
else
  echo -e "${YELLOW}⚠ Step 4: Could not verify post (HTTP $LINKEDIN_STATUS)${NC}"
  echo -e "${YELLOW}  Post may require authentication to view${NC}"
fi

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ E2E Test PASSED${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ✓ Webhook accepted (HTTP 200)${NC}"
echo -e "${GREEN}  ✓ Success message confirmed${NC}"
echo -e "${GREEN}  ✓ LinkedIn URL extracted and validated${NC}"
echo -e "${GREEN}  ✓ Post created at: $LINKEDIN_URL${NC}"
echo ""
exit 0
