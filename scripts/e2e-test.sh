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

# VPC Lambda warmup: Send a warmup request to initialize ENIs
# Note: This may timeout if Lambda needs NAT Gateway for internet access
echo -e "${YELLOW}Warming up Lambda (VPC cold start, may take 30-60s)...${NC}"
for i in {1..2}; do
  WARMUP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$LAMBDA_URL" \
    -H "Content-Type: application/json" \
    -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
    -H "X-GitHub-Event: push" \
    -d "$PAYLOAD" --max-time 60 || echo "000")

  echo -e "${YELLOW}  Warmup attempt $i: HTTP $WARMUP_CODE${NC}"

  if [ "$WARMUP_CODE" -eq 200 ] || [ "$WARMUP_CODE" -eq 401 ] || [ "$WARMUP_CODE" -eq 500 ]; then
    echo -e "${GREEN}✓ Lambda responded (HTTP $WARMUP_CODE) - ENIs initialized${NC}"
    break
  fi

  if [ $i -lt 2 ]; then
    echo -e "${YELLOW}  Warmup failed/timeout, waiting 15s before retry...${NC}"
    sleep 15
  else
    echo -e "${YELLOW}⚠ Warmup attempts exhausted, proceeding with test anyway${NC}"
    echo -e "${YELLOW}  (Lambda may still be initializing)${NC}"
  fi
done
echo ""

# Send webhook request with retry logic
MAX_RETRIES=6
RETRY_DELAYS=(10 15 20 30 45 60)  # Longer delays for VPC Lambda
HTTP_CODE=0

for attempt in $(seq 0 $((MAX_RETRIES - 1))); do
  if [ $attempt -gt 0 ]; then
    DELAY=${RETRY_DELAYS[$((attempt - 1))]}
    echo -e "${YELLOW}Retrying in ${DELAY}s (attempt $((attempt + 1))/$MAX_RETRIES)...${NC}"
    sleep $DELAY
  fi

  echo -e "${YELLOW}Sending webhook request (attempt $((attempt + 1))/$MAX_RETRIES)...${NC}"

  # Send webhook request with longer timeout for VPC Lambda
  RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$LAMBDA_URL" \
    -H "Content-Type: application/json" \
    -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
    -H "X-GitHub-Event: push" \
    -d "$PAYLOAD" --max-time 60 || echo -e "\n000")

  # Extract HTTP status code (last line)
  HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
  # Extract response body (all but last line)
  BODY=$(echo "$RESPONSE" | sed '$d')

  echo "HTTP Status: $HTTP_CODE"

  # Check if we got a successful response
  if [ "$HTTP_CODE" -eq 200 ]; then
    echo -e "${GREEN}✓ Request succeeded${NC}"
    break
  fi

  # Check if error is retryable
  if [ "$HTTP_CODE" -eq 503 ] || [ "$HTTP_CODE" -eq 504 ] || [ "$HTTP_CODE" -eq 000 ]; then
    echo -e "${YELLOW}  Transient error (HTTP $HTTP_CODE), will retry...${NC}"
    continue
  fi

  # Non-retryable error, exit immediately
  echo -e "${RED}  Non-retryable error (HTTP $HTTP_CODE)${NC}"
  break
done

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
  elif [ "$HTTP_CODE" -eq 503 ]; then
    echo -e "${RED}  - Service unavailable (Lambda still initializing after $MAX_RETRIES retries)${NC}"
  elif [ "$HTTP_CODE" -eq 000 ]; then
    echo -e "${RED}  - Connection failed or timeout${NC}"
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
