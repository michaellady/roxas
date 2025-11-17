# End-to-End Testing Guide

This document describes how to run end-to-end tests for the Roxas automation system.

## Overview

The E2E test verifies the complete flow from GitHub webhook to LinkedIn post:

```
GitHub Commit → Webhook → Lambda → GPT-4 Summary → DALL-E Image → LinkedIn Post
```

## Automated E2E Testing

### CI/CD Integration

E2E tests run automatically in the CI/CD pipeline:

**PR Deployments** (`pr-deploy-dev.yml`):
- Deploys to dev environment
- Runs E2E test against dev Lambda
- Posts results as PR comment

**Production Deployments** (`main-deploy-prod.yml`):
- Deploys to production environment
- Runs E2E test to verify deployment
- Reports in GitHub Actions log

### Test Script

The E2E test is implemented in `scripts/e2e-test.sh` and is executed via:

```bash
make e2e
```

**Requirements:**
- `LAMBDA_URL`: Full webhook URL (from Terraform output)
- `WEBHOOK_SECRET`: GitHub webhook secret

## Manual E2E Testing

### Prerequisites

1. **Deployed Lambda Function**
   - Dev or prod environment
   - Obtain webhook URL from Terraform outputs

2. **Environment Variables**
   ```bash
   export LAMBDA_URL="https://your-api-gateway-id.execute-api.us-east-1.amazonaws.com/webhook"
   export WEBHOOK_SECRET="your-webhook-secret"
   ```

3. **Test Payload**
   - Valid GitHub push webhook payload
   - Includes commit data

### Running the Test

```bash
# Set environment variables
export LAMBDA_URL="https://..."
export WEBHOOK_SECRET="..."

# Run E2E test
make e2e

# Or run script directly
./scripts/e2e-test.sh
```

### Expected Output

**Success:**
```
Testing webhook endpoint...
✓ Webhook accepted (HTTP 200)
✓ LinkedIn post created
✓ E2E test PASSED
```

**Failure Examples:**
```
✗ Invalid signature (HTTP 401)
✗ Lambda error (HTTP 500)
✗ E2E test FAILED
```

## Test Flow Details

### 1. Webhook Request

The test sends a POST request to `/webhook` with:

**Headers:**
- `Content-Type: application/json`
- `X-Hub-Signature-256: sha256=<HMAC>`
- `X-GitHub-Event: push`

**Body:**
```json
{
  "ref": "refs/heads/main",
  "repository": {
    "name": "roxas",
    "full_name": "michaellady/roxas"
  },
  "commits": [
    {
      "id": "abc123...",
      "message": "Test commit for E2E validation",
      "author": {
        "name": "E2E Test",
        "email": "test@example.com"
      },
      "url": "https://github.com/michaellady/roxas/commit/abc123"
    }
  ]
}
```

### 2. Lambda Processing

Lambda function:
1. Validates GitHub signature
2. Parses webhook payload
3. Orchestrates the flow:
   - GPT-4 summarizes commit
   - DALL-E generates image
   - LinkedIn API posts content

### 3. Verification

The test verifies:
- HTTP 200 response received
- No error messages in response
- Lambda completes within timeout (30s)

**Note:** The test does NOT verify LinkedIn post creation directly (would require LinkedIn API polling). Production verification requires manual check of LinkedIn feed.

## Viewing Test Results

### CI/CD Logs

**GitHub Actions:**
1. Go to repository → Actions tab
2. Select workflow run
3. Expand "Run E2E Test" step
4. View test output

**Example Output:**
```
Run ./scripts/e2e-test.sh
Testing webhook: https://abc123.execute-api.us-east-1.amazonaws.com/webhook
Generating signature...
Sending webhook request...
Response: {"message":"Webhook processed successfully"}
✓ E2E test completed successfully
```

### CloudWatch Logs

View detailed Lambda execution logs:

```bash
# AWS CLI
aws logs tail /aws/lambda/roxas-webhook-handler-prod --follow --since 5m

# Filter for errors
aws logs tail /aws/lambda/roxas-webhook-handler-prod --filter-pattern "ERROR" --since 1h
```

**Key Log Messages:**
- `Received webhook request: POST`
- `Webhook signature validated`
- `Generated summary: ...`
- `Generated image: ...`
- `Posted to LinkedIn: ...`

## Troubleshooting

### Test Fails with 401 Unauthorized

**Cause:** Signature validation failed

**Solutions:**
1. Verify `WEBHOOK_SECRET` matches Lambda environment variable
2. Check signature generation in test script
3. Ensure no extra whitespace in secret

### Test Fails with 500 Internal Server Error

**Cause:** Lambda execution error

**Solutions:**
1. Check CloudWatch logs for error details
2. Verify all environment variables are set in Lambda:
   - `OPENAI_API_KEY`
   - `LINKEDIN_ACCESS_TOKEN`
   - `WEBHOOK_SECRET`
3. Check API quotas (OpenAI, LinkedIn)

### Test Succeeds but No LinkedIn Post

**Possible Causes:**
1. LinkedIn access token expired (90-day expiration)
2. LinkedIn API rate limiting
3. Post filtered by LinkedIn (spam detection)

**Debug Steps:**
1. Check CloudWatch logs for LinkedIn API response
2. Verify access token is valid
3. Test LinkedIn API directly with curl

### Test Timeout

**Cause:** Lambda execution exceeds 30s timeout

**Solutions:**
1. Check if OpenAI API is responding slowly
2. Review Lambda timeout setting in Terraform
3. Check for network issues between Lambda and external APIs

## Production Verification

After E2E test passes, verify manually:

1. **Check LinkedIn Feed**
   - Go to https://linkedin.com/feed
   - Verify new post appears
   - Confirm image and text are correct

2. **Review CloudWatch Metrics**
   - Lambda invocations count
   - Error rate
   - Duration metrics

3. **Test Real Webhook**
   - Push a commit to a test repository
   - Configure GitHub webhook to point to Lambda URL
   - Verify LinkedIn post appears

## Test History

| Date | Environment | Result | Notes |
|------|-------------|--------|-------|
| 2025-11-15 | Production | ✅ PASS | Initial tracer bullet deployment |
| 2025-11-16 | Dev | ✅ PASS | Multi-account setup verified |
| 2025-11-16 | Production | ✅ PASS | CI/CD automation working |

---

**For automated testing in CI/CD, this process runs on every PR and main branch deployment.**
