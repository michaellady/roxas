# Stable Webhook URLs Implementation

**Status:** ✅ Implemented (DNS propagation in progress)
**Branch:** `roxas-o1v`
**Issue:** roxas-o1v

## Problem Solved

Previously, API Gateway generated auto-URLs that changed when resources were recreated:
```
https://abc123.execute-api.us-east-1.amazonaws.com/webhook
```

This required manual GitHub webhook updates after each deployment.

## Solution

Implemented custom domains with stable URLs:

### Production (roxas.ai)
```
URL: https://roxas.ai/webhook
Strategy: Apex domain with path-based routing
Account: Prod AWS (598821842404)
```

### Development (roxasapp.com)
```
URLs: https://pr-{NUMBER}.roxasapp.com/webhook
Strategy: Wildcard subdomain per PR
Account: Dev AWS (539402214167)
Examples:
  - PR #1: https://pr-1.roxasapp.com/webhook
  - PR #2: https://pr-2.roxasapp.com/webhook
```

## Architecture

### Production Flow
```
GitHub Webhook
  ↓
https://roxas.ai/webhook
  ↓
Route53 A Record (roxas.ai → API Gateway domain)
  ↓
API Gateway Custom Domain (roxas.ai)
  + ACM Certificate
  + Path mapping: /webhooks → $default stage
  ↓
API Gateway Stage ($default)
  ↓
Lambda: roxas-webhook-handler-prod
```

### Development Flow (per PR)
```
GitHub Webhook (auto-updated by CI/CD)
  ↓
https://pr-123.roxasapp.com/webhook
  ↓
Route53 A Record (pr-123.roxasapp.com → API Gateway domain)
  ↓
API Gateway Custom Domain (pr-123.roxasapp.com)
  + Wildcard ACM Certificate (*.roxasapp.com)
  ↓
API Gateway Stage ($default)
  ↓
Lambda: roxas-webhook-handler-dev-pr-123

When PR closes: Terraform destroys all resources
```

## Implementation Details

### Terraform Resources Added

**custom_domain.tf** (new file)
- `aws_acm_certificate.webhook` - SSL/TLS certificates
  - Prod: Single cert for roxas.ai
  - Dev: Wildcard cert for *.roxasapp.com
- `aws_route53_record.cert_validation` - DNS validation records
- `aws_acm_certificate_validation.webhook` - Wait for validation
- `aws_apigatewayv2_domain_name.webhook` - Custom domain configuration
- `aws_apigatewayv2_api_mapping.webhook` - Map domain to API Gateway
  - Prod: Maps `/webhooks` path to API
  - Dev: Maps root path to API
- `aws_route53_record.webhook` - A record alias to API Gateway

**variables.tf** (modified)
- `custom_domain_enabled` - Enable/disable custom domains
- `domain_name` - Base domain name
- `hosted_zone_id` - Route53 hosted zone ID
- `pr_number` - PR number for subdomain generation

**outputs.tf** (modified)
- `webhook_url` - Updated to use custom domain if enabled
- `custom_domain_name` - Output the custom domain
- `certificate_arn` - Output certificate ARN

**prod.tfvars** (modified)
```hcl
custom_domain_enabled = true
domain_name           = "roxas.ai"
hosted_zone_id        = "Z04315832ENRI8EX7SUBL"
```

**dev.tfvars** (modified)
```hcl
custom_domain_enabled = true
domain_name           = "roxasapp.com"
hosted_zone_id        = "Z06579361DMB1AK1VDFFZ"
```

### GitHub Actions Updates

**pr-deploy-dev.yml** (modified)
- Added `TF_VAR_pr_number: ${{ github.event.pull_request.number }}`
- Added `TF_VAR_custom_domain_enabled: true`
- Terraform creates `pr-{NUMBER}.roxasapp.com` dynamically

**main-deploy-prod.yml** (modified)
- Added `TF_VAR_custom_domain_enabled: true`
- Terraform creates `roxas.ai` custom domain

## DNS Configuration

### roxas.ai (Production)
**Status:** ✅ Nameservers updated at name.com
**Propagation:** In progress (24-48 hours max, usually faster)

Nameservers configured:
```
ns-303.awsdns-37.com
ns-1630.awsdns-11.co.uk
ns-611.awsdns-12.net
ns-1271.awsdns-30.org
```

Hosted Zone ID: `Z04315832ENRI8EX7SUBL`

### roxasapp.com (Development)
**Status:** ✅ Registered and hosted zone created
**Account:** Prod AWS (598821842404) - will use dev hosted zone via nameservers

Hosted Zone ID: `Z06579361DMB1AK1VDFFZ`

## Certificate Details

### Production Certificate
- Domain: `roxas.ai` (single domain)
- Type: DV (Domain Validated) via DNS
- Region: us-east-1 (required for API Gateway)
- Managed by: AWS Certificate Manager (ACM)

### Development Certificate
- Domain: `*.roxasapp.com` (wildcard)
- SAN: `roxasapp.com` (base domain)
- Type: DV (Domain Validated) via DNS
- Region: us-east-1 (required for API Gateway)
- Covers: All PR subdomains (pr-1, pr-2, pr-3, etc.)
- Managed by: AWS Certificate Manager (ACM)

## Testing Plan

### Verify DNS Propagation
```bash
# Check roxas.ai nameservers
dig roxas.ai NS +short

# Expected (after propagation):
# ns-303.awsdns-37.com
# ns-1630.awsdns-11.co.uk
# ns-611.awsdns-12.net
# ns-1271.awsdns-30.org

# Check roxasapp.com nameservers
dig roxasapp.com NS +short
```

### Test Production Deployment
1. Merge this PR to main
2. GitHub Actions deploys to prod
3. Certificate created and validated (~5-10 minutes)
4. Custom domain configured
5. Test webhook: `curl https://roxas.ai/webhook`
6. Update GitHub webhook settings to new URL
7. Test with real commit

### Test Development Deployment
1. Create a test PR
2. GitHub Actions deploys to dev-pr-{NUMBER}
3. Certificate created and validated (one-time, ~5-10 minutes)
4. Custom domain configured for PR subdomain
5. Test webhook: `curl https://pr-{NUMBER}.roxasapp.com/webhook`
6. PR deployment comment shows stable URL
7. Close PR → resources cleaned up automatically

## Benefits

✅ **Stable URLs** - Never change across deployments
✅ **Professional** - Branded domains (roxas.ai, roxasapp.com)
✅ **Isolated Testing** - Each PR has unique URL
✅ **Parallel PRs** - Multiple PRs can test simultaneously
✅ **Auto Cleanup** - PR close removes subdomain
✅ **Cost Effective** - Single wildcard cert for all dev PRs
✅ **HTTPS** - AWS-managed certificates, auto-renewal
✅ **Low Latency** - Regional API Gateway endpoints

## Cost Impact

### Added Costs
- **Route53 Hosted Zones**: $0.50/month per zone
  - roxas.ai: $0.50/month
  - roxasapp.com: $0.50/month
  - **Total**: $1.00/month
- **Route53 DNS Queries**: $0.40 per million queries
  - Webhook traffic is low volume
  - **Estimated**: <$0.10/month
- **ACM Certificates**: FREE (AWS-managed)
- **API Gateway Custom Domains**: FREE
- **Domain Registration**:
  - roxas.ai: ~$95/year (already purchased)
  - roxasapp.com: ~$13/year (already purchased)

### Removed Costs
None (API Gateway still used with custom domain)

**Total Monthly Increase**: ~$1.10/month
**Total Annual Cost**: ~$13.20/year + domain renewals

## Next Steps

### Immediate
1. ✅ Nameservers updated at name.com (done)
2. ⏳ Wait for DNS propagation (in progress)
3. ⏳ Wait for PR review and approval
4. ⏳ Merge to main

### After Merge
1. Monitor prod deployment in GitHub Actions
2. Verify certificate creation and validation
3. Test webhook endpoint: `https://roxas.ai/webhook`
4. Update GitHub webhook settings in repository
5. Test with real commit
6. Monitor CloudWatch logs for any issues

### Development Testing
1. Create a test PR
2. Verify PR subdomain created: `pr-{NUMBER}.roxasapp.com`
3. Test webhook endpoint
4. Close PR and verify cleanup

## Troubleshooting

### DNS Not Propagating
- Wait up to 48 hours (usually 1-4 hours)
- Check with: `dig roxas.ai NS +short`
- Clear DNS cache: `sudo dscacheutil -flushcache` (macOS)

### Certificate Validation Fails
- Check Route53 validation records exist
- Verify hosted zone ID is correct
- ACM validation takes 5-30 minutes typically
- Check Terraform logs for errors

### Custom Domain Not Working
- Verify certificate is validated (ACM console)
- Check API Gateway custom domain configuration
- Verify Route53 A record points to correct API Gateway domain
- Check CloudWatch logs for Lambda errors

### Webhook Returns 403/404
- Verify API Gateway route is configured: `POST /webhook`
- Check API mapping configuration
- For prod: Verify path mapping `/webhooks` is correct
- Test API Gateway URL directly first

## Documentation

- Epic: roxas-o1v
- Tasks completed:
  - roxas-kjy: Purchase domains
  - roxas-67v: Configure roxas.ai for production
  - roxas-5dm: Wildcard certificate for dev
  - roxas-na8: Dynamic PR subdomain configuration
  - roxas-edt: Production apex domain implementation

## Related Files

- `terraform/custom_domain.tf` - Custom domain resources
- `terraform/variables.tf` - Domain configuration variables
- `terraform/outputs.tf` - Webhook URL outputs
- `terraform/prod.tfvars` - Production configuration
- `terraform/dev.tfvars` - Development configuration
- `.github/workflows/pr-deploy-dev.yml` - Dev deployment workflow
- `.github/workflows/main-deploy-prod.yml` - Prod deployment workflow

---

**Implementation Date:** 2025-11-17
**Author:** Claude Code
**Branch:** roxas-o1v
**Status:** Ready for Review
