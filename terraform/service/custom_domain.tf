# Custom Domain Configuration for Stable Webhook URLs
#
# Production: roxas.ai/webhook
# Dev: dev.roxasapp.com/webhook
# PR environments: pr-{NUMBER}.roxasapp.com/webhook
#
# ACM certificate is managed by terraform/shared/ and referenced via SSM

# Local values for domain configuration
locals {
  # Determine the full domain name based on environment
  # PR environments get subdomain (pr-123.roxasapp.com)
  # Prod gets root domain (roxas.ai)
  # Dev (non-PR) gets dev subdomain (dev.roxasapp.com)
  full_domain_name = var.environment == "prod" ? "roxas.ai" : (
    local.pr_number != "" ? "pr-${local.pr_number}.roxasapp.com" : "dev.roxasapp.com"
  )

  # Determine if custom domain should be created
  create_custom_domain = var.custom_domain_enabled && local.full_domain_name != ""
}

# API Gateway Custom Domain Name
# Uses shared ACM certificate from terraform/shared/
resource "aws_apigatewayv2_domain_name" "webhook" {
  count = local.create_custom_domain ? 1 : 0

  domain_name = local.full_domain_name

  domain_name_configuration {
    certificate_arn = local.acm_certificate_arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }

  tags = merge(local.common_tags, {
    Name = "${local.function_name_full}-domain"
  })
}

# API Gateway API Mapping
# Maps the custom domain to the API Gateway stage
resource "aws_apigatewayv2_api_mapping" "webhook" {
  count = local.create_custom_domain ? 1 : 0

  api_id      = aws_apigatewayv2_api.webhook.id
  domain_name = aws_apigatewayv2_domain_name.webhook[0].id
  stage       = aws_apigatewayv2_stage.default.id

  # No path mapping - use root path for both prod and dev
  api_mapping_key = null
}

# Route53 A Record for Custom Domain
# Creates an alias record pointing to the API Gateway domain
resource "aws_route53_record" "webhook" {
  count = local.create_custom_domain ? 1 : 0

  zone_id = local.hosted_zone_id
  name    = local.full_domain_name
  type    = "A"

  alias {
    name                   = aws_apigatewayv2_domain_name.webhook[0].domain_name_configuration[0].target_domain_name
    zone_id                = aws_apigatewayv2_domain_name.webhook[0].domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }
}
