# Custom Domain Configuration for Stable Webhook URLs
#
# Production: roxas.ai with /webhooks path
# Development: pr-{NUMBER}.getroxas.com per PR

# Local values for domain configuration
locals {
  # Determine the full domain name based on environment
  full_domain_name = var.environment == "prod" ? "roxas.ai" : (
    var.pr_number != "" ? "pr-${var.pr_number}.getroxas.com" : ""
  )

  # Hosted zone IDs (hardcoded for now, can be data sources later)
  prod_hosted_zone_id = "Z04315832ENRI8EX7SUBL"  # roxas.ai
  dev_hosted_zone_id  = "Z06579361DMB1AK1VDFFZ"  # getroxas.com

  # Select the correct hosted zone based on environment
  hosted_zone_id = var.environment == "prod" ? local.prod_hosted_zone_id : local.dev_hosted_zone_id

  # Determine if custom domain should be created
  create_custom_domain = var.custom_domain_enabled && local.full_domain_name != ""

  # Certificate ARNs (will be outputs from certificate creation)
  certificate_arn = local.create_custom_domain ? aws_acm_certificate.webhook[0].arn : ""
}

# ACM Certificate for Custom Domain
# Must be in us-east-1 for API Gateway
resource "aws_acm_certificate" "webhook" {
  count = local.create_custom_domain ? 1 : 0

  domain_name = var.environment == "prod" ? "roxas.ai" : "*.getroxas.com"

  # For dev wildcard cert, also include the base domain
  subject_alternative_names = var.environment == "prod" ? [] : ["getroxas.com"]

  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.function_name_full}-certificate"
  })
}

# Route53 DNS Validation Records for ACM Certificate
resource "aws_route53_record" "cert_validation" {
  for_each = local.create_custom_domain ? {
    for dvo in aws_acm_certificate.webhook[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = local.hosted_zone_id
}

# Wait for Certificate Validation to Complete
resource "aws_acm_certificate_validation" "webhook" {
  count = local.create_custom_domain ? 1 : 0

  certificate_arn         = aws_acm_certificate.webhook[0].arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# API Gateway Custom Domain Name
resource "aws_apigatewayv2_domain_name" "webhook" {
  count = local.create_custom_domain ? 1 : 0

  domain_name = local.full_domain_name

  domain_name_configuration {
    certificate_arn = aws_acm_certificate_validation.webhook[0].certificate_arn
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

  # For production, map /webhooks path to the API
  # For dev, use root path
  api_mapping_key = var.environment == "prod" ? "webhooks" : null
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
