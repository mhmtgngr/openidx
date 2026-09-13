# OpenIDX edge on AWS: CloudFront + WAFv2 (+ Shield Advanced) — global-scale
# plan task 1.1, ADR-3.
#
# CloudFront's anycast POPs take the L3/L4 and volumetric L7 hit and Shield
# Standard is always on; Shield Advanced (var.shield_advanced) adds the DDoS
# response team, cost protection and L7 auto-mitigation for a subscription.
# WAFv2 in scope CLOUDFRONT must live in us-east-1, so the caller passes an
# aliased provider for that region. Rules come from ../edge-common/rules.json.
#
# Origin cloaking here is a secret header: CloudFront adds X-Edge-Origin-Verify
# to every origin request and the origin (APISIX / ALB listener rule / ingress)
# refuses requests without it, on top of allowing only edge_cidrs.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.0"
      configuration_aliases = [aws.us_east_1]
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

locals {
  rules = jsondecode(file(var.rules_file))

  # WAFv2 rate-based rules take a limit per evaluation window; we use the 60 s
  # window so the number is the design's per-minute figure. The service floor
  # is 10.
  rate_rules = { for r in local.rules.rate_rules : r.name => merge(r, {
    limit = max(10, r.requests_per_minute)
  }) }

  # Managed rule groups: broad L7 hygiene the application should not have to
  # self-enforce. Order = priority.
  managed_groups = ["AWSManagedRulesAmazonIpReputationList", "AWSManagedRulesCommonRuleSet", "AWSManagedRulesKnownBadInputsRuleSet"]

  # CloudFront managed policy ids (public constants).
  cache_policy_disabled        = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad" # CachingDisabled
  origin_request_policy_viewer = "216adef6-5c7f-47e4-b989-5492eafa07d3" # AllViewer
}

resource "random_password" "origin_verify" {
  length  = 48
  special = false
}

# ---------------------------------------------------------------- WAF (us-east-1)
resource "aws_wafv2_web_acl" "this" {
  provider = aws.us_east_1

  name        = "${var.name}-edge"
  description = "OpenIDX edge: managed L7 hygiene, per-source rate limits and size caps from edge-common/rules.json"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # Managed groups first.
  dynamic "rule" {
    for_each = { for i, g in local.managed_groups : g => i }
    content {
      name     = rule.key
      priority = rule.value
      override_action {
        none {}
      }
      statement {
        managed_rule_group_statement {
          name        = rule.key
          vendor_name = "AWS"
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = replace(rule.key, "AWSManagedRules", "")
        sampled_requests_enabled   = true
      }
    }
  }

  # Size caps (§5.3). SCIM bulk is the one path allowed a larger body.
  rule {
    name     = "body-size-scim"
    priority = 10
    action {
      block {}
    }
    statement {
      and_statement {
        statement {
          byte_match_statement {
            positional_constraint = "STARTS_WITH"
            search_string         = "/scim/"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
        statement {
          size_constraint_statement {
            comparison_operator = "GT"
            size                = local.rules.limits.scim_bulk_body_bytes
            field_to_match {
              body {
                oversize_handling = "MATCH"
              }
            }
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BodySizeSCIM"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "body-size-default"
    priority = 11
    action {
      block {}
    }
    statement {
      and_statement {
        statement {
          not_statement {
            statement {
              byte_match_statement {
                positional_constraint = "STARTS_WITH"
                search_string         = "/scim/"
                field_to_match {
                  uri_path {}
                }
                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }
          }
        }
        statement {
          size_constraint_statement {
            comparison_operator = "GT"
            size                = local.rules.limits.body_bytes
            field_to_match {
              body {
                oversize_handling = "MATCH"
              }
            }
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BodySizeDefault"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "url-size"
    priority = 12
    action {
      block {}
    }
    statement {
      size_constraint_statement {
        comparison_operator = "GT"
        size                = local.rules.limits.url_bytes
        field_to_match {
          uri_path {}
        }
        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "URLSize"
      sampled_requests_enabled   = true
    }
  }

  # Per-source rate limits (§5.3), one rule per entry, scoped to its paths.
  dynamic "rule" {
    for_each = local.rate_rules
    content {
      name     = "rate-${rule.key}"
      priority = 20 + index(keys(local.rate_rules), rule.key)
      action {
        block {}
      }
      statement {
        rate_based_statement {
          limit                 = rule.value.limit
          evaluation_window_sec = 60
          aggregate_key_type    = "IP"
          scope_down_statement {
            or_statement {
              dynamic "statement" {
                for_each = length(rule.value.paths) >= 2 ? rule.value.paths : concat(rule.value.paths, rule.value.paths)
                content {
                  byte_match_statement {
                    positional_constraint = "STARTS_WITH"
                    search_string         = statement.value
                    field_to_match {
                      uri_path {}
                    }
                    text_transformation {
                      priority = 0
                      type     = "NONE"
                    }
                  }
                }
              }
            }
          }
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "Rate${replace(title(rule.key), "-", "")}"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-edge"
    sampled_requests_enabled   = true
  }

  tags = var.tags
}

# ---------------------------------------------------------------- cache policies (§5.3)
resource "aws_cloudfront_cache_policy" "cache" {
  for_each = { for r in local.rules.cache_rules : r.name => r }

  name        = "${var.name}-${each.key}"
  comment     = each.value.description
  default_ttl = each.value.ttl_seconds
  max_ttl     = each.value.ttl_seconds
  min_ttl     = 1

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_brotli = true
    enable_accept_encoding_gzip   = true
    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "whitelist"
      headers {
        items = ["Host"]
      }
    }
    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

# ---------------------------------------------------------------- distribution
resource "aws_cloudfront_distribution" "this" {
  enabled         = true
  comment         = "OpenIDX edge (${var.name}); origin cloaked behind CloudFront"
  is_ipv6_enabled = true
  http_version    = "http2and3"
  price_class     = var.price_class
  aliases         = var.edge_hostnames
  web_acl_id      = aws_wafv2_web_acl.this.arn

  origin {
    domain_name = var.origin_hostname
    origin_id   = "origin"

    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "https-only"
      origin_ssl_protocols     = ["TLSv1.2"]
      origin_read_timeout      = 30
      origin_keepalive_timeout = 5
    }

    # The cloaking secret: the origin refuses requests without it.
    custom_header {
      name  = "X-Edge-Origin-Verify"
      value = random_password.origin_verify.result
    }
  }

  # Default: no caching, forward everything (identity traffic is per-user).
  default_cache_behavior {
    target_origin_id         = "origin"
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    compress                 = true
    cache_policy_id          = local.cache_policy_disabled
    origin_request_policy_id = local.origin_request_policy_viewer
  }

  # Cached paths from rules.json.
  dynamic "ordered_cache_behavior" {
    for_each = { for r in local.rules.cache_rules : r.name => r }
    content {
      # One behaviour per first path prefix; CloudFront patterns are globs.
      path_pattern             = "${ordered_cache_behavior.value.paths[0]}*"
      target_origin_id         = "origin"
      viewer_protocol_policy   = "redirect-to-https"
      allowed_methods          = ["GET", "HEAD", "OPTIONS"]
      cached_methods           = ["GET", "HEAD"]
      compress                 = true
      cache_policy_id          = aws_cloudfront_cache_policy.cache[ordered_cache_behavior.key].id
      origin_request_policy_id = local.origin_request_policy_viewer
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn            = var.acm_certificate_arn
    cloudfront_default_certificate = var.acm_certificate_arn == null
    ssl_support_method             = var.acm_certificate_arn == null ? null : "sni-only"
    minimum_protocol_version       = var.acm_certificate_arn == null ? "TLSv1" : "TLSv1.2_2021"
  }

  tags = var.tags
}

# ---------------------------------------------------------------- Shield Advanced
resource "aws_shield_protection" "this" {
  count = var.shield_advanced ? 1 : 0

  name         = "${var.name}-edge"
  resource_arn = aws_cloudfront_distribution.this.arn
  tags         = var.tags
}

# ---------------------------------------------------------------- published ranges
data "aws_ip_ranges" "cloudfront" {
  regions  = ["global"]
  services = ["cloudfront"]
}
