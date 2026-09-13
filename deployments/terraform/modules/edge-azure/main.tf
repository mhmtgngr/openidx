# OpenIDX edge on Azure Front Door Premium + WAF — global-scale plan task 1.1,
# ADR-3.
#
# Front Door's anycast network absorbs L3/L4 and volumetric L7; the Premium SKU
# carries the managed WAF (Microsoft Default Rule Set + Bot Manager) and custom
# rate-limit rules, which this module renders from ../edge-common/rules.json.
# Origin cloaking is the X-Azure-FDID header (this profile's resource GUID): the
# origin refuses requests that do not carry it, on top of allowing only the
# AzureFrontDoor.Backend service tag at its NSG.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

locals {
  rules = jsondecode(file(var.rules_file))

  # Front Door WAF names must be alphanumeric.
  waf_name = replace("${var.name}edgewaf", "/[^A-Za-z0-9]/", "")

  rate_rules  = { for i, r in local.rules.rate_rules : r.name => merge(r, { priority = 100 + i }) }
  cache_rules = { for i, r in local.rules.cache_rules : r.name => merge(r, { order = i + 1 }) }

  # Front Door cache_duration is d.HH:MM:SS; 31536000s (a year) is 365.00:00:00.
  cache_duration = { for k, r in local.cache_rules :
    k => format("%d.%02d:%02d:%02d", floor(r.ttl_seconds / 86400), floor((r.ttl_seconds % 86400) / 3600), floor((r.ttl_seconds % 3600) / 60), r.ttl_seconds % 60)
  }
}

# ---------------------------------------------------------------- profile + endpoint
resource "azurerm_cdn_frontdoor_profile" "this" {
  name                = "${var.name}-edge"
  resource_group_name = var.resource_group_name
  sku_name            = "Premium_AzureFrontDoor"
  tags                = var.tags
}

resource "azurerm_cdn_frontdoor_endpoint" "this" {
  name                     = "${var.name}-edge"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  tags                     = var.tags
}

# ---------------------------------------------------------------- origin (cloaked)
resource "azurerm_cdn_frontdoor_origin_group" "this" {
  name                     = "${var.name}-origin"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  session_affinity_enabled = false

  load_balancing {
    sample_size                 = 4
    successful_samples_required = 3
  }

  # Probe the edge's own static health at nginx, never a service /health/ready:
  # those are closed at the edge (task 0.4) and ping the data tier.
  health_probe {
    interval_in_seconds = 30
    path                = "/"
    protocol            = "Https"
    request_type        = "HEAD"
  }
}

resource "azurerm_cdn_frontdoor_origin" "this" {
  name                           = "${var.name}-origin"
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.this.id
  enabled                        = true
  host_name                      = var.origin_hostname
  origin_host_header             = var.origin_hostname
  http_port                      = 80
  https_port                     = 443
  priority                       = 1
  weight                         = 1000
  certificate_name_check_enabled = true
}

# ---------------------------------------------------------------- public names
resource "azurerm_cdn_frontdoor_custom_domain" "edge" {
  for_each = toset(var.edge_hostnames)

  name                     = replace(each.value, "/[^A-Za-z0-9]/", "-")
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  host_name                = each.value

  tls {
    certificate_type = "ManagedCertificate"
  }
}

# ---------------------------------------------------------------- cache rules (§5.3)
resource "azurerm_cdn_frontdoor_rule_set" "cache" {
  name                     = replace("${var.name}cache", "/[^A-Za-z0-9]/", "")
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
}

resource "azurerm_cdn_frontdoor_rule" "cache" {
  for_each = local.cache_rules

  name                      = replace(each.key, "/[^A-Za-z0-9]/", "")
  cdn_frontdoor_rule_set_id = azurerm_cdn_frontdoor_rule_set.cache.id
  order                     = each.value.order
  behavior_on_match         = "Continue"

  conditions {
    url_path_condition {
      operator     = "BeginsWith"
      match_values = each.value.paths
    }
  }

  actions {
    route_configuration_override_action {
      cache_behavior                = "OverrideAlways"
      cache_duration                = local.cache_duration[each.key]
      query_string_caching_behavior = "IgnoreQueryString"
      compression_enabled           = true
    }
  }

  depends_on = [azurerm_cdn_frontdoor_origin_group.this, azurerm_cdn_frontdoor_origin.this]
}

# ---------------------------------------------------------------- route
resource "azurerm_cdn_frontdoor_route" "this" {
  name                          = "${var.name}-route"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.this.id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.this.id
  cdn_frontdoor_origin_ids      = [azurerm_cdn_frontdoor_origin.this.id]
  cdn_frontdoor_rule_set_ids    = [azurerm_cdn_frontdoor_rule_set.cache.id]
  enabled                       = true

  supported_protocols    = ["Http", "Https"]
  patterns_to_match      = ["/*"]
  forwarding_protocol    = "HttpsOnly"
  https_redirect_enabled = true
  link_to_default_domain = false

  cdn_frontdoor_custom_domain_ids = [for d in azurerm_cdn_frontdoor_custom_domain.edge : d.id]
}

# ---------------------------------------------------------------- WAF (managed + §5.3)
resource "azurerm_cdn_frontdoor_firewall_policy" "this" {
  name                = local.waf_name
  resource_group_name = var.resource_group_name
  sku_name            = azurerm_cdn_frontdoor_profile.this.sku_name
  enabled             = true
  mode                = "Prevention"
  tags                = var.tags

  managed_rule {
    type    = "Microsoft_DefaultRuleSet"
    version = "2.1"
    action  = "Block"
  }

  managed_rule {
    type    = "Microsoft_BotManagerRuleSet"
    version = "1.0"
    action  = "Block"
  }

  # Size caps (§5.3). Front Door evaluates request body size in custom rules
  # via the RequestBody variable with GreaterThan on length.
  custom_rule {
    name     = "BodySizeScim"
    enabled  = true
    priority = 10
    type     = "MatchRule"
    action   = "Block"
    match_condition {
      match_variable = "RequestUri"
      operator       = "BeginsWith"
      match_values   = ["/scim/"]
    }
    match_condition {
      match_variable = "RequestBody"
      operator       = "GreaterThan"
      match_values   = [tostring(local.rules.limits.scim_bulk_body_bytes)]
    }
  }

  custom_rule {
    name     = "BodySizeDefault"
    enabled  = true
    priority = 11
    type     = "MatchRule"
    action   = "Block"
    match_condition {
      match_variable     = "RequestUri"
      operator           = "BeginsWith"
      negation_condition = true
      match_values       = ["/scim/"]
    }
    match_condition {
      match_variable = "RequestBody"
      operator       = "GreaterThan"
      match_values   = [tostring(local.rules.limits.body_bytes)]
    }
  }

  # Per-source rate limits (§5.3).
  dynamic "custom_rule" {
    for_each = local.rate_rules
    content {
      name                           = replace("Rate${title(custom_rule.key)}", "/[^A-Za-z0-9]/", "")
      enabled                        = true
      priority                       = custom_rule.value.priority
      type                           = "RateLimitRule"
      action                         = "Block"
      rate_limit_duration_in_minutes = 1
      rate_limit_threshold           = custom_rule.value.requests_per_minute
      match_condition {
        match_variable = "RequestUri"
        operator       = "BeginsWith"
        match_values   = custom_rule.value.paths
      }
    }
  }
}

resource "azurerm_cdn_frontdoor_security_policy" "this" {
  name                     = "${var.name}-edge-security"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id

  security_policies {
    firewall {
      cdn_frontdoor_firewall_policy_id = azurerm_cdn_frontdoor_firewall_policy.this.id
      association {
        patterns_to_match = ["/*"]
        dynamic "domain" {
          for_each = azurerm_cdn_frontdoor_custom_domain.edge
          content {
            cdn_frontdoor_domain_id = domain.value.id
          }
        }
      }
    }
  }
}
