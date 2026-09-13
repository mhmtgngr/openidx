# OpenIDX edge on Cloudflare (global-scale plan task 1.1, ADR-3).
#
# Cloudflare's anycast network absorbs L3/L4 and volumetric L7 before a packet
# reaches the cell; this module encodes the application-aware rules the design
# puts at the edge (§5.3) and cloaks the origin behind Authenticated Origin
# Pulls. Rules come from ../edge-common/rules.json so the table in the design,
# the Cloudflare rulesets, the AWS WAF and the Azure WAF stay one list.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.40"
    }
  }
}

locals {
  rules = jsondecode(file(var.rules_file))

  # Cloudflare expression for "path starts with any of these prefixes".
  path_expr = { for r in local.rules.rate_rules :
    r.name => join(" or ", [for p in r.paths : format("starts_with(http.request.uri.path, %q)", p)])
  }
  cache_expr = { for r in local.rules.cache_rules :
    r.name => join(" or ", [for p in r.paths : format("starts_with(http.request.uri.path, %q)", p)])
  }
}

data "cloudflare_zone" "this" {
  name = var.zone_domain
}

# ---------------------------------------------------------------- TLS / HTTP
resource "cloudflare_zone_settings_override" "this" {
  zone_id = data.cloudflare_zone.this.id

  settings {
    min_tls_version          = "1.2"
    tls_1_3                  = "on"
    always_use_https         = "on"
    automatic_https_rewrites = "on"
    http3                    = "on"
    brotli                   = "on"
    # Browser integrity + medium security level: cheap wins against the
    # dumbest floods without challenging real users.
    browser_check  = "on"
    security_level = "medium"
  }
}

# ---------------------------------------------------------------- DNS
# Every public name is proxied (orange cloud): the client sees Cloudflare's
# anycast address, never the origin. The origin hostname itself is NOT created
# here — it must not exist in public DNS at all.
resource "cloudflare_record" "edge" {
  for_each = toset(var.edge_hostnames)

  zone_id = data.cloudflare_zone.this.id
  name    = each.value
  type    = "CNAME"
  content = var.origin_hostname
  proxied = true
  ttl     = 1
  comment = "OpenIDX edge (${var.name}); origin cloaked behind Cloudflare"
}

# ---------------------------------------------------------------- origin cloaking
# Authenticated Origin Pulls: Cloudflare presents a client certificate on every
# connection to the origin, and the origin (APISIX / ingress) requires it. With
# the origin's firewall also limited to edge_cidrs, a direct hit on the origin
# fails twice. Enable at zone level; the origin trusts Cloudflare's origin-pull
# CA (https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/).
resource "cloudflare_authenticated_origin_pulls" "this" {
  zone_id = data.cloudflare_zone.this.id
  enabled = true
}

# ---------------------------------------------------------------- managed WAF
resource "cloudflare_ruleset" "waf_managed" {
  zone_id     = data.cloudflare_zone.this.id
  name        = "${var.name}-waf-managed"
  description = "OpenIDX: Cloudflare Managed Ruleset (OWASP-class L7 protection)"
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  rules {
    action = "execute"
    action_parameters {
      # Cloudflare Managed Ruleset
      id = "efb7b8c949ac4650a09736fc376e9aee"
    }
    expression  = "true"
    description = "Execute Cloudflare Managed Ruleset"
    enabled     = true
  }
}

# ---------------------------------------------------------------- custom rules: sizes + challenge
resource "cloudflare_ruleset" "custom" {
  zone_id     = data.cloudflare_zone.this.id
  name        = "${var.name}-custom"
  description = "OpenIDX: request size limits and login challenge"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  # Oversized bodies never reach the cell. SCIM bulk gets its own, larger cap.
  rules {
    action      = "block"
    description = "Body over ${local.rules.limits.scim_bulk_body_bytes} bytes on SCIM"
    expression  = format("starts_with(http.request.uri.path, \"/scim/\") and http.request.body.size gt %d", local.rules.limits.scim_bulk_body_bytes)
    enabled     = true
  }
  rules {
    action      = "block"
    description = "Body over ${local.rules.limits.body_bytes} bytes elsewhere"
    expression  = format("not starts_with(http.request.uri.path, \"/scim/\") and http.request.body.size gt %d", local.rules.limits.body_bytes)
    enabled     = true
  }
  rules {
    action      = "block"
    description = "URL over ${local.rules.limits.url_bytes} bytes"
    expression  = format("len(http.request.uri) gt %d", local.rules.limits.url_bytes)
    enabled     = true
  }

  # Managed challenge on the credential-submitting paths. Off by default: the
  # design (§5.3) wants it driven by an anomaly signal, and the scoring fields
  # (cf.bot_management.score, cf.waf.score) depend on the Cloudflare plan.
  # Turn it on during an attack (runbook step 2) or wire a score once available.
  dynamic "rules" {
    for_each = var.challenge_login_paths ? [1] : []
    content {
      action      = "managed_challenge"
      description = "Managed challenge on credential-submitting paths"
      expression  = local.path_expr["auth-ui"]
      enabled     = true
    }
  }
}

# ---------------------------------------------------------------- rate limits (§5.3)
resource "cloudflare_ruleset" "ratelimit" {
  zone_id     = data.cloudflare_zone.this.id
  name        = "${var.name}-ratelimit"
  description = "OpenIDX: per-source rate limits from edge-common/rules.json"
  kind        = "zone"
  phase       = "http_ratelimit"

  dynamic "rules" {
    for_each = { for r in local.rules.rate_rules : r.name => r }
    content {
      action      = "block"
      description = "${rules.value.name}: ${rules.value.requests_per_minute}/min per source — ${rules.value.description}"
      expression  = local.path_expr[rules.value.name]
      enabled     = true
      ratelimit {
        characteristics     = ["cf.colo.id", "ip.src"]
        period              = 60
        requests_per_period = rules.value.requests_per_minute
        mitigation_timeout  = 60
      }
    }
  }
}

# ---------------------------------------------------------------- cache (§5.3)
resource "cloudflare_ruleset" "cache" {
  zone_id     = data.cloudflare_zone.this.id
  name        = "${var.name}-cache"
  description = "OpenIDX: edge cache for discovery/JWKS and immutable assets"
  kind        = "zone"
  phase       = "http_request_cache_settings"

  dynamic "rules" {
    for_each = { for r in local.rules.cache_rules : r.name => r }
    content {
      action      = "set_cache_settings"
      description = "${rules.value.name}: ${rules.value.ttl_seconds}s — ${rules.value.description}"
      expression  = local.cache_expr[rules.value.name]
      enabled     = true
      action_parameters {
        cache = true
        edge_ttl {
          mode    = "override_origin"
          default = rules.value.ttl_seconds
        }
        browser_ttl {
          mode = "respect_origin"
        }
      }
    }
  }
}

# ---------------------------------------------------------------- published ranges
data "cloudflare_ip_ranges" "this" {}
