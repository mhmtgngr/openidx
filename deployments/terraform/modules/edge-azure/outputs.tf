output "edge_cidrs" {
  description = "Azure publishes Front Door's source ranges as the service tag AzureFrontDoor.Backend rather than a static list: allow that tag at the origin NSG, and for OIDX_EDGE_TRUSTED_CIDRS fetch the tag's current prefixes (Service Tags API / weekly JSON) into files/edge-cidr-sync.sh with PROVIDER=static. Empty here on purpose — a hard-coded copy would rot."
  value       = []
}

output "origin_verification" {
  description = "How the origin proves a request came through the edge: require X-Azure-FDID equal to this value at APISIX/ingress (and refuse without it), in addition to the NSG service-tag allow-list."
  value = {
    method = "header"
    header = "X-Azure-FDID"
    value  = azurerm_cdn_frontdoor_profile.this.resource_guid
  }
}

output "edge_hostname" {
  description = "Front Door endpoint hostname. CNAME edge_hostnames to it."
  value       = azurerm_cdn_frontdoor_endpoint.this.host_name
}

output "profile_id" {
  value = azurerm_cdn_frontdoor_profile.this.id
}

output "firewall_policy_id" {
  value = azurerm_cdn_frontdoor_firewall_policy.this.id
}

output "rule_counts" {
  description = "How many rules of each kind were rendered from rules.json — compare against the design's §5.3 table."
  value = {
    rate  = length(local.rules.rate_rules)
    cache = length(local.rules.cache_rules)
  }
}
