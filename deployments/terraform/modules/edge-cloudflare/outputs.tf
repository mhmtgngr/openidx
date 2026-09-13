output "edge_cidrs" {
  description = "Cloudflare's published IPv4+IPv6 ranges. Put them in OIDX_EDGE_TRUSTED_CIDRS / EDGE_TRUSTED_CIDRS and the origin security group; files/edge-cidr-sync.sh (PROVIDER=cloudflare) keeps them current."
  value       = concat(data.cloudflare_ip_ranges.this.ipv4_cidr_blocks, data.cloudflare_ip_ranges.this.ipv6_cidr_blocks)
}

output "origin_verification" {
  description = "How the origin proves a request came through the edge."
  value = {
    method = "mtls"
    detail = "Authenticated Origin Pulls enabled at zone level: require Cloudflare's origin-pull CA as a client certificate at APISIX/ingress (ssl.client), in addition to restricting the listener to edge_cidrs."
  }
}

output "edge_hostname" {
  description = "Nothing to CNAME manually: records are created proxied in the zone. Returned for interface parity."
  value       = var.zone_domain
}

output "zone_id" {
  description = "Cloudflare zone id."
  value       = data.cloudflare_zone.this.id
}

output "rule_counts" {
  description = "How many rules of each kind were rendered from rules.json — compare against the design's §5.3 table."
  value = {
    rate  = length(local.rules.rate_rules)
    cache = length(local.rules.cache_rules)
  }
}
