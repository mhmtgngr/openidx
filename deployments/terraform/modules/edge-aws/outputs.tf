output "edge_cidrs" {
  description = "CloudFront's published IPv4+IPv6 ranges. Put them in OIDX_EDGE_TRUSTED_CIDRS / EDGE_TRUSTED_CIDRS and the origin security group; files/edge-cidr-sync.sh (PROVIDER=aws-cloudfront) keeps them current."
  value       = concat(data.aws_ip_ranges.cloudfront.cidr_blocks, data.aws_ip_ranges.cloudfront.ipv6_cidr_blocks)
}

output "origin_verification" {
  description = "How the origin proves a request came through the edge: require this header value at APISIX/ingress (and refuse without it), in addition to restricting the listener to edge_cidrs."
  sensitive   = true
  value = {
    method = "header"
    header = "X-Edge-Origin-Verify"
    value  = random_password.origin_verify.result
  }
}

output "edge_hostname" {
  description = "CloudFront distribution domain. Point edge_hostnames at it (Route 53 alias A/AAAA)."
  value       = aws_cloudfront_distribution.this.domain_name
}

output "distribution_id" {
  value = aws_cloudfront_distribution.this.id
}

output "web_acl_arn" {
  value = aws_wafv2_web_acl.this.arn
}

output "rule_counts" {
  description = "How many rules of each kind were rendered from rules.json — compare against the design's §5.3 table."
  value = {
    rate  = length(local.rules.rate_rules)
    cache = length(local.rules.cache_rules)
  }
}
