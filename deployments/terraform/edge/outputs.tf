# The same four outputs whichever provider is selected, so the cell's Helm
# values and the edge-cidr-sync job read them without knowing K1's answer.

output "edge_cidrs" {
  description = "Provider's published source ranges (empty for Azure: use the AzureFrontDoor.Backend service tag)."
  value = coalescelist(
    try(module.edge_cloudflare[0].edge_cidrs, []),
    try(module.edge_aws[0].edge_cidrs, []),
    try(module.edge_azure[0].edge_cidrs, []),
    [],
  )
}

output "origin_verification" {
  description = "How the origin proves a request came through the edge (mTLS CA / secret header / X-Azure-FDID)."
  sensitive   = true
  value = try(
    module.edge_cloudflare[0].origin_verification,
    module.edge_aws[0].origin_verification,
    module.edge_azure[0].origin_verification,
    null,
  )
}

output "edge_hostname" {
  description = "Where public DNS points."
  value = try(
    module.edge_cloudflare[0].edge_hostname,
    module.edge_aws[0].edge_hostname,
    module.edge_azure[0].edge_hostname,
    null,
  )
}

output "rule_counts" {
  description = "Rules rendered from edge-common/rules.json; must match the design's §5.3 table."
  value = try(
    module.edge_cloudflare[0].rule_counts,
    module.edge_aws[0].rule_counts,
    module.edge_azure[0].rule_counts,
    null,
  )
}
