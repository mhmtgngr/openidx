variable "name" {
  description = "Prefix for every resource this module creates (e.g. openidx-prod)."
  type        = string
}

variable "zone_domain" {
  description = "The Cloudflare zone (apex) the tenant subdomains hang off — the value of TENANT_BASE_DOMAIN."
  type        = string
}

variable "edge_hostnames" {
  description = "Public hostnames the edge answers for, relative to or including the zone (e.g. [\"auth\", \"api\", \"*\"]). Each becomes a proxied CNAME to the origin."
  type        = list(string)
}

variable "origin_hostname" {
  description = "The cloaked origin (the cell's NLB/ingress hostname). Must NOT exist in public DNS; only Cloudflare resolves it."
  type        = string
}

variable "rules_file" {
  description = "Path to the shared edge rule set. Defaults to ../edge-common/rules.json — the design's §5.3 table as data."
  type        = string
  default     = "../edge-common/rules.json"
}

variable "challenge_login_paths" {
  description = "Issue a managed challenge on credential-submitting paths. Off by default; switch on during an attack (runbook) or once a bot score is available on the plan."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Unused on Cloudflare (no resource tags); kept for interface parity with the other edge modules."
  type        = map(string)
  default     = {}
}
