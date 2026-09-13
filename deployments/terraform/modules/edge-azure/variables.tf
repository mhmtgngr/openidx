variable "name" {
  description = "Prefix for every resource this module creates (e.g. openidx-prod)."
  type        = string
}

variable "resource_group_name" {
  description = "Resource group for the Front Door profile and WAF policy."
  type        = string
}

variable "zone_domain" {
  description = "The public apex the tenant subdomains hang off (TENANT_BASE_DOMAIN). Informational here: DNS is managed outside this module (CNAME edge_hostnames to edge_hostname, plus the _dnsauth TXT for managed certificates)."
  type        = string
}

variable "edge_hostnames" {
  description = "Public hostnames the edge answers for, e.g. [\"auth.example.com\", \"api.example.com\"]. Each becomes a Front Door custom domain with a managed certificate. Front Door does not accept a bare wildcard here; list the names."
  type        = list(string)
}

variable "origin_hostname" {
  description = "The cloaked origin (the cell's load balancer / ingress hostname). Its NSG allows only the AzureFrontDoor.Backend service tag and the listener requires X-Azure-FDID."
  type        = string
}

variable "rules_file" {
  description = "Path to the shared edge rule set. Defaults to ../edge-common/rules.json."
  type        = string
  default     = "../edge-common/rules.json"
}

variable "tags" {
  description = "Tags applied to every taggable resource."
  type        = map(string)
  default     = {}
}
