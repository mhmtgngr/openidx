variable "name" {
  description = "Prefix for every resource this module creates (e.g. openidx-prod)."
  type        = string
}

variable "zone_domain" {
  description = "The public apex the tenant subdomains hang off (TENANT_BASE_DOMAIN). Informational here: DNS for AWS is managed outside this module (Route 53 alias to edge_hostname)."
  type        = string
}

variable "edge_hostnames" {
  description = "Public hostnames (CloudFront aliases) the edge answers for, e.g. [\"auth.example.com\", \"api.example.com\", \"*.example.com\"]. Requires acm_certificate_arn covering them."
  type        = list(string)
}

variable "origin_hostname" {
  description = "The cloaked origin (the cell's NLB/ingress hostname). Not published in public DNS beyond what CloudFront needs to resolve."
  type        = string
}

variable "acm_certificate_arn" {
  description = "ACM certificate in us-east-1 covering edge_hostnames. Null uses the default *.cloudfront.net certificate (aliases must then be empty)."
  type        = string
  default     = null
}

variable "shield_advanced" {
  description = "Attach Shield Advanced protection to the distribution. Requires an active Shield Advanced subscription on the account."
  type        = bool
  default     = false
}

variable "price_class" {
  description = "CloudFront price class. PriceClass_All = every POP (the DDoS absorption you are paying for)."
  type        = string
  default     = "PriceClass_All"
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
