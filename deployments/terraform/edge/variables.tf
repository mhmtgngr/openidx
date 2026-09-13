variable "edge_provider" {
  description = "Which anycast edge fronts this cell: cloudflare | aws | azure (roadmap decision K1)."
  type        = string
  validation {
    condition     = contains(["cloudflare", "aws", "azure"], var.edge_provider)
    error_message = "edge_provider must be one of cloudflare, aws, azure."
  }
}

variable "name" {
  description = "Prefix for edge resources, e.g. openidx-eu-1."
  type        = string
}

variable "zone_domain" {
  description = "Public apex the tenant subdomains hang off (TENANT_BASE_DOMAIN)."
  type        = string
}

variable "edge_hostnames" {
  description = "Public hostnames the edge answers for."
  type        = list(string)
}

variable "origin_hostname" {
  description = "The cloaked origin: the cell's NLB/ingress hostname, never published in public DNS."
  type        = string
}

variable "challenge_login_paths" {
  description = "Cloudflare only: managed challenge on credential-submitting paths (attack mode)."
  type        = bool
  default     = false
}

variable "tags" {
  type    = map(string)
  default = { Project = "OpenIDX", Component = "edge", ManagedBy = "Terraform" }
}

# ---- provider-specific
variable "aws_region" {
  description = "Home region for the AWS provider (the cell's region). CloudFront/WAF are global; WAF's API is us-east-1 via the alias."
  type        = string
  default     = "eu-west-1"
}

variable "aws_acm_certificate_arn" {
  description = "AWS only: ACM certificate in us-east-1 covering edge_hostnames."
  type        = string
  default     = null
}

variable "aws_shield_advanced" {
  description = "AWS only: attach Shield Advanced (requires subscription)."
  type        = bool
  default     = false
}

variable "azure_subscription_id" {
  description = "Azure only: subscription for the Front Door profile."
  type        = string
  default     = null
}

variable "azure_resource_group_name" {
  description = "Azure only: resource group for Front Door + WAF."
  type        = string
  default     = "openidx-edge"
}
