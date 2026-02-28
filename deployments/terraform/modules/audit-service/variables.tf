# Audit Service Module - Variables
# Defines configuration variables for the OpenIDX Audit Service deployment

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "enabled" {
  description = "Enable the audit service"
  type        = bool
  default     = true
}

variable "replica_count" {
  description = "Number of audit service replicas"
  type        = number
  default     = 2

  validation {
    condition     = var.replica_count >= 1 && var.replica_count <= 10
    error_message = "Replica count must be between 1 and 10."
  }
}

variable "image_repository" {
  description = "Docker image repository for the audit service"
  type        = string
  default     = "audit-service"
}

variable "image_tag" {
  description = "Docker image tag for the audit service"
  type        = string
  default     = "latest"
}

variable "service_port" {
  description = "Service port for the audit service"
  type        = number
  default     = 8004
}

# ============================================================================
# WebSocket Origin Validation Configuration
# ============================================================================

variable "audit_stream_allowed_origins" {
  description = "Comma-separated list of allowed WebSocket origins for audit event streaming. Empty list enforces same-origin policy. Examples: 'https://admin.example.com,https://audit.example.com' or 'https://*.example.com'"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for origin in var.audit_stream_allowed_origins :
      contains(["*"], substr(origin, 0, 1)) || startswith(origin, "http://") || startswith(origin, "https://")
    ])
    error_message = "All origins must start with http:// or https://, or be a wildcard '*'."
  }
}

variable "audit_stream_enable_security_logging" {
  description = "Enable security logging for WebSocket connection attempts"
  type        = bool
  default     = true
}

variable "audit_stream_max_clients" {
  description = "Maximum number of concurrent WebSocket clients"
  type        = number
  default     = 100

  validation {
    condition     = var.audit_stream_max_clients > 0 && var.audit_stream_max_clients <= 10000
    error_message = "Max clients must be between 1 and 10000."
  }
}

variable "audit_stream_max_message_size" {
  description = "Maximum WebSocket message size in bytes"
  type        = number
  default     = 65536 # 64KB

  validation {
    condition     = var.audit_stream_max_message_size >= 4096 && var.audit_stream_max_message_size <= 1048576
    error_message = "Max message size must be between 4096 and 1048576 bytes."
  }
}

# ============================================================================
# Resource Configuration
# ============================================================================

variable "cpu_request" {
  description = "CPU request for audit service pods"
  type        = string
  default     = "100m"
}

variable "cpu_limit" {
  description = "CPU limit for audit service pods"
  type        = string
  default     = "500m"
}

variable "memory_request" {
  description = "Memory request for audit service pods"
  type        = string
  default     = "128Mi"
}

variable "memory_limit" {
  description = "Memory limit for audit service pods"
  type        = string
  default     = "512Mi"
}

# ============================================================================
# High Availability Configuration
# ============================================================================

variable "pod_disruption_budget_enabled" {
  description = "Enable Pod Disruption Budget for high availability"
  type        = bool
  default     = true
}

variable "pod_disruption_budget_max_unavailable" {
  description = "Maximum unavailable pods during disruption"
  type        = number
  default     = 1

  validation {
    condition     = var.pod_disruption_budget_max_unavailable >= 0
    error_message = "Max unavailable must be non-negative."
  }
}

variable "autoscaling_enabled" {
  description = "Enable horizontal pod autoscaling"
  type        = bool
  default     = false
}

variable "autoscaling_min_replicas" {
  description = "Minimum number of replicas for autoscaling"
  type        = number
  default     = 2
}

variable "autoscaling_max_replicas" {
  description = "Maximum number of replicas for autoscaling"
  type        = number
  default     = 10
}

variable "autoscaling_target_cpu_utilization" {
  description = "Target CPU utilization percentage for autoscaling"
  type        = number
  default     = 80

  validation {
    condition     = var.autoscaling_target_cpu_utilization > 0 && var.autoscaling_target_cpu_utilization <= 100
    error_message = "Target CPU utilization must be between 1 and 100."
  }
}

variable "autoscaling_target_memory_utilization" {
  description = "Target memory utilization percentage for autoscaling"
  type        = number
  default     = 80

  validation {
    condition     = var.autoscaling_target_memory_utilization > 0 && var.autoscaling_target_memory_utilization <= 100
    error_message = "Target memory utilization must be between 1 and 100."
  }
}

# ============================================================================
# Security Configuration
# ============================================================================

variable "tls_enabled" {
  description = "Enable TLS for the audit service"
  type        = bool
  default     = true
}

variable "tls_cert_secret" {
  description = "Kubernetes secret containing the TLS certificate"
  type        = string
  default     = ""
}

variable "pod_security_context" {
  description = "Pod security context for the audit service"
  type = map(object({
    run_as_user        = optional(number)
    run_as_group       = optional(number)
    fs_group           = optional(number)
    run_as_non_root    = optional(bool)
    read_only_root_filesystem = optional(bool)
    allow_privilege_escalation = optional(bool)
  }))
  default = {}
}
