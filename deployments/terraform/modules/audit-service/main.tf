# Audit Service Module - Main Configuration
# Deploys the OpenIDX Audit Service with WebSocket origin validation

# ============================================================================
# Kubernetes Deployment via Helm
# ============================================================================

resource "helm_release" "audit_service" {
  count       = var.enabled ? 1 : 0
  name       = "openidx-audit-service"
  repository = "oci://ghcr.io/openidx/helm"
  chart      = "openidx"
  namespace  = "openidx"
  version    = "1.0.0"

  # Pass audit service specific values
  set {
    name  = "auditService.enabled"
    value = var.enabled
  }

  set {
    name  = "auditService.replicaCount"
    value = var.replica_count
  }

  set {
    name  = "auditService.image.repository"
    value = var.image_repository
  }

  set {
    name  = "auditService.image.tag"
    value = var.image_tag
  }

  set {
    name  = "auditService.service.port"
    value = var.service_port
  }

  # WebSocket origin validation configuration
  set {
    name  = "auditService.allowedOrigins"
    value = join(",", var.audit_stream_allowed_origins)
  }

  set {
    name  = "auditService.enableSecurityLogging"
    value = var.audit_stream_enable_security_logging
  }

  # Resource limits
  set {
    name  = "auditService.resources.requests.cpu"
    value = var.cpu_request
  }

  set {
    name  = "auditService.resources.requests.memory"
    value = var.memory_request
  }

  set {
    name  = "auditService.resources.limits.cpu"
    value = var.cpu_limit
  }

  set {
    name  = "auditService.resources.limits.memory"
    value = var.memory_limit
  }

  # Pod Disruption Budget
  set {
    name  = "auditService.pdb.enabled"
    value = var.pod_disruption_budget_enabled
  }

  set {
    name  = "auditService.pdb.maxUnavailable"
    value = var.pod_disruption_budget_max_unavailable
  }

  # Autoscaling
  set {
    name  = "auditService.autoscaling.enabled"
    value = var.autoscaling_enabled
  }

  set {
    name  = "auditService.autoscaling.minReplicas"
    value = var.autoscaling_min_replicas
  }

  set {
    name  = "auditService.autoscaling.maxReplicas"
    value = var.autoscaling_max_replicas
  }

  set {
    name  = "auditService.autoscaling.targetCPUUtilizationPercentage"
    value = var.autoscaling_target_cpu_utilization
  }

  set {
    name  = "auditService.autoscaling.targetMemoryUtilizationPercentage"
    value = var.autoscaling_target_memory_utilization
  }

  # Security settings
  set {
    name  = "serviceTLS.enabled"
    value = var.tls_enabled
  }

  # Environment variables for WebSocket configuration
  set {
    name  = "auditService.env[0].name"
    value = "AUDIT_STREAM_MAX_CLIENTS"
  }

  set {
    name  = "auditService.env[0].value"
    value = var.audit_stream_max_clients
  }

  set {
    name  = "auditService.env[1].name"
    value = "AUDIT_STREAM_MAX_MESSAGE_SIZE"
  }

  set {
    name  = "auditService.env[1].value"
    value = var.audit_stream_max_message_size
  }

  # Production security validation warning
  dynamic "set" {
    for_each = var.environment == "prod" && length(var.audit_stream_allowed_origins) == 0 ? [1] : []
    content {
      name  = "auditService.productionSecurityWarning"
      value = "Audit stream WebSocket allowed origins not configured in production. Same-origin policy will be enforced."
    }
  }

  # Wildcard origin warning for production
  dynamic "set" {
    for_each = var.environment == "prod" && contains(var.audit_stream_allowed_origins, "*") ? [1] : []
    content {
      name  = "auditService.wildcardOriginWarning"
      value = "SECURITY WARNING: Wildcard origin '*' configured for audit stream in production. This is a security risk!"
    }
  }

  depends_on = [
    # Ensure infrastructure dependencies are met
    # These would be passed as module variables in a real deployment
  ]
}

# ============================================================================
# Kubernetes ConfigMap for Audit Service Configuration
# ============================================================================

resource "kubernetes_config_map" "audit_service_config" {
  count = var.enabled ? 1 : 0
  metadata {
    name      = "openidx-audit-service-config"
    namespace = "openidx"
    labels = {
      app.kubernetes.io/name     = "audit-service"
      app.kubernetes.io/instance = "openidx"
      app.kubernetes.io/part-of  = "openidx"
      app.kubernetes.io/managed-by = "terraform"
    }
  }

  data = {
    # Audit stream configuration
    "AUDIT_STREAM_ALLOWED_ORIGINS" = join(",", var.audit_stream_allowed_origins)
    "AUDIT_STREAM_ENABLE_SECURITY_LOGGING" = tostring(var.audit_stream_enable_security_logging)
    "AUDIT_STREAM_MAX_CLIENTS" = tostring(var.audit_stream_max_clients)
    "AUDIT_STREAM_MAX_MESSAGE_SIZE" = tostring(var.audit_stream_max_message_size)
  }
}

# ============================================================================
# Outputs
# ============================================================================

output "service_name" {
  description = "Name of the audit service"
  value       = var.enabled ? "openidx-audit-service" : null
}

output "allowed_origins" {
  description = "Configured allowed WebSocket origins"
  value       = var.audit_stream_allowed_origins
  sensitive   = false
}

output "security_logging_enabled" {
  description = "Whether security logging is enabled"
  value       = var.audit_stream_enable_security_logging
}

output "production_safe" {
  description = "Whether the configuration is safe for production deployment"
  value = {
    safe = !(
      # Production is unsafe if:
      (var.environment == "prod" && contains(var.audit_stream_allowed_origins, "*")) || # Wildcard in production
      (var.environment == "prod" && var.tls_enabled == false) || # TLS disabled in production
      (var.environment == "prod" && var.audit_stream_enable_security_logging == false) # Logging disabled in production
    )
    warnings = concat(
      var.environment == "prod" && contains(var.audit_stream_allowed_origins, "*") ? ["Wildcard origin '*' is not safe for production"] : [],
      var.environment == "prod" && var.tls_enabled == false ? ["TLS is disabled in production"] : [],
      var.environment == "prod" && var.audit_stream_enable_security_logging == false ? ["Security logging is disabled in production"] : [],
      var.environment == "prod" && length(var.audit_stream_allowed_origins) == 0 ? ["No explicit allowed origins configured - same-origin policy enforced"] : [],
    )
  }
}
