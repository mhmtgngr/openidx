# Audit Service Module - Outputs
# Defines output values for the OpenIDX Audit Service

output "enabled" {
  description = "Whether the audit service is enabled"
  value       = var.enabled
}

output "replica_count" {
  description = "Number of audit service replicas"
  value       = var.replica_count
}

output "service_port" {
  description = "Service port for the audit service"
  value       = var.service_port
}

output "audit_stream_allowed_origins" {
  description = "List of allowed WebSocket origins for audit event streaming"
  value       = var.audit_stream_allowed_origins
}

output "audit_stream_enable_security_logging" {
  description = "Whether security logging is enabled for WebSocket connections"
  value       = var.audit_stream_enable_security_logging
}

output "audit_stream_max_clients" {
  description = "Maximum number of concurrent WebSocket clients"
  value       = var.audit_stream_max_clients
}

output "tls_enabled" {
  description = "Whether TLS is enabled for the audit service"
  value       = var.tls_enabled
}

output "pod_disruption_budget_enabled" {
  description = "Whether Pod Disruption Budget is enabled"
  value       = var.pod_disruption_budget_enabled
}

output "autoscaling_enabled" {
  description = "Whether horizontal pod autoscaling is enabled"
  value       = var.autoscaling_enabled
}

