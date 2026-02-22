# OpenIDX Access Control Policy
# This policy defines authorization rules for the OpenIDX Zero Trust Access Platform

package openidx

# Default deny - explicit allow is required
default allow = false

# =============================================================================
# Administrator Access
# =============================================================================

allow {
    input.user.roles[_] == "admin"
}

# =============================================================================
# Self-Service Access
# Users can always read and update their own profile
# =============================================================================

allow {
    input.user.id == input.resource.id
    input.resource.type == "user"
    input.action in ["read", "update"]
}

# =============================================================================
# Role-Based Access Control (RBAC)
# =============================================================================

# Security analysts can view audit logs
allow {
    input.user.roles[_] == "security_analyst"
    input.resource.type == "audit_log"
    input.action == "read"
}

# Help desk can manage user sessions
allow {
    input.user.roles[_] == "helpdesk"
    input.resource.type == "session"
    input.action in ["read", "revoke"]
}

# Compliance officers can view compliance reports
allow {
    input.user.roles[_] == "compliance_officer"
    input.resource.type == "compliance_report"
    input.action == "read"
}

# =============================================================================
# Group-Based Access Control
# =============================================================================

# Finance group members can access finance resources
allow {
    input.user.groups[_] == "finance"
    input.resource.attributes["department"] == "finance"
    input.action in ["read", "update"]
}

# HR group members can access HR resources
allow {
    input.user.groups[_] == "human_resources"
    input.resource.attributes["department"] == "hr"
    input.action in ["read", "update"]
}

# =============================================================================
# Resource Owner Access
# =============================================================================

allow {
    input.user.id == input.resource.owner
    input.action in ["read", "update", "delete"]
}

# =============================================================================
# Environment-Based Access
# =============================================================================

# Allow read-only access during maintenance mode for admins
allow {
    input.context.environment == "maintenance"
    input.user.roles[_] == "admin"
    input.action == "read"
}

# Deny all non-admin access during maintenance
deny[msg] {
    input.context.environment == "maintenance"
    not input.user.roles[_] == "admin"
    msg := "System is under maintenance"
}

# =============================================================================
# Time-Based Access Controls
# =============================================================================

# Warn about off-hours access
warnings[msg] {
    input.context.time
    hour := time.clock_ns(input.context.time)[0]
    hour < 6
    hour > 22
    msg := "Access during off-hours is monitored and logged"
}

# =============================================================================
# Privileged Access Management
# =============================================================================

# Require explicit approval for privileged action access
deny[msg] {
    input.resource.attributes["sensitivity"] == "privileged"
    input.action in ["create", "delete", "update"]
    not input.user.attributes["privileged_access_approved"]
    msg := "Privileged access requires explicit approval"
}

# =============================================================================
# Data Sensitivity Levels
# =============================================================================

# Public resources can be read by authenticated users
allow {
    input.resource.attributes["classification"] == "public"
    input.action == "read"
    input.user.authenticated
}

# Internal resources require any role
allow {
    input.resource.attributes["classification"] == "internal"
    input.action == "read"
    count(input.user.roles) > 0
    input.user.authenticated
}

# Confidential resources require specific department membership
allow {
    input.resource.attributes["classification"] == "confidential"
    input.action == "read"
    input.user.groups[_] == input.resource.attributes["department"]
    input.user.authenticated
}

# =============================================================================
# Denial Reasons
# =============================================================================

deny[msg] {
    not allow
    input.action == "delete"
    msg := sprintf("User %s is not authorized to delete resource %s", [input.user.username, input.resource.id])
}

deny[msg] {
    not allow
    not input.user.authenticated
    msg := "Authentication required for this action"
}

deny[msg] {
    not allow
    msg := sprintf("Access denied: insufficient permissions for %s on %s", [input.action, input.resource.type])
}

# =============================================================================
# Just-in-Time (JIT) Access
# =============================================================================

# Check for active JIT access grant
allow {
    input.action in ["create", "update", "delete"]
    input.user.attributes["jit_grant"]
    input.user.attributes["jit_expiry"]
    time.now_ns() < input.user.attributes["jit_expiry"]
}

# =============================================================================
# Multi-Factor Authentication Requirements
# =============================================================================

# Require MFA for sensitive operations
deny[msg] {
    input.action in ["delete", "update"]
    input.resource.attributes["sensitivity"] == "high"
    not input.user.attributes["mfa_verified"]
    msg := "Multi-factor authentication required for this operation"
}

# =============================================================================
# Session Security
# =============================================================================

# Deny access from suspicious locations
deny[msg] {
    input.context.attributes["suspicious_location"] == "true"
    msg := "Access blocked: suspicious location detected"
}

# Warn about new device access
warnings[msg] {
    input.context.attributes["new_device"] == "true"
    msg := "Access from new device is being monitored"
}

# =============================================================================
# Rate Limiting and Abuse Prevention
# =============================================================================

# Deny access if rate limit exceeded
deny[msg] {
    input.context.attributes["rate_limit_exceeded"] == "true"
    msg := "Rate limit exceeded, please try again later"
}

# =============================================================================
# Compliance and Audit
# =============================================================================

# Log all high-risk access attempts for audit
warnings[msg] {
    input.resource.attributes["classification"] == "confidential"
    msg := "This access attempt will be logged for compliance purposes"
}

warnings[msg] {
    input.action == "delete"
    msg := "Delete operations are logged and cannot be undone"
}
