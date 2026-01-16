// Package logger provides structured logging utilities for OpenIDX services
package logger

import (
	"time"

	"go.uber.org/zap"
)

// AuditEvent represents an audit log event
type AuditEvent struct {
	EventType  string                 `json:"event_type"`
	Actor      string                 `json:"actor"`       // User ID who performed the action
	ActorEmail string                 `json:"actor_email,omitempty"`
	Action     string                 `json:"action"`      // What action was performed
	Resource   string                 `json:"resource"`    // What resource was affected
	ResourceID string                 `json:"resource_id"` // ID of the affected resource
	Status     string                 `json:"status"`      // success, failure, denied
	Reason     string                 `json:"reason,omitempty"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
}

// AuditLogger provides audit logging functionality
type AuditLogger struct {
	logger *zap.Logger
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(logger *zap.Logger) *AuditLogger {
	return &AuditLogger{
		logger: logger.With(zap.String("log_type", "audit")),
	}
}

// Log logs an audit event
func (a *AuditLogger) Log(event *AuditEvent) {
	fields := []zap.Field{
		zap.String("event_type", event.EventType),
		zap.String("actor", event.Actor),
		zap.String("action", event.Action),
		zap.String("resource", event.Resource),
		zap.String("resource_id", event.ResourceID),
		zap.String("status", event.Status),
		zap.Time("timestamp", event.Timestamp),
	}

	if event.ActorEmail != "" {
		fields = append(fields, zap.String("actor_email", event.ActorEmail))
	}

	if event.Reason != "" {
		fields = append(fields, zap.String("reason", event.Reason))
	}

	if event.IPAddress != "" {
		fields = append(fields, zap.String("ip_address", event.IPAddress))
	}

	if event.UserAgent != "" {
		fields = append(fields, zap.String("user_agent", event.UserAgent))
	}

	if event.Metadata != nil && len(event.Metadata) > 0 {
		fields = append(fields, zap.Any("metadata", event.Metadata))
	}

	// Log at appropriate level based on status
	switch event.Status {
	case "failure", "error":
		a.logger.Error("Audit event", fields...)
	case "denied", "forbidden":
		a.logger.Warn("Audit event", fields...)
	default:
		a.logger.Info("Audit event", fields...)
	}
}

// LogUserCreated logs a user creation event
func (a *AuditLogger) LogUserCreated(actor, actorEmail, userID, username string, metadata map[string]interface{}) {
	a.Log(&AuditEvent{
		EventType:  "user.created",
		Actor:      actor,
		ActorEmail: actorEmail,
		Action:     "create",
		Resource:   "user",
		ResourceID: userID,
		Status:     "success",
		Metadata:   mergeMetadata(metadata, map[string]interface{}{"username": username}),
		Timestamp:  time.Now(),
	})
}

// LogUserUpdated logs a user update event
func (a *AuditLogger) LogUserUpdated(actor, actorEmail, userID string, changes map[string]interface{}) {
	a.Log(&AuditEvent{
		EventType:  "user.updated",
		Actor:      actor,
		ActorEmail: actorEmail,
		Action:     "update",
		Resource:   "user",
		ResourceID: userID,
		Status:     "success",
		Metadata:   changes,
		Timestamp:  time.Now(),
	})
}

// LogUserDeleted logs a user deletion event
func (a *AuditLogger) LogUserDeleted(actor, actorEmail, userID, username string) {
	a.Log(&AuditEvent{
		EventType:  "user.deleted",
		Actor:      actor,
		ActorEmail: actorEmail,
		Action:     "delete",
		Resource:   "user",
		ResourceID: userID,
		Status:     "success",
		Metadata:   map[string]interface{}{"username": username},
		Timestamp:  time.Now(),
	})
}

// LogLoginSuccess logs a successful login
func (a *AuditLogger) LogLoginSuccess(userID, email, ipAddress, userAgent string) {
	a.Log(&AuditEvent{
		EventType:  "auth.login.success",
		Actor:      userID,
		ActorEmail: email,
		Action:     "login",
		Resource:   "session",
		ResourceID: userID,
		Status:     "success",
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		Timestamp:  time.Now(),
	})
}

// LogLoginFailure logs a failed login attempt
func (a *AuditLogger) LogLoginFailure(username, ipAddress, userAgent, reason string) {
	a.Log(&AuditEvent{
		EventType:  "auth.login.failure",
		Actor:      username,
		Action:     "login",
		Resource:   "session",
		ResourceID: username,
		Status:     "failure",
		Reason:     reason,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		Timestamp:  time.Now(),
	})
}

// LogLogout logs a logout event
func (a *AuditLogger) LogLogout(userID, email, sessionID string) {
	a.Log(&AuditEvent{
		EventType:  "auth.logout",
		Actor:      userID,
		ActorEmail: email,
		Action:     "logout",
		Resource:   "session",
		ResourceID: sessionID,
		Status:     "success",
		Timestamp:  time.Now(),
	})
}

// LogAccessDenied logs an access denied event
func (a *AuditLogger) LogAccessDenied(actor, actorEmail, action, resource, resourceID, reason string) {
	a.Log(&AuditEvent{
		EventType:  "access.denied",
		Actor:      actor,
		ActorEmail: actorEmail,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Status:     "denied",
		Reason:     reason,
		Timestamp:  time.Now(),
	})
}

// LogPolicyViolation logs a policy violation
func (a *AuditLogger) LogPolicyViolation(actor, actorEmail, policyName, action, reason string) {
	a.Log(&AuditEvent{
		EventType:  "policy.violation",
		Actor:      actor,
		ActorEmail: actorEmail,
		Action:     action,
		Resource:   "policy",
		ResourceID: policyName,
		Status:     "denied",
		Reason:     reason,
		Timestamp:  time.Now(),
	})
}

// LogGroupCreated logs a group creation event
func (a *AuditLogger) LogGroupCreated(actor, actorEmail, groupID, groupName string) {
	a.Log(&AuditEvent{
		EventType:  "group.created",
		Actor:      actor,
		ActorEmail: actorEmail,
		Action:     "create",
		Resource:   "group",
		ResourceID: groupID,
		Status:     "success",
		Metadata:   map[string]interface{}{"group_name": groupName},
		Timestamp:  time.Now(),
	})
}

// LogGroupMemberAdded logs adding a user to a group
func (a *AuditLogger) LogGroupMemberAdded(actor, actorEmail, groupID, userID string) {
	a.Log(&AuditEvent{
		EventType:  "group.member.added",
		Actor:      actor,
		ActorEmail: actorEmail,
		Action:     "add_member",
		Resource:   "group",
		ResourceID: groupID,
		Status:     "success",
		Metadata:   map[string]interface{}{"added_user_id": userID},
		Timestamp:  time.Now(),
	})
}

// LogGroupMemberRemoved logs removing a user from a group
func (a *AuditLogger) LogGroupMemberRemoved(actor, actorEmail, groupID, userID string) {
	a.Log(&AuditEvent{
		EventType:  "group.member.removed",
		Actor:      actor,
		ActorEmail: actorEmail,
		Action:     "remove_member",
		Resource:   "group",
		ResourceID: groupID,
		Status:     "success",
		Metadata:   map[string]interface{}{"removed_user_id": userID},
		Timestamp:  time.Now(),
	})
}

// LogPermissionGranted logs granting a permission
func (a *AuditLogger) LogPermissionGranted(actor, actorEmail, targetUserID, permission, resource string) {
	a.Log(&AuditEvent{
		EventType:  "permission.granted",
		Actor:      actor,
		ActorEmail: actorEmail,
		Action:     "grant",
		Resource:   resource,
		ResourceID: targetUserID,
		Status:     "success",
		Metadata:   map[string]interface{}{"permission": permission},
		Timestamp:  time.Now(),
	})
}

// LogPermissionRevoked logs revoking a permission
func (a *AuditLogger) LogPermissionRevoked(actor, actorEmail, targetUserID, permission, resource string) {
	a.Log(&AuditEvent{
		EventType:  "permission.revoked",
		Actor:      actor,
		ActorEmail: actorEmail,
		Action:     "revoke",
		Resource:   resource,
		ResourceID: targetUserID,
		Status:     "success",
		Metadata:   map[string]interface{}{"permission": permission},
		Timestamp:  time.Now(),
	})
}

// LogConfigurationChanged logs a configuration change
func (a *AuditLogger) LogConfigurationChanged(actor, actorEmail, configKey string, oldValue, newValue interface{}) {
	a.Log(&AuditEvent{
		EventType:  "config.changed",
		Actor:      actor,
		ActorEmail: actorEmail,
		Action:     "update",
		Resource:   "configuration",
		ResourceID: configKey,
		Status:     "success",
		Metadata: map[string]interface{}{
			"old_value": oldValue,
			"new_value": newValue,
		},
		Timestamp: time.Now(),
	})
}

// LogSecurityEvent logs a security-related event
func (a *AuditLogger) LogSecurityEvent(eventType, actor, action, details string, metadata map[string]interface{}) {
	a.Log(&AuditEvent{
		EventType:  eventType,
		Actor:      actor,
		Action:     action,
		Resource:   "security",
		ResourceID: eventType,
		Status:     "alert",
		Reason:     details,
		Metadata:   metadata,
		Timestamp:  time.Now(),
	})
}

// Helper function to merge metadata maps
func mergeMetadata(maps ...map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, m := range maps {
		if m != nil {
			for k, v := range m {
				result[k] = v
			}
		}
	}
	return result
}
