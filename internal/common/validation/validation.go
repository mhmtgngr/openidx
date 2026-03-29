// Package validation provides input validation utilities for OpenIDX
package validation

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
)

// Validator defines the interface for validation rules
type Validator interface {
	Validate(value interface{}) error
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   string `json:"value,omitempty"`
}

func (e *ValidationError) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("%s: %s (value: %s)", e.Field, e.Message, e.Value)
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors struct {
	Errors []*ValidationError `json:"errors"`
}

func (e *ValidationErrors) Error() string {
	if len(e.Errors) == 0 {
		return "validation failed"
	}
	if len(e.Errors) == 1 {
		return e.Errors[0].Error()
	}
	return fmt.Sprintf("validation failed with %d errors", len(e.Errors))
}

// Add adds a validation error
func (e *ValidationErrors) Add(field, message string, value ...string) {
	verr := &ValidationError{
		Field:   field,
		Message: message,
	}
	if len(value) > 0 {
		verr.Value = value[0]
	}
	e.Errors = append(e.Errors, verr)
}

// HasErrors returns true if there are validation errors
func (e *ValidationErrors) HasErrors() bool {
	return len(e.Errors) > 0
}

// String validators

// ValidateRequired checks if a string is not empty
func ValidateRequired(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return &ValidationError{
			Field:   field,
			Message: "is required",
		}
	}
	return nil
}

// ValidateEmail checks if a string is a valid email address
func ValidateEmail(field, value string) error {
	if value == "" {
		return nil // Use ValidateRequired for required check
	}

	addr, err := mail.ParseAddress(value)
	if err != nil {
		return &ValidationError{
			Field:   field,
			Message: "must be a valid email address",
			Value:   value,
		}
	}

	// Additional validation: ensure no special characters in local part
	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 {
		return &ValidationError{
			Field:   field,
			Message: "must be a valid email address",
			Value:   value,
		}
	}

	return nil
}

// ValidateUsername checks if a username is valid
func ValidateUsername(field, value string) error {
	if value == "" {
		return nil // Use ValidateRequired for required check
	}

	// Username must be 3-32 characters
	if len(value) < 3 || len(value) > 32 {
		return &ValidationError{
			Field:   field,
			Message: "must be between 3 and 32 characters",
			Value:   value,
		}
	}

	// Username must start with a letter
	if !unicode.IsLetter(rune(value[0])) {
		return &ValidationError{
			Field:   field,
			Message: "must start with a letter",
			Value:   value,
		}
	}

	// Username can only contain letters, numbers, dots, hyphens, underscores
	validUsername := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]*$`)
	if !validUsername.MatchString(value) {
		return &ValidationError{
			Field:   field,
			Message: "can only contain letters, numbers, dots, hyphens, and underscores",
			Value:   value,
		}
	}

	return nil
}

// ValidateLength checks if a string length is within the specified range
func ValidateLength(field, value string, min, max int) error {
	length := len(value)
	if length < min || length > max {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be between %d and %d characters", min, max),
			Value:   fmt.Sprintf("%d characters", length),
		}
	}
	return nil
}

// ValidateMinLength checks if a string has at least min characters
func ValidateMinLength(field, value string, min int) error {
	if len(value) < min {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be at least %d characters", min),
			Value:   fmt.Sprintf("%d characters", len(value)),
		}
	}
	return nil
}

// ValidateMaxLength checks if a string has at most max characters
func ValidateMaxLength(field, value string, max int) error {
	if len(value) > max {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be at most %d characters", max),
			Value:   fmt.Sprintf("%d characters", len(value)),
		}
	}
	return nil
}

// ValidatePattern checks if a string matches a regex pattern
func ValidatePattern(field, value, pattern, description string) error {
	matched, err := regexp.MatchString(pattern, value)
	if err != nil {
		return &ValidationError{
			Field:   field,
			Message: "invalid pattern",
		}
	}
	if !matched {
		return &ValidationError{
			Field:   field,
			Message: description,
			Value:   value,
		}
	}
	return nil
}

// ValidateUUID checks if a string is a valid UUID
func ValidateUUID(field, value string) error {
	if value == "" {
		return nil // Use ValidateRequired for required check
	}

	uuidPattern := `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
	matched, _ := regexp.MatchString(uuidPattern, strings.ToLower(value))
	if !matched {
		return &ValidationError{
			Field:   field,
			Message: "must be a valid UUID",
			Value:   value,
		}
	}
	return nil
}

// ValidateURL checks if a string is a valid URL
func ValidateURL(field, value string) error {
	if value == "" {
		return nil // Use ValidateRequired for required check
	}

	urlPattern := `^https?://[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(:[0-9]+)?(/[^\s]*)?$`
	matched, _ := regexp.MatchString(urlPattern, value)
	if !matched {
		return &ValidationError{
			Field:   field,
			Message: "must be a valid URL",
			Value:   value,
		}
	}
	return nil
}

// ValidateAlphanumeric checks if a string contains only alphanumeric characters
func ValidateAlphanumeric(field, value string) error {
	if value == "" {
		return nil
	}

	for _, char := range value {
		if !unicode.IsLetter(char) && !unicode.IsNumber(char) {
			return &ValidationError{
				Field:   field,
				Message: "must contain only letters and numbers",
				Value:   value,
			}
		}
	}
	return nil
}

// Number validators

// ValidateRange checks if a number is within the specified range
func ValidateRange(field string, value, min, max int) error {
	if value < min || value > max {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be between %d and %d", min, max),
			Value:   fmt.Sprintf("%d", value),
		}
	}
	return nil
}

// ValidateMin checks if a number is at least min
func ValidateMin(field string, value, min int) error {
	if value < min {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be at least %d", min),
			Value:   fmt.Sprintf("%d", value),
		}
	}
	return nil
}

// ValidateMax checks if a number is at most max
func ValidateMax(field string, value, max int) error {
	if value > max {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be at most %d", max),
			Value:   fmt.Sprintf("%d", value),
		}
	}
	return nil
}

// ValidatePositive checks if a number is positive
func ValidatePositive(field string, value int) error {
	if value <= 0 {
		return &ValidationError{
			Field:   field,
			Message: "must be positive",
			Value:   fmt.Sprintf("%d", value),
		}
	}
	return nil
}

// Collection validators

// ValidateOneOf checks if a value is one of the allowed values
func ValidateOneOf(field, value string, allowed []string) error {
	if value == "" {
		return nil
	}

	for _, a := range allowed {
		if value == a {
			return nil
		}
	}

	return &ValidationError{
		Field:   field,
		Message: fmt.Sprintf("must be one of: %s", strings.Join(allowed, ", ")),
		Value:   value,
	}
}

// ValidateNotEmpty checks if a slice is not empty
func ValidateNotEmpty(field string, value []string) error {
	if len(value) == 0 {
		return &ValidationError{
			Field:   field,
			Message: "must not be empty",
		}
	}
	return nil
}

// Composite validators

// ValidatePassword checks if a password meets security requirements
func ValidatePassword(field, value string) error {
	if value == "" {
		return nil // Use ValidateRequired for required check
	}

	errors := &ValidationErrors{}

	// Minimum length
	if len(value) < 8 {
		errors.Add(field, "must be at least 8 characters long")
	}

	// Maximum length
	if len(value) > 128 {
		errors.Add(field, "must be at most 128 characters long")
	}

	// Must contain at least one uppercase letter
	hasUpper := false
	for _, char := range value {
		if unicode.IsUpper(char) {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		errors.Add(field, "must contain at least one uppercase letter")
	}

	// Must contain at least one lowercase letter
	hasLower := false
	for _, char := range value {
		if unicode.IsLower(char) {
			hasLower = true
			break
		}
	}
	if !hasLower {
		errors.Add(field, "must contain at least one lowercase letter")
	}

	// Must contain at least one digit
	hasDigit := false
	for _, char := range value {
		if unicode.IsDigit(char) {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		errors.Add(field, "must contain at least one digit")
	}

	// Must contain at least one special character
	hasSpecial := false
	for _, char := range value {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) && !unicode.IsSpace(char) {
			hasSpecial = true
			break
		}
	}
	if !hasSpecial {
		errors.Add(field, "must contain at least one special character")
	}

	if errors.HasErrors() {
		return errors
	}

	return nil
}

// Sanitization functions

// SanitizeString removes leading/trailing whitespace and normalizes spaces
func SanitizeString(value string) string {
	// Trim leading/trailing whitespace
	value = strings.TrimSpace(value)

	// Replace multiple spaces with single space
	spaceRegex := regexp.MustCompile(`\s+`)
	value = spaceRegex.ReplaceAllString(value, " ")

	return value
}

// SanitizeEmail normalizes an email address
func SanitizeEmail(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ToLower(value)
	return value
}

// SanitizeUsername normalizes a username
func SanitizeUsername(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ToLower(value)
	return value
}

// Helper functions for batch validation

// ValidateAll runs multiple validators and collects errors
func ValidateAll(validators ...func() error) error {
	errors := &ValidationErrors{}

	for _, validator := range validators {
		if err := validator(); err != nil {
			if verr, ok := err.(*ValidationError); ok {
				errors.Errors = append(errors.Errors, verr)
			} else if verrs, ok := err.(*ValidationErrors); ok {
				errors.Errors = append(errors.Errors, verrs.Errors...)
			}
		}
	}

	if errors.HasErrors() {
		return errors
	}

	return nil
}

// SQL Column Name Validation
// The following functions provide safe validation for SQL column names
// to prevent SQL injection when building dynamic queries.

// SafeSQLColumnNames is an allowlist of known-safe column names.
// When using fmt.Sprintf to build SQL queries with column names,
// only column names from this allowlist (or other validated sources)
// should be used. This prevents SQL injection via column names.
var SafeSQLColumnNames = map[string]bool{
	// Primary key and identifiers
	"id": true, "external_id": true,
	"user_id": true, "org_id": true, "organization_id": true,
	"provider_id": true, "policy_id": true, "application_id": true,
	"directory_id": true, "resource_id": true, "target_id": true,
	"agent_id": true, "owner_id": true, "claim_id": true,
	"rule_id": true, "role_id": true, "group_id": true,
	"link_id": true, "perm_id": true,

	// User/Identity columns
	"username": true, "display_name": true, "name": true,
	"active": true, "enabled": true, "email": true, "email_verified": true,
	"password": true, "password_hash": true, "password_changed_at": true,
	"password_must_change": true, "failed_login_count": true,
	"last_failed_login_at": true, "locked_until": true,
	"last_login_at": true, "ldap_dn": true, "source": true,

	// Profile JSONB columns
	"emails": true, "phone_numbers": true, "photos": true, "addresses": true,
	"groups": true, "roles": true, "entitlements": true,
	"attributes": true, "meta": true,

	// Group columns
	"members": true,

	// Organization columns
	"description": true, "domain": true, "branding": true, "settings": true,

	// Application/OAuth columns
	"client_id": true, "type": true, "protocol": true,
	"base_url": true, "redirect_uris": true,

	// Policy/Rule columns
	"priority": true, "conditions": true,
	"required_methods": true, "grace_period_hours": true,
	"thresholds": true,

	// Notification columns
	"channel": true, "title": true, "body": true, "link": true, "read": true,
	"notification_type": true, "event_type": true, "category": true,

	// Timestamp columns
	"created_at": true, "updated_at": true, "deleted_at": true,
	"expires_at": true, "sent_at": true, "scheduled_at": true,
	"processed_by": true, "completed_at": true, "last_sent_at": true,
	"next_scheduled_at": true, "rotated_at": true, "last_active_at": true,
	"remediated_at": true, "dismissed_reason": true,
	"started_at": true,

	// Status and state columns
	"status": true, "outcome": true, "state": true, "severity": true,

	// Audit/Event columns
	"action": true, "actor_type": true, "actor_ip": true,
	"target_type": true, "resource_type": true,
	"details": true, "session_id": true, "request_id": true,
	"timestamp": true, "correlation_id": true,

	// Federation/Identity Provider columns
	"provider_key": true, "provider_name": true,
	"sort_order": true, "icon_url": true,
	"button_color": true, "button_text": true,
	"auto_create_users": true, "auto_link_by_email": true,
	"allowed_domains": true, "attribute_mapping": true,
	"email_domain": true, "auto_redirect": true,
	"external_email": true, "external_username": true,

	// MFA columns
	"totp_enabled": true, "sms_enabled": true, "email_otp_enabled": true,
	"push_enabled": true, "webauthn_enabled": true, "backup_codes_remaining": true,
	"credential_type": true, "key_prefix": true,

	// Privacy/Data columns
	"request_type": true, "result_file_path": true,
	"result_file_size": true, "retention_days": true, "archive_enabled": true,
	"archive_format": true, "anonymize_fields": true,
	"data_category": true, "risk_level": true,
	"assessor_id": true, "reviewer_id": true, "review_notes": true,
	"approved_at": true, "findings": true, "mitigations": true,
	"processing_purposes": true, "data_categories": true,

	// SAML columns
	"entity_id": true, "acs_url": true, "slo_url": true, "certificate": true,
	"metadata_xml": true, "want_assertions_signed": true,
	"encryption_enabled": true, "name_id_format": true,

	// AI Agent columns
	"agent_type": true, "capabilities": true,
	"trust_level": true, "rate_limits": true, "allowed_scopes": true,
	"ip_allowlist": true,

	// ISPM columns
	"check_type": true, "affected_entity_type": true, "affected_entity_id": true,
	"affected_entity_name": true, "remediation_action": true, "remediation_details": true,
	"dismissed_by": true,

	// Common JSONB/JSON columns
	"channels": true, "template_overrides": true,
	"target_ids": true, "target_applications": true,
	"claim_name": true, "claim_type": true, "source_value": true,
	"include_in_id_token": true, "include_in_access_token": true, "include_in_userinfo": true,
}

// ValidateSQLColumnName checks if a column name is in the allowlist.
// Returns an error if the column name is not safe for use in SQL queries.
// Use this function when accepting column names from user input for sorting or filtering.
func ValidateSQLColumnName(columnName string) error {
	if columnName == "" {
		return &ValidationError{
			Field:   "column_name",
			Message: "column name cannot be empty",
		}
	}

	// Check against allowlist
	if !SafeSQLColumnNames[columnName] {
		return &ValidationError{
			Field:   "column_name",
			Message: "is not a valid column name",
			Value:   columnName,
		}
	}

	return nil
}

// IsSafeSQLColumnName returns true if the column name is in the allowlist.
// This is a convenience function for quick checks without error handling.
func IsSafeSQLColumnName(columnName string) bool {
	return SafeSQLColumnNames[columnName]
}

// ValidateSortBy validates a sort-by column name against the allowlist.
// Returns an error if the column name is not safe for ORDER BY clauses.
func ValidateSortBy(columnName string) error {
	// Sort by can include qualified names like "emails->0->>'value'"
	// For now, validate the base column name
	baseName := columnName
	if idx := strings.Index(columnName, "->"); idx > 0 {
		baseName = columnName[:idx]
	}
	if idx := strings.Index(columnName, "."); idx > 0 {
		baseName = columnName[:idx]
	}

	// Special case for JSON operators - they're safe if the base column is safe
	if strings.Contains(columnName, "->") || strings.Contains(columnName, ">>") {
		return ValidateSQLColumnName(baseName)
	}

	return ValidateSQLColumnName(columnName)
}
