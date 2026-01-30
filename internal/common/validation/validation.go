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
