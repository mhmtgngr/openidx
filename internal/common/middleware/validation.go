// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Validator is a function that validates a value and returns an error if invalid
type Validator func(string) error

// ValidationRule defines a validation rule for query or path parameters
type ValidationRule struct {
	Required bool
	Validators []Validator
}

// JSONSchema defines a JSON schema for request body validation
type JSONSchema struct {
	Type       string                 // "object", "array", "string", "number", "integer", "boolean", "null"
	Required   []string               // Required field names
	Properties map[string]*JSONSchema // Property schemas for objects
	Items      *JSONSchema            // Item schema for arrays
	MinLength  *int                   // Minimum length for strings/arrays
	MaxLength  *int                   // Maximum length for strings/arrays
	Minimum    *float64               // Minimum value for numbers
	Maximum    *float64               // Maximum value for numbers
	Pattern    string                 // Regex pattern for strings
	Enum       []interface{}          // Enum of allowed values
	Format     string                 // Format: "email", "uuid", "uri", "date-time", etc.
	Default    interface{}            // Default value
}

// ValidationError represents a single validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   interface{} `json:"value,omitempty"`
}

// ValidationErrors represents multiple validation errors
type ValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

// Error returns the error message
func (ve *ValidationErrors) Error() string {
	if len(ve.Errors) == 0 {
		return "validation failed"
	}
	return fmt.Sprintf("validation failed: %s", ve.Errors[0].Message)
}

// MaxBodySize returns a middleware that limits the request body size
// For large uploads, use a larger value. Default is 1MB if not specified.
func MaxBodySize(max int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check Content-Length header first if present
		if contentLength := c.Request.Header.Get("Content-Length"); contentLength != "" {
			if length, err := strconv.ParseInt(contentLength, 10, 64); err == nil {
				if length > max {
					c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
						"error": fmt.Sprintf("request body too large: maximum %d bytes", max),
					})
					return
				}
			}
		}

		// Limit the request body size by wrapping with MaxBytesReader
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, max)

		// Attempt to read the body to trigger MaxBytesReader enforcement
		// This ensures oversized bodies are rejected even if the handler doesn't read the body
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": fmt.Sprintf("request body too large: maximum %d bytes", max),
			})
			return
		}
		// Restore the body so downstream handlers can still read it
		c.Request.Body = io.NopCloser(bytes.NewReader(body))

		c.Next()
	}
}

// ValidateContentType returns a middleware that validates the Content-Type header
// against a whitelist of allowed content types
func ValidateContentType(allowed []string) gin.HandlerFunc {
	allowedSet := make(map[string]bool)
	for _, ct := range allowed {
		allowedSet[strings.ToLower(ct)] = true
	}

	return func(c *gin.Context) {
		// Skip validation for methods that typically don't have a body
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodDelete {
			c.Next()
			return
		}

		contentType := c.Request.Header.Get("Content-Type")
		if contentType == "" {
			// No content type header - could be empty body
			c.Next()
			return
		}

		// Parse content type (remove charset and other parameters)
		if idx := strings.Index(contentType, ";"); idx != -1 {
			contentType = contentType[:idx]
		}
		contentType = strings.TrimSpace(strings.ToLower(contentType))

		if !allowedSet[contentType] {
			c.AbortWithStatusJSON(http.StatusUnsupportedMediaType, gin.H{
				"error": fmt.Sprintf("unsupported content type: %s. Allowed: %v", contentType, allowed),
			})
			return
		}

		c.Next()
	}
}

// RequireHeaders returns a middleware that validates required headers are present
func RequireHeaders(headers []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var missing []string

		for _, header := range headers {
			if c.GetHeader(header) == "" {
				missing = append(missing, header)
			}
		}

		if len(missing) > 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("missing required headers: %v", missing),
			})
			return
		}

		c.Next()
	}
}

// ValidateJSONSchema returns a middleware that validates request body against a JSON schema
func ValidateJSONSchema(schema *JSONSchema) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only validate POST, PUT, PATCH requests
		if c.Request.Method != http.MethodPost && c.Request.Method != http.MethodPut && c.Request.Method != http.MethodPatch {
			c.Next()
			return
		}

		// Read and parse body
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "failed to read request body",
			})
			return
		}

		// Empty body is valid if schema allows it
		if len(body) == 0 {
			c.Next()
			return
		}

		var data interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "invalid JSON in request body",
			})
			return
		}

		// Validate against schema
		if errs := validateJSON(data, schema, ""); len(errs) > 0 {
			c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
				"error":  "validation failed",
				"errors": errs,
			})
			return
		}

		// Store parsed data in context for handler use
		switch v := data.(type) {
		case map[string]interface{}:
			c.Set("validated_body", v)
		case []interface{}:
			c.Set("validated_body", v)
		default:
			c.Set("validated_body", data)
		}

		c.Next()
	}
}

// ValidateQueryParams returns a middleware that validates query parameters
func ValidateQueryParams(validators map[string]ValidationRule) gin.HandlerFunc {
	return func(c *gin.Context) {
		var errs []ValidationError

		for param, rule := range validators {
			values := c.QueryArray(param)

			// Check required
			if rule.Required && len(values) == 0 {
				errs = append(errs, ValidationError{
					Field:   param,
					Message: "required query parameter missing",
				})
				continue
			}

			// Validate each value
			for _, value := range values {
				for _, validator := range rule.Validators {
					if err := validator(value); err != nil {
						errs = append(errs, ValidationError{
							Field:   param,
							Message: err.Error(),
							Value:   value,
						})
						break // Stop at first error for this value
					}
				}
			}
		}

		if len(errs) > 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":  "query parameter validation failed",
				"errors": errs,
			})
			return
		}

		c.Next()
	}
}

// ValidatePathParams returns a middleware that validates path parameters
func ValidatePathParams(validators map[string]ValidationRule) gin.HandlerFunc {
	return func(c *gin.Context) {
		var errs []ValidationError

		for param, rule := range validators {
			value := c.Param(param)

			// Check required (path params are inherently required, but we check anyway)
			if rule.Required && value == "" {
				errs = append(errs, ValidationError{
					Field:   param,
					Message: "required path parameter missing",
				})
				continue
			}

			// Validate value
			for _, validator := range rule.Validators {
				if err := validator(value); err != nil {
					errs = append(errs, ValidationError{
						Field:   param,
						Message: err.Error(),
						Value:   value,
					})
					break
				}
			}
		}

		if len(errs) > 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":  "path parameter validation failed",
				"errors": errs,
			})
			return
		}

		c.Next()
	}
}

// validateJSON recursively validates data against a JSON schema
func validateJSON(data interface{}, schema *JSONSchema, path string) []ValidationError {
	var errs []ValidationError

	// Handle null values: null is only valid for "null" type schemas
	if data == nil {
		if schema.Type != "" && schema.Type != "null" {
			errs = append(errs, ValidationError{
				Field:   path,
				Message: fmt.Sprintf("expected type %s, got null", schema.Type),
				Value:   data,
			})
		}
		return errs
	}

	// Type validation
	if err := validateType(data, schema.Type, path); err != nil {
		errs = append(errs, *err)
		return errs
	}

	switch schema.Type {
	case "object":
		errs = append(errs, validateObject(data, schema, path)...)
	case "array":
		errs = append(errs, validateArray(data, schema, path)...)
	case "string":
		errs = append(errs, validateString(data, schema, path)...)
	case "number", "integer":
		errs = append(errs, validateNumber(data, schema, path)...)
	case "boolean":
		// Boolean type is already validated by validateType
	}

	return errs
}

// validateType checks if the data matches the expected type
func validateType(data interface{}, expectedType, path string) *ValidationError {
	if data == nil {
		return nil // Null handling is done in validateJSON
	}

	var actualType string
	switch data.(type) {
	case map[string]interface{}:
		actualType = "object"
	case []interface{}:
		actualType = "array"
	case string:
		actualType = "string"
	case float64:
		actualType = "number"
	case bool:
		actualType = "boolean"
	default:
		actualType = "unknown"
	}

	// "integer" is a subset of "number" in JSON; both parse as float64
	if actualType == "number" && expectedType == "integer" {
		return nil // integer validation is done in validateNumber
	}

	if actualType != expectedType {
		return &ValidationError{
			Field:   path,
			Message: fmt.Sprintf("expected type %s, got %s", expectedType, actualType),
			Value:   data,
		}
	}

	return nil
}

// validateObject validates an object against a schema
func validateObject(data interface{}, schema *JSONSchema, path string) []ValidationError {
	var errs []ValidationError

	obj, ok := data.(map[string]interface{})
	if !ok {
		return []ValidationError{{
			Field:   path,
			Message: "expected object",
			Value:   data,
		}}
	}

	// Check required fields
	for _, req := range schema.Required {
		if _, exists := obj[req]; !exists {
			fieldPath := path
			if fieldPath != "" {
				fieldPath += "."
			}
			fieldPath += req
			errs = append(errs, ValidationError{
				Field:   fieldPath,
				Message: "required field missing",
			})
		}
	}

	// Validate each property
	for key, propSchema := range schema.Properties {
		value, exists := obj[key]
		if !exists {
			continue
		}

		fieldPath := path
		if fieldPath != "" {
			fieldPath += "."
		}
		fieldPath += key

		errs = append(errs, validateJSON(value, propSchema, fieldPath)...)
	}

	return errs
}

// validateArray validates an array against a schema
func validateArray(data interface{}, schema *JSONSchema, path string) []ValidationError {
	var errs []ValidationError

	arr, ok := data.([]interface{})
	if !ok {
		return []ValidationError{{
			Field:   path,
			Message: "expected array",
			Value:   data,
		}}
	}

	// Validate length constraints
	if schema.MinLength != nil && len(arr) < *schema.MinLength {
		errs = append(errs, ValidationError{
			Field:   path,
			Message: fmt.Sprintf("array length %d is less than minimum %d", len(arr), *schema.MinLength),
			Value:   len(arr),
		})
	}

	if schema.MaxLength != nil && len(arr) > *schema.MaxLength {
		errs = append(errs, ValidationError{
			Field:   path,
			Message: fmt.Sprintf("array length %d exceeds maximum %d", len(arr), *schema.MaxLength),
			Value:   len(arr),
		})
	}

	// Validate items
	if schema.Items != nil {
		for i, item := range arr {
			itemPath := fmt.Sprintf("%s[%d]", path, i)
			errs = append(errs, validateJSON(item, schema.Items, itemPath)...)
		}
	}

	return errs
}

// validateString validates a string against a schema
func validateString(data interface{}, schema *JSONSchema, path string) []ValidationError {
	var errs []ValidationError

	str, ok := data.(string)
	if !ok {
		return []ValidationError{{
			Field:   path,
			Message: "expected string",
			Value:   data,
		}}
	}

	// Validate length constraints
	if schema.MinLength != nil && len(str) < *schema.MinLength {
		errs = append(errs, ValidationError{
			Field:   path,
			Message: fmt.Sprintf("string length %d is less than minimum %d", len(str), *schema.MinLength),
			Value:   len(str),
		})
	}

	if schema.MaxLength != nil && len(str) > *schema.MaxLength {
		errs = append(errs, ValidationError{
			Field:   path,
			Message: fmt.Sprintf("string length %d exceeds maximum %d", len(str), *schema.MaxLength),
			Value:   len(str),
		})
	}

	// Validate pattern
	if schema.Pattern != "" {
		if matched, err := regexp.MatchString(schema.Pattern, str); err != nil {
			errs = append(errs, ValidationError{
				Field:   path,
				Message: "invalid regex pattern in schema",
			})
		} else if !matched {
			errs = append(errs, ValidationError{
				Field:   path,
				Message: fmt.Sprintf("does not match pattern: %s", schema.Pattern),
				Value:   str,
			})
		}
	}

	// Validate enum
	if len(schema.Enum) > 0 {
		found := false
		for _, e := range schema.Enum {
			if str == fmt.Sprint(e) {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, ValidationError{
				Field:   path,
				Message: fmt.Sprintf("value must be one of: %v", schema.Enum),
				Value:   str,
			})
		}
	}

	// Validate format
	if schema.Format != "" {
		if err := validateFormat(str, schema.Format); err != nil {
			errs = append(errs, ValidationError{
				Field:   path,
				Message: err.Error(),
				Value:   str,
			})
		}
	}

	return errs
}

// validateNumber validates a number against a schema
func validateNumber(data interface{}, schema *JSONSchema, path string) []ValidationError {
	var errs []ValidationError

	var num float64
	switch v := data.(type) {
	case float64:
		num = v
	case float32:
		num = float64(v)
	case int:
		num = float64(v)
	case int64:
		num = float64(v)
	case int32:
		num = float64(v)
	default:
		return []ValidationError{{
			Field:   path,
			Message: "expected number",
			Value:   data,
		}}
	}

	// Validate integer constraint
	if schema.Type == "integer" && num != float64(int64(num)) {
		errs = append(errs, ValidationError{
			Field:   path,
			Message: "expected integer value",
			Value:   num,
		})
	}

	// Validate minimum
	if schema.Minimum != nil && num < *schema.Minimum {
		errs = append(errs, ValidationError{
			Field:   path,
			Message: fmt.Sprintf("value %v is less than minimum %v", num, *schema.Minimum),
			Value:   num,
		})
	}

	// Validate maximum
	if schema.Maximum != nil && num > *schema.Maximum {
		errs = append(errs, ValidationError{
			Field:   path,
			Message: fmt.Sprintf("value %v exceeds maximum %v", num, *schema.Maximum),
			Value:   num,
		})
	}

	// Validate enum
	if len(schema.Enum) > 0 {
		found := false
		for _, e := range schema.Enum {
			if reflect.DeepEqual(e, num) {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, ValidationError{
				Field:   path,
				Message: fmt.Sprintf("value must be one of: %v", schema.Enum),
				Value:   num,
			})
		}
	}

	return errs
}

// validateFormat validates a string against a format
func validateFormat(value, format string) error {
	switch format {
	case "email":
		return validateEmail(value)
	case "uuid":
		_, err := uuid.Parse(value)
		if err != nil {
			return fmt.Errorf("invalid UUID format")
		}
		return nil
	case "uri", "url":
		if !strings.HasPrefix(value, "http://") && !strings.HasPrefix(value, "https://") {
			return fmt.Errorf("invalid URL format")
		}
		return nil
	case "date-time":
		_, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return fmt.Errorf("invalid date-time format, expected RFC3339")
		}
		return nil
	case "date":
		_, err := time.Parse("2006-01-02", value)
		if err != nil {
			return fmt.Errorf("invalid date format, expected YYYY-MM-DD")
		}
		return nil
	default:
		return nil
	}
}

// validateEmail validates an email address
func validateEmail(email string) error {
	// Simple email validation regex
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// ========================================
// Built-in Validators
// ========================================

// ValidateEmail returns a validator that checks if a value is a valid email
func ValidateEmail() Validator {
	return func(value string) error {
		return validateEmail(value)
	}
}

// ValidateUUID returns a validator that checks if a value is a valid UUID
func ValidateUUID() Validator {
	return func(value string) error {
		_, err := uuid.Parse(value)
		if err != nil {
			return fmt.Errorf("invalid UUID format")
		}
		return nil
	}
}

// ValidateMinLength returns a validator that checks minimum length
func ValidateMinLength(min int) Validator {
	return func(value string) error {
		if len(value) < min {
			return fmt.Errorf("length must be at least %d", min)
		}
		return nil
	}
}

// ValidateMaxLength returns a validator that checks maximum length
func ValidateMaxLength(max int) Validator {
	return func(value string) error {
		if len(value) > max {
			return fmt.Errorf("length must not exceed %d", max)
		}
		return nil
	}
}

// ValidateRange returns a validator that checks if a numeric value is within range
func ValidateRange(min, max int64) Validator {
	return func(value string) error {
		num, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("must be a number")
		}
		if num < min || num > max {
			return fmt.Errorf("must be between %d and %d", min, max)
		}
		return nil
	}
}

// ValidateEnum returns a validator that checks if a value is in the allowed set
func ValidateEnum(allowed []string) Validator {
	return func(value string) error {
		for _, a := range allowed {
			if value == a {
				return nil
			}
		}
		return fmt.Errorf("must be one of: %v", allowed)
	}
}

// ValidatePattern returns a validator that checks if a value matches a regex pattern
func ValidatePattern(pattern string) Validator {
	regex := regexp.MustCompile(pattern)
	return func(value string) error {
		if !regex.MatchString(value) {
			return fmt.Errorf("does not match pattern: %s", pattern)
		}
		return nil
	}
}

// ValidateInt returns a validator that checks if a value is a valid integer
func ValidateInt() Validator {
	return func(value string) error {
		_, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("must be an integer")
		}
		return nil
	}
}

// ValidateBool returns a validator that checks if a value is a valid boolean
func ValidateBool() Validator {
	return func(value string) error {
		_, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("must be a boolean (true or false)")
		}
		return nil
	}
}

// ValidateDate returns a validator that checks if a value is a valid date
func ValidateDate() Validator {
	return func(value string) error {
		_, err := time.Parse("2006-01-02", value)
		if err != nil {
			return fmt.Errorf("invalid date format, expected YYYY-MM-DD")
		}
		return nil
	}
}

// ValidateDateTime returns a validator that checks if a value is a valid datetime
func ValidateDateTime() Validator {
	return func(value string) error {
		_, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return fmt.Errorf("invalid date-time format, expected RFC3339")
		}
		return nil
	}
}

// CustomValidator returns a validator from a custom function
func CustomValidator(fn func(string) error) Validator {
	return fn
}

// ========================================
// Common JSON Schemas
// ========================================

// UserCreateSchema returns a JSON schema for user creation
var UserCreateSchema = &JSONSchema{
	Type:     "object",
	Required: []string{"email", "name"},
	Properties: map[string]*JSONSchema{
		"email": {
			Type:   "string",
			Format: "email",
		},
		"name": {
			Type:      "string",
			MinLength: intPtr(1),
			MaxLength: intPtr(255),
		},
		"password": {
			Type:      "string",
			MinLength: intPtr(8),
		},
		"role": {
			Type: "string",
			Enum: []interface{}{"admin", "user", "viewer"},
		},
	},
}

// UserUpdateSchema returns a JSON schema for user updates
var UserUpdateSchema = &JSONSchema{
	Type:     "object",
	Required: []string{}, // No required fields for updates
	Properties: map[string]*JSONSchema{
		"email": {
			Type:   "string",
			Format: "email",
		},
		"name": {
			Type:      "string",
			MinLength: intPtr(1),
			MaxLength: intPtr(255),
		},
		"role": {
			Type: "string",
			Enum: []interface{}{"admin", "user", "viewer"},
		},
	},
}

// PaginationSchema returns validation rules for common pagination query params
var PaginationSchema = map[string]ValidationRule{
	"page": {
		Validators: []Validator{ValidateInt(), ValidateRange(1, 10000)},
	},
	"limit": {
		Validators: []Validator{ValidateInt(), ValidateRange(1, 100)},
	},
	"sort_by": {
		Validators: []Validator{ValidateMaxLength(50)},
	},
	"sort_order": {
		Validators: []Validator{ValidateEnum([]string{"asc", "desc"})},
	},
}

// Helper function to create int pointers
func intPtr(i int) *int {
	return &i
}

// floatPtr creates a float64 pointer
func floatPtr(f float64) *float64 {
	return &f
}

// ========================================
// Helper for Getting Validated Body
// ========================================

// GetValidatedBody retrieves the validated request body from the context
// Returns nil if validation was not performed
func GetValidatedBody(c *gin.Context) interface{} {
	if body, exists := c.Get("validated_body"); exists {
		return body
	}
	return nil
}

// GetValidatedBodyMap retrieves the validated body as a map
func GetValidatedBodyMap(c *gin.Context) map[string]interface{} {
	body := GetValidatedBody(c)
	if body == nil {
		return nil
	}
	if m, ok := body.(map[string]interface{}); ok {
		return m
	}
	return nil
}
