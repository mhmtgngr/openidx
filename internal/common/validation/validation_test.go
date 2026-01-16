package validation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateRequired(t *testing.T) {
	tests := []struct {
		name        string
		field       string
		value       string
		expectError bool
	}{
		{"Valid value", "username", "john.doe", false},
		{"Empty string", "username", "", true},
		{"Whitespace only", "username", "   ", true},
		{"Valid with spaces", "name", "John Doe", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRequired(tt.field, tt.value)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "is required")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		expectError bool
	}{
		{"Valid email", "john.doe@example.com", false},
		{"Valid email with subdomain", "user@mail.example.com", false},
		{"Valid email with plus", "user+tag@example.com", false},
		{"Invalid - no @", "notanemail", true},
		{"Invalid - no domain", "user@", true},
		{"Invalid - no local", "@example.com", true},
		{"Invalid - spaces", "user @example.com", true},
		{"Empty string - should pass (use ValidateRequired)", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail("email", tt.email)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		expectError bool
		errorMsg    string
	}{
		{"Valid username", "john_doe", false, ""},
		{"Valid with dots", "john.doe", false, ""},
		{"Valid with hyphens", "john-doe", false, ""},
		{"Valid with numbers", "john123", false, ""},
		{"Too short", "ab", true, "must be between 3 and 32 characters"},
		{"Too long", "abcdefghijklmnopqrstuvwxyz1234567", true, "must be between 3 and 32 characters"},
		{"Starts with number", "123john", true, "must start with a letter"},
		{"Contains special chars", "john@doe", true, "can only contain"},
		{"Contains spaces", "john doe", true, "can only contain"},
		{"Empty - should pass", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUsername("username", tt.username)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateLength(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		min         int
		max         int
		expectError bool
	}{
		{"Valid length", "hello", 3, 10, false},
		{"Exact min", "abc", 3, 10, false},
		{"Exact max", "1234567890", 3, 10, false},
		{"Too short", "ab", 3, 10, true},
		{"Too long", "12345678901", 3, 10, true},
		{"Empty within range", "", 0, 10, false},
		{"Empty below min", "", 1, 10, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLength("field", tt.value, tt.min, tt.max)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateUUID(t *testing.T) {
	tests := []struct {
		name        string
		uuid        string
		expectError bool
	}{
		{"Valid UUID", "123e4567-e89b-12d3-a456-426614174000", false},
		{"Valid UUID uppercase", "123E4567-E89B-12D3-A456-426614174000", false},
		{"Invalid - no hyphens", "123e4567e89b12d3a456426614174000", true},
		{"Invalid - wrong format", "123e4567-e89b-12d3-a456", true},
		{"Invalid - not hex", "gggg4567-e89b-12d3-a456-426614174000", true},
		{"Empty - should pass", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUUID("id", tt.uuid)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		expectError bool
	}{
		{"Valid HTTP URL", "http://example.com", false},
		{"Valid HTTPS URL", "https://example.com", false},
		{"Valid with path", "https://example.com/path", false},
		{"Valid with subdomain", "https://api.example.com", false},
		{"Invalid - no protocol", "example.com", true},
		{"Invalid - FTP", "ftp://example.com", true},
		{"Invalid - spaces", "http://example .com", true},
		{"Empty - should pass", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURL("url", tt.url)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAlphanumeric(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		expectError bool
	}{
		{"Valid letters only", "abcDEF", false},
		{"Valid numbers only", "123456", false},
		{"Valid mixed", "abc123", false},
		{"Invalid - spaces", "abc 123", true},
		{"Invalid - special chars", "abc@123", true},
		{"Invalid - hyphen", "abc-123", true},
		{"Empty - should pass", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAlphanumeric("field", tt.value)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRange(t *testing.T) {
	tests := []struct {
		name        string
		value       int
		min         int
		max         int
		expectError bool
	}{
		{"Valid in range", 5, 1, 10, false},
		{"Valid at min", 1, 1, 10, false},
		{"Valid at max", 10, 1, 10, false},
		{"Below min", 0, 1, 10, true},
		{"Above max", 11, 1, 10, true},
		{"Negative in range", -5, -10, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRange("field", tt.value, tt.min, tt.max)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePositive(t *testing.T) {
	tests := []struct {
		name        string
		value       int
		expectError bool
	}{
		{"Positive", 5, false},
		{"Large positive", 1000000, false},
		{"Zero", 0, true},
		{"Negative", -5, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePositive("field", tt.value)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateOneOf(t *testing.T) {
	allowed := []string{"admin", "user", "guest"}

	tests := []struct {
		name        string
		value       string
		expectError bool
	}{
		{"Valid - admin", "admin", false},
		{"Valid - user", "user", false},
		{"Valid - guest", "guest", false},
		{"Invalid value", "superadmin", true},
		{"Case sensitive - User", "User", true},
		{"Empty - should pass", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOneOf("role", tt.value, allowed)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "must be one of")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectError bool
		errorCount  int // Expected number of validation errors
	}{
		{"Valid strong password", "MyP@ssw0rd123", false, 0},
		{"Valid complex password", "C0mpl3x!Pass", false, 0},
		{"Too short", "Pas$1", true, 1},
		{"No uppercase", "myp@ssw0rd123", true, 1},
		{"No lowercase", "MYP@SSW0RD123", true, 1},
		{"No digit", "MyP@ssword", true, 1},
		{"No special char", "MyPassword123", true, 1},
		{"Multiple issues", "password", true, 3}, // no uppercase, digit, special
		{"Empty - should pass", "", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword("password", tt.password)
			if tt.expectError {
				assert.Error(t, err)
				if verrs, ok := err.(*ValidationErrors); ok {
					assert.Equal(t, tt.errorCount, len(verrs.Errors))
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidationErrors(t *testing.T) {
	t.Run("Add and check errors", func(t *testing.T) {
		errors := &ValidationErrors{}

		assert.False(t, errors.HasErrors())

		errors.Add("field1", "is required")
		assert.True(t, errors.HasErrors())
		assert.Equal(t, 1, len(errors.Errors))

		errors.Add("field2", "is invalid", "bad_value")
		assert.Equal(t, 2, len(errors.Errors))
		assert.Equal(t, "bad_value", errors.Errors[1].Value)
	})

	t.Run("Error message", func(t *testing.T) {
		errors := &ValidationErrors{}
		assert.Equal(t, "validation failed", errors.Error())

		errors.Add("field1", "is required")
		assert.Contains(t, errors.Error(), "field1")

		errors.Add("field2", "is invalid")
		assert.Contains(t, errors.Error(), "2 errors")
	})
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"No change needed", "hello", "hello"},
		{"Trim spaces", "  hello  ", "hello"},
		{"Multiple spaces", "hello    world", "hello world"},
		{"Tabs and newlines", "hello\t\nworld", "hello world"},
		{"Mixed whitespace", "  hello   world  ", "hello world"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizeEmail(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Already clean", "user@example.com", "user@example.com"},
		{"Uppercase", "User@Example.COM", "user@example.com"},
		{"With spaces", "  user@example.com  ", "user@example.com"},
		{"Mixed case with spaces", "  User@Example.COM  ", "user@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeEmail(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizeUsername(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Already clean", "john.doe", "john.doe"},
		{"Uppercase", "John.Doe", "john.doe"},
		{"With spaces", "  john.doe  ", "john.doe"},
		{"Mixed case with spaces", "  John.Doe  ", "john.doe"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeUsername(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateAll(t *testing.T) {
	t.Run("All validations pass", func(t *testing.T) {
		err := ValidateAll(
			func() error { return ValidateRequired("field1", "value1") },
			func() error { return ValidateEmail("field2", "user@example.com") },
			func() error { return ValidateRange("field3", 5, 1, 10) },
		)
		assert.NoError(t, err)
	})

	t.Run("One validation fails", func(t *testing.T) {
		err := ValidateAll(
			func() error { return ValidateRequired("field1", "value1") },
			func() error { return ValidateRequired("field2", "") }, // This fails
			func() error { return ValidateRange("field3", 5, 1, 10) },
		)
		assert.Error(t, err)

		verrs, ok := err.(*ValidationErrors)
		assert.True(t, ok)
		assert.Equal(t, 1, len(verrs.Errors))
	})

	t.Run("Multiple validations fail", func(t *testing.T) {
		err := ValidateAll(
			func() error { return ValidateRequired("field1", "") },     // Fails
			func() error { return ValidateEmail("field2", "invalid") }, // Fails
			func() error { return ValidateRange("field3", 15, 1, 10) }, // Fails
		)
		assert.Error(t, err)

		verrs, ok := err.(*ValidationErrors)
		assert.True(t, ok)
		assert.Equal(t, 3, len(verrs.Errors))
	})
}

// Benchmark tests
func BenchmarkValidateEmail(b *testing.B) {
	email := "user@example.com"
	for i := 0; i < b.N; i++ {
		ValidateEmail("email", email)
	}
}

func BenchmarkValidateUsername(b *testing.B) {
	username := "john.doe"
	for i := 0; i < b.N; i++ {
		ValidateUsername("username", username)
	}
}

func BenchmarkValidatePassword(b *testing.B) {
	password := "MyP@ssw0rd123"
	for i := 0; i < b.N; i++ {
		ValidatePassword("password", password)
	}
}
