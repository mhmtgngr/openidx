// Package sms provides comprehensive unit tests for Turkish phone number normalization
package sms

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNormalizePhoneTR tests the normalizePhoneTR function with various Turkish phone formats
func TestNormalizePhoneTR(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Valid formats that should preserve the 90XXXXXXXXXX pattern
		{
			name:     "Already in 90XXXXXXXXXX format (12 digits)",
			input:    "905551234567",
			expected: "905551234567",
		},
		{
			name:     "Starting with +90 (13 chars with +)",
			input:    "+905551234567",
			expected: "905551234567",
		},
		{
			name:     "Starting with +90 and spaces",
			input:    "+90 555 123 45 67",
			expected: "905551234567",
		},
		{
			name:     "Starting with 0 (11 digits)",
			input:    "05551234567",
			expected: "905551234567",
		},
		{
			name:     "Starting with 0 and dashes",
			input:    "0-555-123-45-67",
			expected: "905551234567",
		},
		{
			name:     "Starting with 0 and spaces",
			input:    "0 555 123 45 67",
			expected: "905551234567",
		},
		// 10-digit format (mobile numbers starting with 5)
		{
			name:     "10 digits starting with 5",
			input:    "5551234567",
			expected: "905551234567",
		},
		{
			name:     "10 digits starting with 5 and spaces",
			input:    "555 123 45 67",
			expected: "905551234567",
		},
		{
			name:     "10 digits starting with 5 and dashes",
			input:    "555-123-4567",
			expected: "905551234567",
		},
		// 10-digit format (other prefixes like 4)
		{
			name:     "10 digits starting with 4",
			input:    "4123456789",
			expected: "904123456789",
		},
		// Already normalized (should preserve)
		{
			name:     "90XXXXXXXXXX already normalized",
			input:    "902121234567",
			expected: "902121234567",
		},
		{
			name:     "90XXXXXXXXX with 11 digits (edge case)",
			input:    "90555123456",
			expected: "90555123456", // Shorter but preserves 90 prefix
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizePhoneTR(tt.input)
			assert.Equal(t, tt.expected, result, "normalizePhoneTR(%q) = %q, want %q", tt.input, result, tt.expected)
		})
	}
}

// TestNormalizePhoneTREdgeCases tests edge cases and invalid inputs
func TestNormalizePhoneTREdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Only non-digit characters",
			input:    "abc-!@#",
			expected: "",
		},
		{
			name:     "International format without +90",
			input:    "90555123456", // 11 digits with 90 prefix
			expected: "90555123456",
		},
		{
			name:     "Too short (less than 10 digits)",
			input:    "555123",
			expected: "555123",
		},
		{
			name:     "Too long (more than 12 digits)",
			input:    "9055512345678",
			expected: "9055512345678",
		},
		{
			name:     "Mixed format with parentheses",
			input:    "+90 (555) 123 45 67",
			expected: "905551234567",
		},
		{
			name:     "Mixed format with dots",
			input:    "0.555.123.45.67",
			expected: "905551234567",
		},
		{
			name:     "With country code 90 in middle (unusual but handle)",
			input:    "9055590123456",
			expected: "9055590123456",
		},
		{
			name:     "Multiple plus signs",
			input:    "++905551234567",
			expected: "905551234567",
		},
		{
			name:     "With extension separator",
			input:    "05551234567x123",
			expected: "05551234567123", // The x is removed, leaving 14 digits which doesn't match any special case
		},
		{
			name:     "Turkish mobile operator codes - Turkcell (53X)",
			input:    "05321234567",
			expected: "905321234567",
		},
		{
			name:     "Turkish mobile operator codes - Vodafone (54X)",
			input:    "05421234567",
			expected: "905421234567",
		},
		{
			name:     "Turkish mobile operator codes - Turk Telekom (55X)",
			input:    "05521234567",
			expected: "905521234567",
		},
		{
			name:     "Istanbul landline (212)",
			input:    "02121234567",
			expected: "902121234567",
		},
		{
			name:     "Ankara landline (312)",
			input:    "03121234567",
			expected: "903121234567",
		},
		{
			name:     "Izmir landline (232)",
			input:    "02321234567",
			expected: "902321234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizePhoneTR(tt.input)
			assert.Equal(t, tt.expected, result, "normalizePhoneTR(%q) = %q, want %q", tt.input, result, tt.expected)
		})
	}
}

// TestNormalizePhoneTRInternationalFormats tests various international input formats
func TestNormalizePhoneTRInternationalFormats(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "E.164 format with +90",
			input:    "+905551234567",
			expected: "905551234567",
		},
		{
			name:     "E.164 format 0090",
			input:    "00905551234567",
			expected: "00905551234567", // 0090 format not handled - preserved as-is
		},
		{
			name:     "With double zero prefix",
			input:    "00905551234567",
			expected: "00905551234567", // 0090 format not handled - preserved as-is
		},
		{
			name:     "Spaces in E.164",
			input:    "+90 555 123 45 67",
			expected: "905551234567",
		},
		{
			name:     "Hyphens in E.164",
			input:    "+90-555-123-45-67",
			expected: "905551234567",
		},
		{
			name:     "Mixed separators",
			input:    "+90(555)123-45-67",
			expected: "905551234567",
		},
		{
			name:     "No space after country code",
			input:    "+905551234567",
			expected: "905551234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizePhoneTR(tt.input)
			assert.Equal(t, tt.expected, result, "normalizePhoneTR(%q) = %q, want %q", tt.input, result, tt.expected)
		})
	}
}

// TestNormalizePhoneTRPreservesInput tests that certain patterns are preserved
func TestNormalizePhoneTRPreservesInput(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		shouldMatch string
	}{
		{
			name:        "90XXXXXXXXXX should be preserved exactly",
			input:       "905551234567",
			shouldMatch: "905551234567",
		},
		{
			name:        "Longer numbers with 90 prefix preserved",
			input:       "90123456789012",
			shouldMatch: "90123456789012",
		},
		{
			name:        "Random digits without recognizable pattern preserved",
			input:       "123456789",
			shouldMatch: "123456789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizePhoneTR(tt.input)
			assert.Equal(t, tt.shouldMatch, result, "normalizePhoneTR(%q) should preserve to %q", tt.input, tt.shouldMatch)
		})
	}
}

// BenchmarkNormalizePhoneTR benchmarks the normalization function
func BenchmarkNormalizePhoneTR(b *testing.B) {
	inputs := []string{
		"905551234567",
		"+90 555 123 45 67",
		"05551234567",
		"555-123-4567",
		"0(555)123-4567",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, input := range inputs {
			_ = normalizePhoneTR(input)
		}
	}
}

// TestNormalizePhoneTRRealWorldExamples tests real-world Turkish phone number examples
func TestNormalizePhoneTRRealWorldExamples(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Common mobile format - 05XX XXX XX XX",
			input:    "0532 123 45 67",
			expected: "905321234567",
		},
		{
			name:     "Website form input - 5XX XXX XX XX",
			input:    "532 123 45 67",
			expected: "905321234567",
		},
		{
			name:     "International form - +90 5XX XXX XX XX",
			input:    "+90 532 123 45 67",
			expected: "905321234567",
		},
		{
			name:     "SMS gateway format - 905XXXXXXXXX",
			input:    "905321234567",
			expected: "905321234567",
		},
		{
			name:     "Landline Istanbul - 0212 XXX XX XX",
			input:    "0212 445 56 78",
			expected: "902124455678",
		},
		{
			name:     "Landline Ankara - 0312 XXX XX XX",
			input:    "0312 123 45 67",
			expected: "903121234567",
		},
		{
			name:     "Landline Izmir - 0232 XXX XX XX",
			input:    "0232 456 78 90",
			expected: "902324567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizePhoneTR(tt.input)
			assert.Equal(t, tt.expected, result, "normalizePhoneTR(%q) = %q, want %q", tt.input, result, tt.expected)
		})
	}
}
