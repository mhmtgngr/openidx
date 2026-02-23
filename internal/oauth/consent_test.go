// Package oauth provides unit tests for consent management functionality
package oauth

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test Scope Definitions

func TestScopeDefinitions(t *testing.T) {
	t.Run("All required scopes are defined", func(t *testing.T) {
		requiredScopes := []string{"openid", "profile", "email", "phone", "address", "offline_access"}
		for _, scope := range requiredScopes {
			_, exists := ScopeDefinitions[scope]
			assert.True(t, exists, "Scope %s should be defined", scope)
		}
	})

	t.Run("OpenID scope is marked as required", func(t *testing.T) {
		openidDef := ScopeDefinitions["openid"]
		assert.True(t, openidDef.Required, "openid scope should be required")
		assert.Equal(t, "openid", openidDef.Scope)
	})

	t.Run("Scope display information is complete", func(t *testing.T) {
		for _, def := range ScopeDefinitions {
			assert.NotEmpty(t, def.Scope, "Scope should have a value")
			assert.NotEmpty(t, def.Name, "Scope should have a display name")
			assert.NotEmpty(t, def.Description, "Scope should have a description")
		}
	})
}

// Test Scope Parsing and Building

func TestParseScopeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Single scope",
			input:    "openid",
			expected: []string{"openid"},
		},
		{
			name:     "Multiple scopes",
			input:    "openid profile email",
			expected: []string{"openid", "profile", "email"},
		},
		{
			name:     "Scopes with extra spaces",
			input:    "openid  profile   email",
			expected: []string{"openid", "profile", "email"},
		},
		{
			name:     "Empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "Only spaces",
			input:    "   ",
			expected: []string{},
		},
		{
			name:     "Trailing and leading spaces",
			input:    "  openid profile email  ",
			expected: []string{"openid", "profile", "email"},
		},
		{
			name:     "Scopes with custom values",
			input:    "openid custom1 custom2",
			expected: []string{"openid", "custom1", "custom2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseScopeString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildScopeString(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		expected string
	}{
		{
			name:     "Single scope",
			scopes:   []string{"openid"},
			expected: "openid",
		},
		{
			name:     "Multiple scopes",
			scopes:   []string{"openid", "profile", "email"},
			expected: "openid profile email",
		},
		{
			name:     "Empty slice",
			scopes:   []string{},
			expected: "",
		},
		{
			name:     "Slice with empty strings",
			scopes:   []string{"openid", "", "profile"},
			expected: "openid  profile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildScopeString(tt.scopes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeScopes(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "Already normalized scopes",
			input:    []string{"openid", "profile", "email"},
			expected: []string{"openid", "profile", "email"},
		},
		{
			name:     "Scopes with duplicates",
			input:    []string{"openid", "profile", "openid", "email"},
			expected: []string{"openid", "profile", "email"},
		},
		{
			name:     "Scopes with extra spaces",
			input:    []string{" openid ", " profile ", " email "},
			expected: []string{"openid", "profile", "email"},
		},
		{
			name:     "Scopes with empty strings",
			input:    []string{"openid", "", "profile", ""},
			expected: []string{"openid", "profile"},
		},
		{
			name:     "Empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "All duplicates",
			input:    []string{"openid", "openid", "openid"},
			expected: []string{"openid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeScopes(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetRequiredScopes(t *testing.T) {
	required := GetRequiredScopes()

	assert.Contains(t, required, "openid", "openid should always be required")

	// Verify all returned scopes are marked as required in definitions
	for _, scope := range required {
		def, exists := ScopeDefinitions[scope]
		assert.True(t, exists, "Required scope %s should be defined", scope)
		assert.True(t, def.Required, "Required scope %s should be marked as required", scope)
	}
}

// Test Consent Record

func TestConsentRecord(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(90 * 24 * time.Hour)

	consent := &ConsentRecord{
		ID:        "consent-123",
		UserID:    "user-123",
		ClientID:  "client-123",
		Scopes:    []string{"openid", "profile", "email"},
		Status:    ConsentGranted,
		GrantedAt: now,
		ExpiresAt: &expiresAt,
	}

	assert.Equal(t, "consent-123", consent.ID)
	assert.Equal(t, "user-123", consent.UserID)
	assert.Equal(t, "client-123", consent.ClientID)
	assert.Len(t, consent.Scopes, 3)
	assert.Equal(t, ConsentGranted, consent.Status)
	assert.NotNil(t, consent.ExpiresAt)
}

// Test IsConsentRequired

func TestIsConsentRequired(t *testing.T) {
	tests := []struct {
		name           string
		requestedScopes []string
		previousConsent *ConsentRecord
		expected       bool
	}{
		{
			name:           "No previous consent",
			requestedScopes: []string{"openid", "profile"},
			previousConsent: nil,
			expected:       true,
		},
		{
			name:           "Exact match",
			requestedScopes: []string{"openid", "profile", "email"},
			previousConsent: &ConsentRecord{
				Scopes: []string{"openid", "profile", "email"},
			},
			expected: false,
		},
		{
			name:           "Subset of previously granted",
			requestedScopes: []string{"openid", "profile"},
			previousConsent: &ConsentRecord{
				Scopes: []string{"openid", "profile", "email"},
			},
			expected: false,
		},
		{
			name:           "New scope requested",
			requestedScopes: []string{"openid", "profile", "email", "phone"},
			previousConsent: &ConsentRecord{
				Scopes: []string{"openid", "profile", "email"},
			},
			expected: true,
		},
		{
			name:           "Empty requested scopes",
			requestedScopes: []string{},
			previousConsent: &ConsentRecord{
				Scopes: []string{"openid", "profile"},
			},
			expected: false,
		},
		{
			name:           "Only openid requested but profile granted",
			requestedScopes: []string{"openid"},
			previousConsent: &ConsentRecord{
				Scopes: []string{"openid", "profile"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsConsentRequired(tt.requestedScopes, tt.previousConsent)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test Consent Request

func TestConsentRequest(t *testing.T) {
	now := time.Now()

	req := &ConsentRequest{
		SessionID:       "session-123",
		UserID:          "user-123",
		ClientID:        "client-123",
		RedirectURI:     "https://example.com/callback",
		RequestedScopes: []string{"openid", "profile", "email"},
		GrantedScopes:   []string{"openid", "profile", "email"},
		State:           "state-123",
		CreatedAt:       now,
		ExpiresAt:       now.Add(10 * time.Minute),
	}

	assert.Equal(t, "session-123", req.SessionID)
	assert.Equal(t, "user-123", req.UserID)
	assert.Len(t, req.RequestedScopes, 3)
	assert.Empty(t, req.DeniedScopes)
}

// Test Scope Display

func TestScopeDisplay(t *testing.T) {
	display := ScopeDisplay{
		Scope:       "openid",
		Name:        "OpenID Connect",
		Description: "Verify your identity securely using OpenID Connect",
		Required:    true,
	}

	assert.Equal(t, "openid", display.Scope)
	assert.Equal(t, "OpenID Connect", display.Name)
	assert.True(t, display.Required)
}

// Test Consent UI Response

func TestConsentUIResponse(t *testing.T) {
	response := &ConsentUIResponse{
		SessionID:       "session-123",
		ClientID:        "client-123",
		ClientName:      "Test Application",
		ClientLogoURI:   "https://example.com/logo.png",
		ClientPolicyURI: "https://example.com/policy",
		ClientTOSURI:    "https://example.com/tos",
		RedirectURI:     "https://example.com/callback",
		State:           "state-123",
	}

	assert.Equal(t, "session-123", response.SessionID)
	assert.Equal(t, "client-123", response.ClientID)
	assert.Equal(t, "Test Application", response.ClientName)
	assert.Empty(t, response.RequestedScopes)
}

// Test Consent Status Constants

func TestConsentStatusConstants(t *testing.T) {
	assert.Equal(t, "granted", ConsentGranted)
	assert.Equal(t, "denied", ConsentDenied)
	assert.Equal(t, "revoked", ConsentRevoked)
}

// Test CheckExistingConsent Logic

func TestCheckExistingConsentLogic(t *testing.T) {
	// This tests the logic without database

	tests := []struct {
		name            string
		requestedScopes []string
		consentScopes   []string
		consentExpires  *time.Time
		consentStatus   string
		expectMatch     bool
	}{
		{
			name:            "Exact match, not expired",
			requestedScopes: []string{"openid", "profile", "email"},
			consentScopes:   []string{"openid", "profile", "email"},
			consentExpires:  timePtr(time.Now().Add(1 * time.Hour)),
			consentStatus:   "granted",
			expectMatch:     true,
		},
		{
			name:            "Consent expired",
			requestedScopes: []string{"openid", "profile"},
			consentScopes:   []string{"openid", "profile", "email"},
			consentExpires:  timePtr(time.Now().Add(-1 * time.Hour)),
			consentStatus:   "granted",
			expectMatch:     false,
		},
		{
			name:            "Consent revoked",
			requestedScopes: []string{"openid", "profile"},
			consentScopes:   []string{"openid", "profile", "email"},
			consentExpires:  timePtr(time.Now().Add(1 * time.Hour)),
			consentStatus:   "revoked",
			expectMatch:     false,
		},
		{
			name:            "New scope requested",
			requestedScopes: []string{"openid", "profile", "email", "phone"},
			consentScopes:   []string{"openid", "profile", "email"},
			consentExpires:  timePtr(time.Now().Add(1 * time.Hour)),
			consentStatus:   "granted",
			expectMatch:     false,
		},
		{
			name:            "Subset of granted scopes",
			requestedScopes: []string{"openid", "profile"},
			consentScopes:   []string{"openid", "profile", "email"},
			consentExpires:  timePtr(time.Now().Add(1 * time.Hour)),
			consentStatus:   "granted",
			expectMatch:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the logic from CheckExistingConsent
			if tt.consentStatus != "granted" {
				assert.False(t, tt.expectMatch, "Non-granted consent should not match")
				return
			}

			if tt.consentExpires != nil && time.Now().After(*tt.consentExpires) {
				assert.False(t, tt.expectMatch, "Expired consent should not match")
				return
			}

			// Check if all requested scopes are covered
			grantedScopeSet := make(map[string]bool)
			for _, s := range tt.consentScopes {
				grantedScopeSet[s] = true
			}

			allCovered := true
			for _, requested := range tt.requestedScopes {
				if !grantedScopeSet[requested] {
					allCovered = false
					break
				}
			}

			assert.Equal(t, tt.expectMatch, allCovered)
		})
	}
}

// Test Consent Expiration Logic

func TestConsentExpiration(t *testing.T) {
	now := time.Now()

	consent := &ConsentRecord{
		ID:        "consent-123",
		UserID:    "user-123",
		ClientID:  "client-123",
		Scopes:    []string{"openid", "profile"},
		Status:    ConsentGranted,
		GrantedAt: now.Add(-24 * time.Hour),
	}

	t.Run("Consent without expiration is valid", func(t *testing.T) {
		consent.ExpiresAt = nil
		// Simulate the expiration check
		isExpired := consent.ExpiresAt != nil && time.Now().After(*consent.ExpiresAt)
		assert.False(t, isExpired)
	})

	t.Run("Consent with future expiration is valid", func(t *testing.T) {
		future := now.Add(24 * time.Hour)
		consent.ExpiresAt = &future
		isExpired := consent.ExpiresAt != nil && time.Now().After(*consent.ExpiresAt)
		assert.False(t, isExpired)
	})

	t.Run("Consent with past expiration is expired", func(t *testing.T) {
		past := now.Add(-1 * time.Hour)
		consent.ExpiresAt = &past
		isExpired := consent.ExpiresAt != nil && time.Now().After(*consent.ExpiresAt)
		assert.True(t, isExpired)
	})
}

// Test Scope Comparison Functions

func TestScopeComparison(t *testing.T) {
	t.Run("Scope contains function", func(t *testing.T) {
		scopes := []string{"openid", "profile", "email"}

		// Create a simple contains function
		contains := func(slice []string, item string) bool {
			for _, s := range slice {
				if s == item {
					return true
				}
			}
			return false
		}

		assert.True(t, contains(scopes, "openid"))
		assert.True(t, contains(scopes, "profile"))
		assert.True(t, contains(scopes, "email"))
		assert.False(t, contains(scopes, "phone"))
	})

	t.Run("Scope subset check", func(t *testing.T) {
		isSubset := func(requested, allowed []string) bool {
			allowedSet := make(map[string]bool)
			for _, s := range allowed {
				allowedSet[s] = true
			}
			for _, r := range requested {
				if !allowedSet[r] {
					return false
				}
			}
			return true
		}

		assert.True(t, isSubset(
			[]string{"openid", "profile"},
			[]string{"openid", "profile", "email"},
		))

		assert.False(t, isSubset(
			[]string{"openid", "phone"},
			[]string{"openid", "profile", "email"},
		))

		assert.True(t, isSubset(
			[]string{},
			[]string{"openid", "profile"},
		))
	})
}

// Test Consent Metadata

func TestConsentMetadata(t *testing.T) {
	consent := &ConsentRecord{
		ID:      "consent-123",
		UserID:  "user-123",
		ClientID: "client-123",
		Scopes:  []string{"openid", "profile"},
		Metadata: map[string]interface{}{
			"ip_address":    "192.168.1.1",
			"user_agent":    "Mozilla/5.0",
			"consent_screen": "v2",
		},
	}

	assert.NotNil(t, consent.Metadata)
	assert.Equal(t, "192.168.1.1", consent.Metadata["ip_address"])
	assert.Equal(t, "Mozilla/5.0", consent.Metadata["user_agent"])
	assert.Equal(t, "v2", consent.Metadata["consent_screen"])
}

// Test Consent Request with Denied Scopes

func TestConsentRequestWithDeniedScopes(t *testing.T) {
	req := &ConsentRequest{
		SessionID:       "session-123",
		UserID:          "user-123",
		ClientID:        "client-123",
		RedirectURI:     "https://example.com/callback",
		RequestedScopes: []string{"openid", "profile", "email", "phone"},
		GrantedScopes:   []string{"openid", "profile", "email"},
		DeniedScopes:    []string{"phone"},
	}

	assert.Len(t, req.RequestedScopes, 4)
	assert.Len(t, req.GrantedScopes, 3)
	assert.Len(t, req.DeniedScopes, 1)
	assert.Contains(t, req.DeniedScopes, "phone")
}

// Test Scope Display with Previously Granted

func TestScopeDisplayWithPreviouslyGranted(t *testing.T) {
	display := ScopeDisplay{
		Scope:              "profile",
		Name:               "Basic Profile",
		Description:        "Access your basic profile information",
		Required:           false,
		PreviouslyGranted:  true,
	}

	assert.True(t, display.PreviouslyGranted)
}

// Helper functions

func timePtr(t time.Time) *time.Time {
	return &t
}

// Test string helper functions

func TestStringHelpers(t *testing.T) {
	// Test that we can properly join scopes
	scopes := []string{"openid", "profile", "email"}
	joined := strings.Join(scopes, " ")
	assert.Equal(t, "openid profile email", joined)

	// Test that we can split scopes
	split := strings.Split("openid profile email", " ")
	assert.Equal(t, scopes, split)
}

// Test consent status validation

func TestConsentStatusValidation(t *testing.T) {
	validStatuses := []string{ConsentGranted, ConsentDenied, ConsentRevoked}

	for _, status := range validStatuses {
		assert.NotEmpty(t, status, "Consent status should not be empty")
	}

	// Test that constants have expected values
	assert.Equal(t, "granted", ConsentGranted)
	assert.Equal(t, "denied", ConsentDenied)
	assert.Equal(t, "revoked", ConsentRevoked)
}

// Test consent with claims

func TestConsentWithClaims(t *testing.T) {
	consent := &ConsentRecord{
		ID:      "consent-123",
		UserID:  "user-123",
		ClientID: "client-123",
		Scopes:  []string{"openid", "profile"},
		Claims:  []string{"name", "email", "picture"},
		Status:  ConsentGranted,
	}

	assert.Len(t, consent.Claims, 3)
	assert.Contains(t, consent.Claims, "name")
	assert.Contains(t, consent.Claims, "email")
	assert.Contains(t, consent.Claims, "picture")
}

// Test consent timestamp handling

func TestConsentTimestamps(t *testing.T) {
	now := time.Now()

	consent := &ConsentRecord{
		ID:        "consent-123",
		UserID:    "user-123",
		ClientID:  "client-123",
		Scopes:    []string{"openid"},
		Status:    ConsentGranted,
		GrantedAt: now,
	}

	// Initially no timestamps
	assert.Nil(t, consent.ExpiresAt)
	assert.Nil(t, consent.RevokedAt)
	assert.Nil(t, consent.LastUsedAt)

	// Add timestamps
	expiration := now.Add(90 * 24 * time.Hour)
	consent.ExpiresAt = &expiration
	assert.NotNil(t, consent.ExpiresAt)

	revoked := now.Add(24 * time.Hour)
	consent.RevokedAt = &revoked
	assert.NotNil(t, consent.RevokedAt)

	lastUsed := now.Add(1 * time.Hour)
	consent.LastUsedAt = &lastUsed
	assert.NotNil(t, consent.LastUsedAt)
}
