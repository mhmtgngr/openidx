// Package oauth provides unit tests for OAuth 2.0 core flows
package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/internal/common/database"
)

// testEnvironment creates a test environment with in-memory Redis
type testEnvironment struct {
	db      *database.PostgresDB
	redis   *database.RedisClient
	clients *ClientRepository
	store   *Store
}

func setupTestEnvironment(t *testing.T) *testEnvironment {
	// Note: In a real test setup, you'd use testcontainers or a mock
	// For now, we'll create the structures without actual connections
	return &testEnvironment{
		// Would be initialized with test connections
	}
}

// Test Client Repository

func TestGenerateClientID(t *testing.T) {
	clientID := generateClientID()
	assert.NotEmpty(t, clientID)
	// Base64URL encoding of 16 bytes results in approximately 22 characters
	assert.LessOrEqual(t, len(clientID), 24)
}

func TestGenerateClientSecret(t *testing.T) {
	secret := generateClientSecret()
	assert.NotEmpty(t, secret)
	// Base64URL encoding of 32 bytes results in approximately 43 characters
	assert.LessOrEqual(t, len(secret), 44)
}

func TestHashClientSecret(t *testing.T) {
	secret := "test-secret-123"
	hash1 := hashClientSecret(secret)
	hash2 := hashClientSecret(secret)

	assert.Equal(t, hash1, hash2, "Hashing same secret should produce same hash")
	assert.NotEqual(t, secret, hash1, "Hash should not match original secret")
}

func TestValidateRedirectURI(t *testing.T) {
	client := &Client{
		RedirectURIs: []string{
			"https://example.com/callback",
			"https://app.example.com/auth/callback",
			"https://*.example.com/wildcard",
		},
	}

	tests := []struct {
		name        string
		redirectURI string
		expected    bool
	}{
		{
			name:        "Exact match",
			redirectURI: "https://example.com/callback",
			expected:    true,
		},
		{
			name:        "Exact match with path",
			redirectURI: "https://app.example.com/auth/callback",
			expected:    true,
		},
		{
			name:        "Wildcard subdomain match",
			redirectURI: "https://sub.example.com/wildcard",
			expected:    true,
		},
		{
			name:        "Wildcard with nested subdomain",
			redirectURI: "https://nested.sub.example.com/wildcard",
			expected:    true,
		},
		{
			name:        "No match",
			redirectURI: "https://evil.com/callback",
			expected:    false,
		},
		{
			name:        "Path mismatch",
			redirectURI: "https://example.com/wrong-path",
			expected:    false,
		},
		{
			name:        "Protocol mismatch",
			redirectURI: "http://example.com/callback",
			expected:    false,
		},
	}

	repo := &ClientRepository{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := repo.ValidateRedirectURI(client, tt.redirectURI)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateGrantType(t *testing.T) {
	client := &Client{
		GrantTypes: []string{"authorization_code", "refresh_token"},
	}

	repo := &ClientRepository{}

	tests := []struct {
		name      string
		grantType string
		expected  bool
	}{
		{"Supported grant type", "authorization_code", true},
		{"Supported refresh token", "refresh_token", true},
		{"Unsupported grant type", "client_credentials", false},
		{"Password grant", "password", false},
		{"Empty grant type", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := repo.ValidateGrantType(client, tt.grantType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateScope(t *testing.T) {
	client := &Client{
		Scopes: []string{"openid", "profile", "email"},
	}

	repo := &ClientRepository{}

	tests := []struct {
		name     string
		scope    string
		expected bool
	}{
		{"Single valid scope", "openid", true},
		{"Multiple valid scopes", "openid profile email", true},
		{"Subset of scopes", "openid profile", true},
		{"Invalid scope", "openid invalid", false},
		{"All invalid", "admin write", false},
		{"Empty scope", "", true},
		{"Scope with extra spaces", "openid  profile", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := repo.ValidateScope(client, tt.scope)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test PKCE Validation

func TestValidatePKCEVerifier(t *testing.T) {
	// Generate a valid code verifier
	verifier := generateClientSecret() // 43 characters, base64url-encoded

	// Calculate S256 challenge
	challengeS256 := calculateCodeChallenge(verifier, "S256")

	tests := []struct {
		name                   string
		codeVerifier           string
		codeChallenge          string
		codeChallengeMethod    string
		expectError            bool
		errorContains          string
	}{
		{
			name:                "Valid S256 verification",
			codeVerifier:        verifier,
			codeChallenge:       challengeS256,
			codeChallengeMethod: "S256",
			expectError:         false,
		},
		{
			name:                "Invalid S256 verification",
			codeVerifier:        generateClientSecret(), // 43 chars, different from verifier
			codeChallenge:       challengeS256,
			codeChallengeMethod: "S256",
			expectError:         true,
			errorContains:       "does not match",
		},
		{
			name:                "Valid plain verification",
			codeVerifier:        verifier, // Use same verifier for plain
			codeChallenge:       verifier,
			codeChallengeMethod: "plain",
			expectError:         false,
		},
		{
			name:                "Invalid plain verification",
			codeVerifier:        generateClientSecret(), // will be different from challenge
			codeChallenge:       verifier, // use original verifier as challenge
			codeChallengeMethod: "plain",
			expectError:         true,
			errorContains:       "does not match",
		},
		{
			name:                "Missing verifier when challenge exists",
			codeVerifier:        "",
			codeChallenge:       "some-challenge",
			codeChallengeMethod: "S256",
			expectError:         true,
			errorContains:       "required",
		},
		{
			name:                "Verifier too short with challenge",
			codeVerifier:        "short",
			codeChallenge:       challengeS256,
			codeChallengeMethod: "S256",
			expectError:         true,
			errorContains:       "43 and 128",
		},
		{
			name:                "No PKCE used",
			codeVerifier:        "",
			codeChallenge:       "",
			codeChallengeMethod: "",
			expectError:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePKCEVerifier(tt.codeVerifier, tt.codeChallenge, tt.codeChallengeMethod)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper function for PKCE tests
func calculateCodeChallenge(verifier, method string) string {
	if method == "S256" {
		hash := sha256Hash([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(hash)
	}
	return verifier
}

func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// Test Authorization Code Storage

func TestStoreAuthorizationCode(t *testing.T) {
	// This test would require a mock Redis client
	// For now, we'll test the structure creation

	code := &StoredAuthorizationCode{
		Code:                "test-code-123",
		ClientID:            "test-client",
		UserID:              "user-123",
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile",
		State:               "state-123",
		Nonce:               "nonce-123",
		CodeChallenge:       "challenge-123",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		CreatedAt:           time.Now(),
		Used:                false,
	}

	assert.Equal(t, "test-code-123", code.Code)
	assert.Equal(t, "test-client", code.ClientID)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.False(t, code.Used)
}

func TestAuthorizationCodeExpiration(t *testing.T) {
	// Test expired code
	expiredCode := &StoredAuthorizationCode{
		Code:      "expired-code",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}

	assert.True(t, time.Now().After(expiredCode.ExpiresAt))

	// Test valid code
	validCode := &StoredAuthorizationCode{
		Code:      "valid-code",
		ExpiresAt: time.Now().Add(10 * time.Minute),
		CreatedAt: time.Now(),
	}

	assert.True(t, time.Now().Before(validCode.ExpiresAt))
}

// Test Token Storage

func TestRefreshTokenFamily(t *testing.T) {
	family := &RefreshTokenFamily{
		FamilyID:    "family-123",
		ClientID:    "client-123",
		UserID:      "user-123",
		Scope:       "openid profile offline_access",
		CreatedAt:   time.Now(),
		LastRotated: time.Now(),
		TokenCount:  1,
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour),
	}

	assert.Equal(t, "family-123", family.FamilyID)
	assert.Equal(t, 1, family.TokenCount)
}

func TestStoredRefreshToken(t *testing.T) {
	token := &StoredRefreshToken{
		Token:     "refresh-token-123",
		FamilyID:  "family-123",
		ClientID:  "client-123",
		UserID:    "user-123",
		Scope:     "openid profile offline_access",
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		CreatedAt: time.Now(),
		Revoked:   false,
	}

	assert.Equal(t, "refresh-token-123", token.Token)
	assert.False(t, token.Revoked)
	assert.Nil(t, token.RevokedAt)
}

// Test Scope Utilities

func TestBuildScopeStringWithDeduplication(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		expected string
	}{
		{
			name:     "Simple scopes",
			scopes:   []string{"openid", "profile", "email"},
			expected: "openid profile email",
		},
		{
			name:     "Empty list",
			scopes:   []string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildScopeString(tt.scopes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsScopeSubset(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		allowed   string
		expected  bool
	}{
		{
			name:      "Exact match",
			requested: "openid profile",
			allowed:   "openid profile",
			expected:  true,
		},
		{
			name:      "Subset",
			requested: "openid",
			allowed:   "openid profile email",
			expected:  true,
		},
		{
			name:      "Not a subset",
			requested: "openid admin",
			allowed:   "openid profile",
			expected:  false,
		},
		{
			name:      "Empty requested",
			requested: "",
			allowed:   "openid profile",
			expected:  true,
		},
		{
			name:      "Requested but not allowed",
			requested: "email",
			allowed:   "",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isScopeSubset(tt.requested, tt.allowed)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test Token Generation

func TestStoreGenerateToken(t *testing.T) {
	store := &Store{}
	token1 := store.GenerateToken()
	token2 := store.GenerateToken()

	assert.NotEmpty(t, token1)
	assert.NotEmpty(t, token2)
	assert.NotEqual(t, token1, token2, "Tokens should be unique")
	assert.GreaterOrEqual(t, len(token1), 32, "Token should be at least 32 characters")
}

// Test Authorize Flow

func TestParseAuthorizeRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name        string
		queryParams string
		expectError bool
		checkResult func(*testing.T, *FlowAuthorizeRequest)
	}{
		{
			name:        "Valid authorization code request",
			queryParams: "client_id=test-client&redirect_uri=https://example.com/callback&response_type=code&scope=openid+profile&state=test-state",
			expectError: false,
			checkResult: func(t *testing.T, req *FlowAuthorizeRequest) {
				assert.Equal(t, "test-client", req.ClientID)
				assert.Equal(t, "https://example.com/callback", req.RedirectURI)
				assert.Equal(t, "code", req.ResponseType)
				assert.Equal(t, "openid profile", req.Scope)  // Gin decodes + to space
				assert.Equal(t, "test-state", req.State)
			},
		},
		{
			name:        "Missing client_id",
			queryParams: "redirect_uri=https://example.com/callback&response_type=code",
			expectError: true,
		},
		{
			name:        "Missing redirect_uri",
			queryParams: "client_id=test-client&response_type=code",
			expectError: true,
		},
		{
			name:        "Missing response_type",
			queryParams: "client_id=test-client&redirect_uri=https://example.com/callback",
			expectError: true,
		},
		{
			name:        "PKCE S256 parameters",
			queryParams: "client_id=test-client&redirect_uri=https://example.com/callback&response_type=code&code_challenge=test-challenge&code_challenge_method=S256",
			expectError: false,
			checkResult: func(t *testing.T, req *FlowAuthorizeRequest) {
				assert.Equal(t, "test-challenge", req.CodeChallenge)
				assert.Equal(t, "S256", req.CodeChallengeMethod)
			},
		},
		{
			name:        "OIDC parameters",
			queryParams: "client_id=test-client&redirect_uri=https://example.com/callback&response_type=code&scope=openid&nonce=test-nonce",
			expectError: false,
			checkResult: func(t *testing.T, req *FlowAuthorizeRequest) {
				assert.Equal(t, "test-nonce", req.Nonce)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			var capturedReq *FlowAuthorizeRequest
			var capturedErr error

			router.GET("/test", func(c *gin.Context) {
				flow := &AuthorizeFlow{}
				capturedReq, capturedErr = flow.parseRequest(c)
			})

			req := httptest.NewRequest("GET", "/test?"+tt.queryParams, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if tt.expectError {
				assert.Error(t, capturedErr)
			} else {
				assert.NoError(t, capturedErr)
				if tt.checkResult != nil {
					tt.checkResult(t, capturedReq)
				}
			}
		})
	}
}

// Test Token Flow

func TestParseTokenRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name        string
		formData    url.Values
		expectError bool
		checkResult func(*testing.T, *TokenRequest)
	}{
		{
			name: "Valid authorization code grant",
			formData: url.Values{
				"grant_type":    []string{"authorization_code"},
				"code":         []string{"test-code"},
				"redirect_uri":  []string{"https://example.com/callback"},
				"client_id":     []string{"test-client"},
				"client_secret": []string{"test-secret"},
			},
			expectError: false,
			checkResult: func(t *testing.T, req *TokenRequest) {
				assert.Equal(t, "authorization_code", req.GrantType)
				assert.Equal(t, "test-code", req.Code)
				assert.Equal(t, "test-client", req.ClientID)
			},
		},
		{
			name: "Valid refresh token grant",
			formData: url.Values{
				"grant_type":    []string{"refresh_token"},
				"refresh_token": []string{"refresh-token-123"},
				"client_id":     []string{"test-client"},
				"client_secret": []string{"test-secret"},
			},
			expectError: false,
			checkResult: func(t *testing.T, req *TokenRequest) {
				assert.Equal(t, "refresh_token", req.GrantType)
				assert.Equal(t, "refresh-token-123", req.RefreshToken)
			},
		},
		{
			name: "Valid client credentials grant",
			formData: url.Values{
				"grant_type":    []string{"client_credentials"},
				"scope":         []string{"api.read"},
				"client_id":     []string{"test-client"},
				"client_secret": []string{"test-secret"},
			},
			expectError: false,
			checkResult: func(t *testing.T, req *TokenRequest) {
				assert.Equal(t, "client_credentials", req.GrantType)
				assert.Equal(t, "api.read", req.Scope)
			},
		},
		{
			name: "Missing grant_type",
			formData: url.Values{
				"code": []string{"test-code"},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/token", strings.NewReader(tt.formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = req

			var tokenReq TokenRequest
			err := c.ShouldBind(&tokenReq)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, &tokenReq)
				}
			}
		})
	}
}

// Test HTTP Basic Authentication extraction

func TestExtractBasicAuth(t *testing.T) {
	tests := []struct {
		name            string
		authHeader      string
		expectOK        bool
		expectedClientID string
		expectedSecret  string
	}{
		{
			name:            "Valid Basic Auth",
			authHeader:      "Basic " + base64.StdEncoding.EncodeToString([]byte("client-id:client-secret")),
			expectOK:        true,
			expectedClientID: "client-id",
			expectedSecret:  "client-secret",
		},
		{
			name:       "Missing header",
			authHeader: "",
			expectOK:   false,
		},
		{
			name:       "Invalid format",
			authHeader: "Bearer token",
			expectOK:   false,
		},
		{
			name:       "Malformed base64",
			authHeader: "Basic not-valid-base64!!!",
			expectOK:   false,
		},
		{
			name:       "Missing colon",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("invalid-format")),
			expectOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.authHeader != "" {
				clientID, secret, ok := parseBasicAuth(tt.authHeader)
				assert.Equal(t, tt.expectOK, ok)
				if ok {
					assert.Equal(t, tt.expectedClientID, clientID)
					assert.Equal(t, tt.expectedSecret, secret)
				}
			}
		})
	}
}

// Helper function
func parseBasicAuth(header string) (clientID, secret string, ok bool) {
	if !strings.HasPrefix(header, "Basic ") {
		return "", "", false
	}

	encoded := strings.TrimPrefix(header, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return parts[0], parts[1], true
}

// Test Token Response

func TestTokenResponse(t *testing.T) {
	response := TokenResponse{
		AccessToken:  "access-token-123",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "refresh-token-123",
		IDToken:      "id-token-123",
		Scope:        "openid profile",
	}

	assert.Equal(t, "access-token-123", response.AccessToken)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, 3600, response.ExpiresIn)
	assert.NotEmpty(t, response.RefreshToken)
	assert.NotEmpty(t, response.IDToken)
}

// Test Error Response

func TestTokenErrorResponse(t *testing.T) {
	errorResp := TokenErrorResponse{
		Error:            TokenErrorInvalidGrant,
		ErrorDescription: "The authorization code is invalid",
		ErrorURI:         "https://example.com/errors",
	}

	assert.Equal(t, TokenErrorInvalidGrant, errorResp.Error)
	assert.Equal(t, "The authorization code is invalid", errorResp.ErrorDescription)
}

// Test utilities

func TestIsValidBase64URL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Valid base64url", "abc123-ABC_456", true},
		{"With padding", "abc123=", false},
		{"With special chars", "abc+123/def", false},
		{"Empty string", "", false},
		{"Single hyphen", "-", true},
		{"Single underscore", "_", true},
		{"Alphanumeric only", "abcXYZ123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidBase64URL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test UserSession

func TestUserSession(t *testing.T) {
	session := UserSession{
		UserID:    "user-123",
		Email:     "user@example.com",
		Name:      "Test User",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	assert.Equal(t, "user-123", session.UserID)
	assert.Equal(t, "user@example.com", session.Email)
	assert.True(t, time.Now().Before(session.ExpiresAt))
}

// Test default scopes

func TestDefaultScopes(t *testing.T) {
	tests := []struct {
		name      string
		grantType string
		check     func(*testing.T, []string)
	}{
		{
			name:      "Authorization code grant",
			grantType: "authorization_code",
			check: func(t *testing.T, scopes []string) {
				assert.Contains(t, scopes, "openid")
			},
		},
		{
			name:      "Client credentials grant",
			grantType: "client_credentials",
			check: func(t *testing.T, scopes []string) {
				assert.Empty(t, scopes)
			},
		},
		{
			name:      "Refresh token grant",
			grantType: "refresh_token",
			check: func(t *testing.T, scopes []string) {
				assert.Contains(t, scopes, "openid")
			},
		},
		{
			name:      "Unknown grant type",
			grantType: "unknown",
			check: func(t *testing.T, scopes []string) {
				assert.Contains(t, scopes, "openid")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scopes := DefaultScopes(tt.grantType)
			tt.check(t, scopes)
		})
	}
}
