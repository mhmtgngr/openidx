// Package oauth provides unit tests for OIDC functionality
package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/internal/identity"
)

// Test OIDC Provider ID Token Generation

func TestGenerateIDToken(t *testing.T) {
	key := generateTestRSAKey(t)
	logger := testLogger()

	// Create a mock service
	service := &Service{
		privateKey: key,
		publicKey:  &key.PublicKey,
		issuer:     "https://test.openidx.org",
	}

	// Create a mock identity service with test user
	identitySvc := createMockIdentityService(t)

	provider := NewOIDCProvider(service, identitySvc, logger, "https://test.openidx.org")

	tests := []struct {
		name       string
		req        *IDTokenRequest
		validateFn func(*testing.T, string, *IDTokenRequest)
		expectErr  bool
		errCheck   func(*testing.T, error)
	}{
		{
			name: "Valid ID token with openid scope",
			req: &IDTokenRequest{
				UserID:    "test-user-123",
				ClientID:  "test-client-abc",
				Scope:     "openid",
				ExpiresIn: 3600,
				Nonce:     "test-nonce-123",
			},
			validateFn: func(t *testing.T, token string, req *IDTokenRequest) {
				// Parse the token
				parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
					return &key.PublicKey, nil
				})
				require.NoError(t, err)
				require.True(t, parsedToken.Valid)

				// Check claims
				claims, ok := parsedToken.Claims.(jwt.MapClaims)
				require.True(t, ok)

				// Verify required claims per OIDC spec
				assert.Equal(t, "https://test.openidx.org", claims["iss"])
				assert.NotEmpty(t, claims["sub"])
				assert.Equal(t, req.ClientID, claims["aud"])
				assert.NotEmpty(t, claims["exp"])
				assert.NotEmpty(t, claims["iat"])
				assert.NotEmpty(t, claims["auth_time"])
				assert.Equal(t, req.Nonce, claims["nonce"])

				// Verify JWT header has kid
				headerBytes, _ := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
				var headerMap map[string]interface{}
				json.Unmarshal(headerBytes, &headerMap)
				assert.Equal(t, "openidx-key-1", headerMap["kid"])
			},
			expectErr: false,
		},
		{
			name: "ID token with profile scope",
			req: &IDTokenRequest{
				UserID:    "test-user-123",
				ClientID:  "test-client-abc",
				Scope:     "openid profile",
				ExpiresIn: 3600,
			},
			validateFn: func(t *testing.T, token string, req *IDTokenRequest) {
				parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
					return &key.PublicKey, nil
				})
				require.NoError(t, err)

				claims, ok := parsedToken.Claims.(jwt.MapClaims)
				require.True(t, ok)

				// Verify profile claims
				assert.NotEmpty(t, claims["name"], "name claim should be present")
				assert.NotEmpty(t, claims["preferred_username"], "preferred_username should be present")
			},
			expectErr: false,
		},
		{
			name: "ID token with email scope",
			req: &IDTokenRequest{
				UserID:    "test-user-123",
				ClientID:  "test-client-abc",
				Scope:     "openid email",
				ExpiresIn: 3600,
			},
			validateFn: func(t *testing.T, token string, req *IDTokenRequest) {
				parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
					return &key.PublicKey, nil
				})
				require.NoError(t, err)

				claims, ok := parsedToken.Claims.(jwt.MapClaims)
				require.True(t, ok)

				// Verify email claims
				assert.NotEmpty(t, claims["email"], "email claim should be present")
				assert.True(t, claims["email_verified"] != nil, "email_verified should be present")
			},
			expectErr: false,
		},
		{
			name: "ID token with at_hash",
			req: &IDTokenRequest{
				UserID:      "test-user-123",
				ClientID:    "test-client-abc",
				Scope:       "openid",
				ExpiresIn:   3600,
				AccessToken: "test-access-token-1234567890",
			},
			validateFn: func(t *testing.T, token string, req *IDTokenRequest) {
				parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
					return &key.PublicKey, nil
				})
				require.NoError(t, err)

				claims, ok := parsedToken.Claims.(jwt.MapClaims)
				require.True(t, ok)

				// Verify at_hash is present and valid
				assert.NotEmpty(t, claims["at_hash"], "at_hash should be present")
			},
			expectErr: false,
		},
		{
			name: "ID token with c_hash",
			req: &IDTokenRequest{
				UserID:    "test-user-123",
				ClientID:  "test-client-abc",
				Scope:     "openid",
				ExpiresIn: 3600,
				Code:      "test-auth-code-1234567890",
			},
			validateFn: func(t *testing.T, token string, req *IDTokenRequest) {
				parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
					return &key.PublicKey, nil
				})
				require.NoError(t, err)

				claims, ok := parsedToken.Claims.(jwt.MapClaims)
				require.True(t, ok)

				// Verify c_hash is present
				assert.NotEmpty(t, claims["c_hash"], "c_hash should be present")
			},
			expectErr: false,
		},
		{
			name: "ID token with session ID",
			req: &IDTokenRequest{
				UserID:    "test-user-123",
				ClientID:  "test-client-abc",
				Scope:     "openid",
				ExpiresIn: 3600,
				SessionID: "session-abc-123",
			},
			validateFn: func(t *testing.T, token string, req *IDTokenRequest) {
				parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
					return &key.PublicKey, nil
				})
				require.NoError(t, err)

				claims, ok := parsedToken.Claims.(jwt.MapClaims)
				require.True(t, ok)

				// Verify session ID
				assert.Equal(t, req.SessionID, claims["sid"], "sid should match session ID")
			},
			expectErr: false,
		},
		{
			name: "Missing openid scope returns error",
			req: &IDTokenRequest{
				UserID:    "test-user-123",
				ClientID:  "test-client-abc",
				Scope:     "profile email",
				ExpiresIn: 3600,
			},
			expectErr: true,
			errCheck: func(t *testing.T, err error) {
				assert.Equal(t, ErrScopeMissingOpenID, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idToken, err := provider.GenerateIDToken(context.Background(), tt.req)

			if tt.expectErr {
				assert.Error(t, err)
				if tt.errCheck != nil {
					tt.errCheck(t, err)
				}
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, idToken)

			// Verify JWT structure (header.payload.signature)
			parts := strings.Split(idToken, ".")
			assert.Len(t, parts, 3, "ID token should have 3 parts")

			if tt.validateFn != nil {
				tt.validateFn(t, idToken, tt.req)
			}
		})
	}
}

// Test hashHalf function

func TestHashHalf(t *testing.T) {
	key := generateTestRSAKey(t)
	logger := testLogger()
	service := &Service{privateKey: key, issuer: "https://test.openidx.org"}
	identitySvc := createMockIdentityService(t)
	provider := NewOIDCProvider(service, identitySvc, logger, "https://test.openidx.org")

	tests := []struct {
		name  string
		data  string
		check func(*testing.T, string)
	}{
		{
			name: "Hash of access token",
			data: "test-access-token-1234567890",
			check: func(t *testing.T, hash string) {
				// Hash should be base64url-encoded
				_, err := base64.RawURLEncoding.DecodeString(hash)
				assert.NoError(t, err)
				// Hash should be half of SHA-256 output (128 bits = 16 bytes = ~22 chars in base64url)
				assert.LessOrEqual(t, len(hash), 24)
				assert.GreaterOrEqual(t, len(hash), 20)
			},
		},
		{
			name: "Hash of authorization code",
			data: "test-auth-code-1234567890",
			check: func(t *testing.T, hash string) {
				_, err := base64.RawURLEncoding.DecodeString(hash)
				assert.NoError(t, err)
			},
		},
		{
			name: "Consistent hashing",
			data: "consistent-data-123",
			check: func(t *testing.T, hash string) {
				// Hash same data twice, should get same result
				hash2 := provider.hashHalf("consistent-data-123")
				assert.Equal(t, hash, hash2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.hashHalf(tt.data)
			assert.NotEmpty(t, result)
			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

// Test UserInfo endpoint

func TestGetUserInfo(t *testing.T) {
	t.Skip("Test requires mock store setup - needs refactoring")
	/*
	key := generateTestRSAKey(t)
	logger := testLogger()

	// Create a mock service with store
	service := &Service{
		privateKey: key,
		issuer:     "https://test.openidx.org",
	}
	identitySvc := createMockIdentityService(t)

	provider := NewOIDCProvider(service, identitySvc, logger, "https://test.openidx.org")

	// Mock the store to return a valid access token
	// TODO: Need to set up mock redis for this test

	tests := []struct {
		name       string
		req        *UserInfoRequest
		validateFn func(*testing.T, *UserInfoResponse)
		expectErr  bool
	}{
		{
			name: "Valid UserInfo with profile scope",
			req: &UserInfoRequest{
				AccessToken: "test-access-token",
				Scope:       "openid profile",
			},
			validateFn: func(t *testing.T, info *UserInfoResponse) {
				assert.NotEmpty(t, info.Sub, "sub is required")
				assert.NotEmpty(t, info.Name, "name should be present with profile scope")
				assert.NotEmpty(t, info.PreferredUsername, "preferred_username should be present")
			},
			expectErr: false,
		},
		{
			name: "Valid UserInfo with email scope",
			req: &UserInfoRequest{
				AccessToken: "test-access-token",
				Scope:       "openid email",
			},
			validateFn: func(t *testing.T, info *UserInfoResponse) {
				assert.NotEmpty(t, info.Sub)
				assert.NotEmpty(t, info.Email, "email should be present with email scope")
			},
			expectErr: false,
		},
		{
			name: "Valid UserInfo with all scopes",
			req: &UserInfoRequest{
				AccessToken: "test-access-token",
				Scope:       "openid profile email phone address",
			},
			validateFn: func(t *testing.T, info *UserInfoResponse) {
				assert.NotEmpty(t, info.Sub)
				assert.NotEmpty(t, info.Name)
				assert.NotEmpty(t, info.Email)
			},
			expectErr: false,
		},
		{
			name: "Empty access token",
			req: &UserInfoRequest{
				AccessToken: "",
			},
			expectErr: true,
		},
		{
			name: "Invalid access token",
			req: &UserInfoRequest{
				AccessToken: "invalid-token",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userInfo, err := provider.GetUserInfo(context.Background(), tt.req)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, userInfo)

			if tt.validateFn != nil {
				tt.validateFn(t, userInfo)
			}
		})
	}
	*/
}

// Test ExtractBearerToken

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name      string
		authHeader string
		expectErr bool
		checkToken func(*testing.T, string)
	}{
		{
			name:       "Valid Bearer token",
			authHeader: "Bearer test-token-1234567890",
			expectErr:  false,
			checkToken: func(t *testing.T, token string) {
				assert.Equal(t, "test-token-1234567890", token)
			},
		},
		{
			name:       "Bearer token with spaces",
			authHeader: "Bearer   spaced-token-123",
			expectErr:  false,
			checkToken: func(t *testing.T, token string) {
				assert.Equal(t, "spaced-token-123", token)
			},
		},
		{
			name:       "Empty Authorization header",
			authHeader: "",
			expectErr:  true,
		},
		{
			name:       "Missing Bearer prefix",
			authHeader: "test-token-123",
			expectErr:  true,
		},
		{
			name:       "Wrong authentication type",
			authHeader: "Basic dGVzdDp0ZXN0",
			expectErr:  true,
		},
		{
			name:       "Bearer with empty token",
			authHeader: "Bearer ",
			expectErr:  true,
		},
		{
			name:       "Bearer with only whitespace",
			authHeader: "Bearer    ",
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := ExtractBearerToken(tt.authHeader)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.checkToken != nil {
				tt.checkToken(t, token)
			}
		})
	}
}

// Mock implementations

// mockIdentityService is a minimal mock for testing
type mockIdentityService struct {
	users map[string]*identity.User
}

func createMockIdentityService(t *testing.T) *mockIdentityService {
	return &mockIdentityService{
		users: map[string]*identity.User{
			"test-user-123": {
				ID:          "test-user-123",
				UserName:    "testuser",
				DisplayName: stringPtr("Test User"),
				Name: &identity.Name{
					GivenName:  stringPtr("Test"),
					FamilyName: stringPtr("User"),
				},
				Emails: []identity.Email{
					{Value: "test@example.com", Primary: boolPtr(true), Verified: boolPtr(true)},
				},
				Roles:    []string{"user", "admin"},
				Groups:   []string{"developers", "testers"},
				EmailVerified: true,
			},
		},
	}
}

func (m *mockIdentityService) GetUser(ctx context.Context, id string) (*identity.User, error) {
	user, ok := m.users[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	return user, nil
}

// Mock Store for testing

type mockStore struct {
	accessTokenData *AccessTokenData
}

func (s *mockStore) GetAccessToken(ctx context.Context, token string) (*AccessTokenData, error) {
	if s.accessTokenData != nil && s.accessTokenData.Token == token {
		return s.accessTokenData, nil
	}
	if token == "test-access-token" && s.accessTokenData != nil {
		return s.accessTokenData, nil
	}
	return nil, ErrInvalidAccessToken
}

// Helper functions

func stringPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}
