package access

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- hashToken ----

func TestHashToken_Deterministic(t *testing.T) {
	token := "test-session-token-12345"
	hash1 := hashToken(token)
	hash2 := hashToken(token)
	assert.Equal(t, hash1, hash2)
}

func TestHashToken_Unique(t *testing.T) {
	hash1 := hashToken("token-a")
	hash2 := hashToken("token-b")
	assert.NotEqual(t, hash1, hash2)
}

func TestHashToken_NotEmpty(t *testing.T) {
	hash := hashToken("any-token")
	assert.NotEmpty(t, hash)
	assert.Len(t, hash, 64) // SHA-256 hex = 64 chars
}

// ---- hasAnyRole ----

func TestHasAnyRole_MatchFound(t *testing.T) {
	assert.True(t, hasAnyRole([]string{"admin", "user"}, []string{"admin"}))
	assert.True(t, hasAnyRole([]string{"admin", "user"}, []string{"viewer", "user"}))
}

func TestHasAnyRole_NoMatch(t *testing.T) {
	assert.False(t, hasAnyRole([]string{"user"}, []string{"admin", "super_admin"}))
}

func TestHasAnyRole_EmptyUserRoles(t *testing.T) {
	assert.False(t, hasAnyRole([]string{}, []string{"admin"}))
}

func TestHasAnyRole_EmptyRequiredRoles(t *testing.T) {
	assert.False(t, hasAnyRole([]string{"admin"}, []string{}))
}

func TestHasAnyRole_BothEmpty(t *testing.T) {
	assert.False(t, hasAnyRole([]string{}, []string{}))
}

func TestHasAnyRole_NilSlices(t *testing.T) {
	assert.False(t, hasAnyRole(nil, nil))
	assert.False(t, hasAnyRole(nil, []string{"admin"}))
	assert.False(t, hasAnyRole([]string{"admin"}, nil))
}

// ---- singleJoiningSlash ----

func TestSingleJoiningSlash(t *testing.T) {
	tests := []struct {
		name     string
		a, b     string
		expected string
	}{
		{"both have slash", "http://host/", "/path", "http://host/path"},
		{"neither has slash", "http://host", "path", "http://host/path"},
		{"only a has slash", "http://host/", "path", "http://host/path"},
		{"only b has slash", "http://host", "/path", "http://host/path"},
		{"empty b", "http://host/", "", "http://host/"},
		{"empty a", "", "/path", "/path"},
		{"both empty", "", "", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, singleJoiningSlash(tt.a, tt.b))
		})
	}
}

// ---- generate functions uniqueness ----

func TestGenerateCodeVerifier_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		v := generateCodeVerifier()
		require.False(t, seen[v], "duplicate verifier generated")
		seen[v] = true
	}
}

func TestGenerateCodeVerifier_NotEmpty(t *testing.T) {
	v := generateCodeVerifier()
	assert.NotEmpty(t, v)
	assert.Greater(t, len(v), 20)
}

func TestGenerateCodeChallenge_Deterministic(t *testing.T) {
	verifier := generateCodeVerifier()
	c1 := generateCodeChallenge(verifier)
	c2 := generateCodeChallenge(verifier)
	assert.Equal(t, c1, c2)
}

func TestGenerateCodeChallenge_DifferentVerifiers(t *testing.T) {
	v1 := generateCodeVerifier()
	v2 := generateCodeVerifier()
	assert.NotEqual(t, generateCodeChallenge(v1), generateCodeChallenge(v2))
}

func TestGenerateState_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s := generateState()
		require.False(t, seen[s], "duplicate state generated")
		seen[s] = true
	}
}

func TestGenerateState_HexEncoded(t *testing.T) {
	s := generateState()
	assert.Len(t, s, 32) // 16 bytes = 32 hex chars
}

func TestGenerateSessionToken_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		tok := generateSessionToken()
		require.False(t, seen[tok], "duplicate session token generated")
		seen[tok] = true
	}
}

func TestGenerateSessionToken_NotEmpty(t *testing.T) {
	tok := generateSessionToken()
	assert.NotEmpty(t, tok)
	assert.Greater(t, len(tok), 20)
}

// ---- ProxyRoute model ----

func TestProxyRoute_Defaults(t *testing.T) {
	r := ProxyRoute{}
	assert.False(t, r.RequireAuth)
	assert.False(t, r.ZitiEnabled)
	assert.False(t, r.RequireDeviceTrust)
	assert.Equal(t, 0, r.MaxRiskScore)
	assert.Empty(t, r.AllowedRoles)
	assert.Empty(t, r.AllowedCountries)
}

func TestProxyRoute_Construction(t *testing.T) {
	r := ProxyRoute{
		ID:               "route-1",
		Name:             "test",
		FromURL:          "https://app.example.com",
		ToURL:            "http://localhost:8080",
		RequireAuth:      true,
		AllowedRoles:     []string{"admin"},
		AllowedCountries: []string{"US", "GB"},
		MaxRiskScore:     80,
		InlinePolicy:     `device.trusted == true`,
	}
	assert.Equal(t, "route-1", r.ID)
	assert.True(t, r.RequireAuth)
	assert.Equal(t, 2, len(r.AllowedCountries))
	assert.Equal(t, 80, r.MaxRiskScore)
}

// ---- ProxySession model ----

func TestProxySession_Construction(t *testing.T) {
	s := ProxySession{
		ID:            "sess-1",
		UserID:        "user-1",
		Email:         "test@example.com",
		Roles:         []string{"user", "editor"},
		DeviceTrusted: true,
		RiskScore:     25,
	}
	assert.Equal(t, "sess-1", s.ID)
	assert.Equal(t, 2, len(s.Roles))
	assert.True(t, s.DeviceTrusted)
}
