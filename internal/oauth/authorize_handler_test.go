package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// The pure functions in authorize.go (GenerateAuthorizationCode, ValidatePKCE,
// isValidPKCEChar, constantTimeStringCompare, BuildRedirectURI) are already
// covered by service_extended_test.go. The methods on *AuthorizeHandler
// itself are not — every method on lines 158..236 of authorize.go reports
// 0% coverage. This file fills that gap: each test reaches one validator
// without bringing up a Service / Redis / DB.

// newTestAuthorizeHandler returns an AuthorizeHandler bound to a stub Service.
// The pure-validation methods we exercise do not touch the embedded service.
func newTestAuthorizeHandler(t *testing.T) *AuthorizeHandler {
	t.Helper()
	return &AuthorizeHandler{
		service: &Service{},
		logger:  zap.NewNop(),
	}
}

// TestAuthorizeHandler_ValidateRedirectURI covers the exact-match
// registration check. No URI normalization on purpose — the OAuth spec
// requires byte equality with the registered redirect_uri.
func TestAuthorizeHandler_ValidateRedirectURI(t *testing.T) {
	h := newTestAuthorizeHandler(t)
	client := &OAuthClient{
		RedirectURIs: []string{"https://a.example/cb", "https://b.example/cb"},
	}

	if !h.validateRedirectURI(client, "https://a.example/cb") {
		t.Error("registered URI rejected")
	}
	if !h.validateRedirectURI(client, "https://b.example/cb") {
		t.Error("second registered URI rejected")
	}
	if h.validateRedirectURI(client, "https://a.example/cb/") {
		t.Error("trailing-slash variant accepted (must be byte-exact)")
	}
	if h.validateRedirectURI(client, "https://attacker.example/cb") {
		t.Error("unregistered URI accepted")
	}
	if h.validateRedirectURI(client, "") {
		t.Error("empty URI accepted")
	}
}

// TestAuthorizeHandler_ValidateResponseType verifies the per-client
// response_types whitelist used to enforce code-flow / implicit-flow opt-ins.
func TestAuthorizeHandler_ValidateResponseType(t *testing.T) {
	h := newTestAuthorizeHandler(t)
	client := &OAuthClient{ResponseTypes: []string{"code", "id_token"}}
	if !h.validateResponseType(client, "code") {
		t.Error("code rejected")
	}
	if !h.validateResponseType(client, "id_token") {
		t.Error("id_token rejected")
	}
	if h.validateResponseType(client, "token") {
		t.Error("implicit-flow token accepted but not in whitelist")
	}
	if h.validateResponseType(client, "") {
		t.Error("empty response_type accepted")
	}
}

// TestAuthorizeHandler_ValidateScope verifies the scope check: empty scope
// is allowed, all requested scopes must be in the client's allow-list, and
// multi-scope strings split on spaces.
func TestAuthorizeHandler_ValidateScope(t *testing.T) {
	h := newTestAuthorizeHandler(t)
	client := &OAuthClient{Scopes: []string{"openid", "profile", "email"}}

	if !h.validateScope(client, "") {
		t.Error("empty scope should be allowed")
	}
	if !h.validateScope(client, "openid") {
		t.Error("single allowed scope rejected")
	}
	if !h.validateScope(client, "openid profile email") {
		t.Error("multi allowed scopes rejected")
	}
	if h.validateScope(client, "openid admin") {
		t.Error("scope outside whitelist accepted")
	}
	// Double-space tokens come back as "" which the validator skips.
	if !h.validateScope(client, "openid  profile") {
		t.Error("double-spaced scopes rejected")
	}
}

// TestAuthorizeHandler_ValidatePKCEParameters covers the per-client PKCE
// policy: public clients MUST present a code_challenge; the method must be
// S256 or plain; the challenge must be base64url-decodable and 43..128 bytes
// long.
func TestAuthorizeHandler_ValidatePKCEParameters(t *testing.T) {
	h := newTestAuthorizeHandler(t)

	public := &OAuthClient{Type: "public"}
	confidential := &OAuthClient{Type: "confidential"}

	// Build a 64-byte verifier and its S256 challenge once.
	const v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk_test_verifier_pad_ab"
	sum := sha256.Sum256([]byte(v))
	chall := base64.RawURLEncoding.EncodeToString(sum[:])

	t.Run("public without challenge rejected", func(t *testing.T) {
		req := &AuthorizeRequest{}
		if err := h.validatePKCEParameters(public, req); err == nil {
			t.Error("public client without code_challenge accepted")
		}
	})
	t.Run("confidential without PKCE allowed", func(t *testing.T) {
		req := &AuthorizeRequest{}
		if err := h.validatePKCEParameters(confidential, req); err != nil {
			t.Errorf("confidential client without PKCE rejected: %v", err)
		}
	})
	t.Run("valid S256 challenge", func(t *testing.T) {
		req := &AuthorizeRequest{CodeChallenge: chall, CodeChallengeMethod: "S256"}
		if err := h.validatePKCEParameters(public, req); err != nil {
			t.Errorf("valid S256 challenge rejected: %v", err)
		}
	})
	t.Run("unsupported challenge method", func(t *testing.T) {
		req := &AuthorizeRequest{CodeChallenge: chall, CodeChallengeMethod: "MD5"}
		if err := h.validatePKCEParameters(public, req); err == nil {
			t.Error("MD5 method accepted")
		}
	})
	t.Run("non-base64url challenge rejected", func(t *testing.T) {
		req := &AuthorizeRequest{
			CodeChallenge:       strings.Repeat("!", 50),
			CodeChallengeMethod: "S256",
		}
		if err := h.validatePKCEParameters(public, req); err == nil {
			t.Error("non-base64url challenge accepted")
		}
	})
	t.Run("challenge too short", func(t *testing.T) {
		req := &AuthorizeRequest{
			CodeChallenge:       strings.Repeat("a", 10),
			CodeChallengeMethod: "S256",
		}
		if err := h.validatePKCEParameters(public, req); err == nil {
			t.Error("too-short challenge accepted")
		}
	})
}

// TestAuthorizeHandler_ParseAuthorizeRequest covers parameter extraction +
// the required-field gate. Uses gin's test-mode router so we don't bind to
// a port.
func TestAuthorizeHandler_ParseAuthorizeRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := newTestAuthorizeHandler(t)

	mkCtx := func(rawQuery string) *gin.Context {
		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+rawQuery, nil)
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = req
		return c
	}

	t.Run("all required fields parsed", func(t *testing.T) {
		c := mkCtx("client_id=cid&redirect_uri=https%3A%2F%2Fa%2Fcb&response_type=code&" +
			"scope=openid+profile&state=xyz&nonce=n0&code_challenge=ch&code_challenge_method=S256")
		got, err := h.parseAuthorizeRequest(c)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if got.ClientID != "cid" {
			t.Errorf("ClientID = %q", got.ClientID)
		}
		if got.RedirectURI != "https://a/cb" {
			t.Errorf("RedirectURI = %q", got.RedirectURI)
		}
		if got.ResponseType != "code" {
			t.Errorf("ResponseType = %q", got.ResponseType)
		}
		if got.Scope != "openid profile" {
			t.Errorf("Scope = %q", got.Scope)
		}
		if got.State != "xyz" {
			t.Errorf("State = %q", got.State)
		}
		if got.Nonce != "n0" {
			t.Errorf("Nonce = %q", got.Nonce)
		}
		if got.CodeChallenge != "ch" {
			t.Errorf("CodeChallenge = %q", got.CodeChallenge)
		}
		if got.CodeChallengeMethod != "S256" {
			t.Errorf("CodeChallengeMethod = %q", got.CodeChallengeMethod)
		}
	})

	t.Run("default method when challenge present, method absent", func(t *testing.T) {
		c := mkCtx("client_id=cid&redirect_uri=https%3A%2F%2Fa%2Fcb&response_type=code&code_challenge=ch")
		got, err := h.parseAuthorizeRequest(c)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		// The code defaults the method to "plain" — keep the test aligned
		// with behavior, not the comment in the source.
		if got.CodeChallengeMethod != "plain" {
			t.Errorf("CodeChallengeMethod default = %q, want plain", got.CodeChallengeMethod)
		}
	})

	t.Run("no challenge, no method", func(t *testing.T) {
		c := mkCtx("client_id=cid&redirect_uri=https%3A%2F%2Fa%2Fcb&response_type=code")
		got, err := h.parseAuthorizeRequest(c)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if got.CodeChallenge != "" || got.CodeChallengeMethod != "" {
			t.Errorf("expected both empty, got challenge=%q method=%q",
				got.CodeChallenge, got.CodeChallengeMethod)
		}
	})

	t.Run("missing client_id", func(t *testing.T) {
		c := mkCtx("redirect_uri=https%3A%2F%2Fa%2Fcb&response_type=code")
		_, err := h.parseAuthorizeRequest(c)
		if err == nil || !strings.Contains(err.Error(), "client_id") {
			t.Errorf("err = %v, want about client_id", err)
		}
	})
	t.Run("missing redirect_uri", func(t *testing.T) {
		c := mkCtx("client_id=cid&response_type=code")
		_, err := h.parseAuthorizeRequest(c)
		if err == nil || !strings.Contains(err.Error(), "redirect_uri") {
			t.Errorf("err = %v, want about redirect_uri", err)
		}
	})
	t.Run("missing response_type", func(t *testing.T) {
		c := mkCtx("client_id=cid&redirect_uri=https%3A%2F%2Fa%2Fcb")
		_, err := h.parseAuthorizeRequest(c)
		if err == nil || !strings.Contains(err.Error(), "response_type") {
			t.Errorf("err = %v, want about response_type", err)
		}
	})
}
