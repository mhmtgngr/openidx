package identity

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/openidx/openidx/internal/common/middleware"
)

// An administrator's ID token carries the same roles as their access token and
// verifies against the same key; it is also handed to every relying party they
// sign in to. The identity API must refuse it, and must do so in the
// authentication middleware: the nil pool behind celledIdentity means a token
// that got as far as the permission resolver would panic rather than answer.
func TestIdentityRefusesAnAdminsIDToken(t *testing.T) {
	r, issuer := celledIdentity(t, "")
	claims := jwt.MapClaims{
		"sub":   "11111111-1111-1111-1111-111111111111",
		"iss":   issuer,
		"aud":   "admin-console",
		"roles": []interface{}{"admin"},
		"exp":   float64(time.Now().Add(time.Hour).Unix()),
	}
	idToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(signingKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	w := call(t, r, idToken)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("an admin's ID token answered %d at GET /users, want 401", w.Code)
	}
	var body map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "invalid token: not an access token" {
		t.Errorf("error = %v", body["error"])
	}

	// The control: an access token for the same subject, holding no role,
	// authenticates and is stopped by the admin gate instead.
	if w := call(t, r, token(t, issuer, jwt.MapClaims{})); w.Code != http.StatusForbidden {
		t.Fatalf("an access token answered %d, want 403 from the admin gate", w.Code)
	}
}

// An administrator who signs in to a third-party application hands it an
// access token carrying their roles. The identity API refuses it in the
// authentication middleware, before the admin gate its roles would pass.
func TestIdentityRefusesATokenWithoutAPIAccess(t *testing.T) {
	r, issuer := celledIdentity(t, "")
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":       "11111111-1111-1111-1111-111111111111",
		"iss":       issuer,
		"client_id": "third-party",
		"roles":     []interface{}{"admin"},
		"org_id":    middleware.DefaultOrgID,
		"exp":       float64(time.Now().Add(time.Hour).Unix()),
	})
	tok.Header["typ"] = middleware.AccessTokenType
	thirdParty, err := tok.SignedString(signingKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	w := call(t, r, thirdParty)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a third-party application's token answered %d at GET /users, want 401", w.Code)
	}
	var body map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "invalid token: this application may not call the OpenIDX API" {
		t.Errorf("error = %v", body["error"])
	}

	// The control: the console's access token for the same subject, holding
	// no role, authenticates and is stopped by the admin gate instead.
	if w := call(t, r, token(t, issuer, jwt.MapClaims{})); w.Code != http.StatusForbidden {
		t.Fatalf("the console's access token answered %d, want 403 from the admin gate", w.Code)
	}
}
