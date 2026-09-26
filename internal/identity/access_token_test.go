package identity

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
