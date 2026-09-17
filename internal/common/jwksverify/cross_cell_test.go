package jwksverify

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// A TOKEN FROM ANOTHER CELL'S KEY DOES NOT VERIFY HERE (plan 4.4 acceptance).
//
// Cell us-1 publishes its own JWKS (its own oauth_signing_keys, its own
// database). A token signed by cell eu-1's key carries eu-1's kid, which is
// not in that JWKS, and is refused. The kid prefix is what makes the refusal
// legible -- "eu-1-key-… not found" -- not what causes it: the key is absent
// whatever it is called. Two more shapes are pinned: a leaked eu-1 key
// wearing us-1's kid fails on signature, and us-1's own token is the positive
// control that says the JWKS server and verifier are working.
func TestATokenSignedByAnotherCellsKeyIsRefused(t *testing.T) {
	resetJWKSCache()
	us, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	eu, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const usKid, euKid = "us-1-key-0a0a0a0a0a0a", "eu-1-key-0b0b0b0b0b0b"
	srv := newJWKSServer(t, usKid, &us.PublicKey)
	defer srv.Close()
	claims := jwt.MapClaims{"sub": "u", "exp": time.Now().Add(time.Minute).Unix()}

	// Positive control: the cell's own token verifies.
	if _, err := VerifyBearerToken(srv.URL, signRS256(t, us, usKid, claims)); err != nil {
		t.Fatalf("this cell's own token was refused: %v", err)
	}

	// Another cell's token: its kid is not in this cell's JWKS.
	_, err = VerifyBearerToken(srv.URL, signRS256(t, eu, euKid, claims))
	if err == nil {
		t.Fatal("a token signed by another cell's key verified against this cell's JWKS")
	}
	if !strings.Contains(err.Error(), euKid) || !strings.Contains(err.Error(), "not found in JWKS") {
		t.Fatalf("refusal does not name the foreign kid: %v", err)
	}

	// A leaked foreign key wearing this cell's kid: found by name, refused
	// on signature.
	_, err = VerifyBearerToken(srv.URL, signRS256(t, eu, usKid, claims))
	if err == nil {
		t.Fatal("a token signed by another cell's key under this cell's kid verified")
	}
}
