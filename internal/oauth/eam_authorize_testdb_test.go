package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/federation/oidcrp"
)

// ENTRA HANDS THE SECOND FACTOR TO OPENIDX.
//
// Driven through RegisterRoutes over a migrated database with a fake Entra
// (httptest) publishing a per-tenant discovery document and keys. Entra's
// request is checked (client, reply address, tenant, the hint's signature
// and audience), the person is found by the hint's oid, the TOTP step runs
// against /eam/verify, and the id_token posted back has the shape Entra
// reads, signed by a key /eam/jwks publishes.

const (
	eamTestClient = "eam-app-0001"
	eamTestTenant = "11111111-2222-3333-4444-555555555555"
)

type fakeEntra struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newFakeEntra(t *testing.T) *fakeEntra {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e := &fakeEntra{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/v2.0/.well-known/openid-configuration"):
			tid := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[0]
			iss := e.srv.URL + "/" + tid + "/v2.0"
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer": iss, "authorization_endpoint": iss + "/authorize", "token_endpoint": iss + "/token",
				"jwks_uri": e.srv.URL + "/" + tid + "/discovery/v2.0/keys",
			})
		case strings.HasSuffix(r.URL.Path, "/discovery/v2.0/keys"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]string{{
				"kty": "RSA", "use": "sig", "kid": "entra-1",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	})
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

// hint is the id_token_hint Entra sends: issued a while ago, already expired.
func (e *fakeEntra) hint(tid, aud, oid, upn string) string {
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": e.srv.URL + "/" + tid + "/v2.0", "aud": aud, "sub": "pairwise-" + oid,
		"oid": oid, "tid": tid, "preferred_username": upn,
		"iat": now.Add(-time.Hour).Unix(), "exp": now.Add(-50 * time.Minute).Unix(),
	})
	tok.Header["kid"] = "entra-1"
	s, _ := tok.SignedString(e.key)
	return s
}

func (e *fakeEntra) reply() string { return e.srv.URL + "/common/federation/externalauthprovider" }

func TestEAMAuthorizeVerifiesEntraAndIssuesTheIDToken(t *testing.T) {
	t.Setenv(oidcrp.AllowLoopbackEnv, "1")
	x := newExternalHarness(t)
	entra := newFakeEntra(t)
	x.issuer.config = &config.Config{EAMEnabled: true, EAMClientID: eamTestClient, EAMTenantIDs: "other-tenant, " + eamTestTenant, EAMRequireStrongFactors: true}
	x.issuer.eamAuthority = entra.srv.URL
	x.api = x.oauthRouteTable(nil)

	userID, _, secret := x.linkedUser("eam-person", "totp")
	oid := "oid-" + x.suffix
	x.exec(`UPDATE users SET source = 'azure_ad', external_id = $1 WHERE id = $2::uuid`, oid, userID)

	authorize := func(mut func(url.Values)) *httptest.ResponseRecorder {
		q := url.Values{
			"client_id": {eamTestClient}, "redirect_uri": {entra.reply()},
			"response_type": {"id_token"}, "response_mode": {"form_post"}, "scope": {"openid"},
			"nonce": {"n-123"}, "state": {"st-abc"}, "client-request-id": {"crid-1"},
			"claims":        {`{"id_token":{"acr":{"essential":true,"values":["possessionorinherence"]}}}`},
			"id_token_hint": {entra.hint(eamTestTenant, eamTestClient, oid, "someone@example.test")},
		}
		if mut != nil {
			mut(q)
		}
		return x.get("/eam/authorize?" + q.Encode())
	}
	refusedToEntra := func(t *testing.T, w *httptest.ResponseRecorder, code string) {
		t.Helper()
		body := w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(body, `action="`+entra.reply()+`"`) ||
			!strings.Contains(body, `name="error" value="`+code+`"`) || !strings.Contains(body, `value="st-abc"`) {
			t.Fatalf("want an %s form_post to Entra, got %d %s", code, w.Code, body)
		}
	}

	t.Run("a foreign client id is refused without a reply", func(t *testing.T) {
		w := authorize(func(q url.Values) { q.Set("client_id", "someone-else") })
		if w.Code != http.StatusBadRequest {
			t.Fatalf("got %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("a foreign reply address is refused without a reply", func(t *testing.T) {
		w := authorize(func(q url.Values) { q.Set("redirect_uri", "https://evil.example/cb") })
		if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "evil.example") {
			t.Fatalf("got %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("a hint for another audience is denied", func(t *testing.T) {
		refusedToEntra(t, authorize(func(q url.Values) {
			q.Set("id_token_hint", entra.hint(eamTestTenant, "another-app", oid, ""))
		}), "access_denied")
	})
	t.Run("a hint from a tenant not on the list is denied", func(t *testing.T) {
		refusedToEntra(t, authorize(func(q url.Values) {
			q.Set("id_token_hint", entra.hint("99999999-0000-0000-0000-000000000000", eamTestClient, oid, ""))
		}), "access_denied")
	})
	t.Run("a hint signed by someone else is denied", func(t *testing.T) {
		other := &fakeEntra{srv: entra.srv}
		other.key, _ = rsa.GenerateKey(rand.Reader, 2048)
		refusedToEntra(t, authorize(func(q url.Values) {
			q.Set("id_token_hint", other.hint(eamTestTenant, eamTestClient, oid, ""))
		}), "access_denied")
	})
	t.Run("an Entra user OpenIDX does not know is denied", func(t *testing.T) {
		refusedToEntra(t, authorize(func(q url.Values) {
			q.Set("id_token_hint", entra.hint(eamTestTenant, eamTestClient, "oid-nobody", "nobody@example.test"))
		}), "access_denied")
	})

	t.Run("the person is found by oid and finishes with TOTP", func(t *testing.T) {
		w := authorize(nil)
		if w.Code != http.StatusFound {
			t.Fatalf("authorize = %d %s", w.Code, w.Body.String())
		}
		loc, _ := url.Parse(w.Header().Get("Location"))
		session := loc.Query().Get("eam_session")
		if loc.Path != "/login" || session == "" || loc.Query().Get("mfa_methods") != "totp" {
			t.Fatalf("Location = %q", w.Header().Get("Location"))
		}

		// The session cannot be finished at /oauth/mfa-verify (no OpenIDX code).
		if code, _ := x.post("/oauth/mfa-verify", "", map[string]string{"mfa_session": session, "code": "000000"}); code != http.StatusBadRequest {
			t.Fatalf("/oauth/mfa-verify on an EAM session = %d, want 400", code)
		}
		// Nor with a factor the session does not offer.
		if code, _ := x.post("/eam/verify", "", map[string]string{"mfa_session": session, "code": "x", "method": "backup"}); code != http.StatusBadRequest {
			t.Fatalf("backup on an EAM session = %d, want 400", code)
		}
		otp, _ := totp.GenerateCode(secret, time.Now())
		code, out := x.post("/eam/verify", "", map[string]string{"mfa_session": session, "code": otp, "method": "totp"})
		if code != http.StatusOK {
			t.Fatalf("/eam/verify = %d %v", code, out)
		}
		fp, _ := out["form_post"].(map[string]interface{})
		fields, _ := fp["fields"].(map[string]interface{})
		if fp["action"] != entra.reply() || fields["state"] != "st-abc" {
			t.Fatalf("form_post = %v", fp)
		}
		raw, _ := fields["id_token"].(string)

		// Verify it the way Entra would: against /eam/jwks.
		jw := x.get("/eam/jwks")
		var set struct {
			Keys []eamJWK `json:"keys"`
		}
		if err := json.Unmarshal(jw.Body.Bytes(), &set); err != nil || len(set.Keys) == 0 || len(set.Keys[0].X5c) != 1 || set.Keys[0].X5t == "" {
			t.Fatalf("jwks = %s", jw.Body.String())
		}
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(raw, claims, func(tok *jwt.Token) (interface{}, error) {
			for _, k := range set.Keys {
				if k.Kid == tok.Header["kid"] {
					n, _ := base64.RawURLEncoding.DecodeString(k.N)
					return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}, nil
				}
			}
			return nil, jwt.ErrTokenUnverifiable
		}, jwt.WithValidMethods([]string{"RS256"}))
		if err != nil {
			t.Fatalf("id_token does not verify against /eam/jwks: %v", err)
		}
		if claims["iss"] != x.issuer.issuer+"/eam" || claims["aud"] != eamTestClient ||
			claims["sub"] != "pairwise-"+oid || claims["nonce"] != "n-123" || claims["acr"] != "possessionorinherence" {
			t.Fatalf("claims = %v", claims)
		}
		amr, _ := claims["amr"].([]interface{})
		if len(amr) != 1 || amr[0] != "otp" {
			t.Fatalf("amr = %v", claims["amr"])
		}
		exp, _ := claims["exp"].(float64)
		iat, _ := claims["iat"].(float64)
		if exp-iat != 300 {
			t.Fatalf("lifetime = %v s, want 300", exp-iat)
		}
		// The session is spent.
		if code, _ := x.post("/eam/verify", "", map[string]string{"mfa_session": session, "code": otp}); code != http.StatusBadRequest {
			t.Fatalf("replayed session = %d", code)
		}
	})
}

func TestEAMKeyRotationPublishesBeforeSigning(t *testing.T) {
	x := newExternalHarness(t)
	x.issuer.config = &config.Config{EAMEnabled: true, EAMClientID: eamTestClient}
	ctx := context.Background()
	x.exec(`DELETE FROM eam_signing_keys`)
	now := time.Now()

	first, err := x.issuer.eamSigningKey(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	next, err := x.issuer.rotateEAMKey(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := x.issuer.loadEAMKeys(ctx, now)
	if len(keys) != 2 {
		t.Fatalf("published %d keys, want 2", len(keys))
	}
	if got, _ := x.issuer.eamSigningKey(ctx, now.Add(time.Hour)); got.KID != first.KID {
		t.Fatalf("a key rotated in an hour ago signs (%s), want %s", got.KID, first.KID)
	}
	if got, _ := x.issuer.eamSigningKey(ctx, now.Add(eamKeyPublishLead+time.Minute)); got.KID != next.KID {
		t.Fatalf("after the lead, %s signs, want %s", got.KID, next.KID)
	}
	if v := x.scalar(`SELECT kid FROM eam_signing_keys WHERE active`); v != next.KID {
		t.Fatalf("active column = %s, want %s", v, next.KID)
	}
}
