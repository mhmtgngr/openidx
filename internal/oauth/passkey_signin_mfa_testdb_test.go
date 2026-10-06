package oauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/stepup"
)

// A passkey sign-in in which the authenticator verified the person counts as
// multi-factor; one in which it only tested presence does not (#1109).
//
// Before this, /oauth/passkey-finish never recorded how the session was
// authenticated: the session had no amr and no mfa_verified_at, so the step-up
// freshness gate refused it as never verified, however the passkey was used.
// The Windows tray registers Windows Hello as a passkey, so that blocked the
// Windows client's own step-up story.
//
// The test drives /oauth/passkey-begin and /oauth/passkey-finish against the
// migrated schema and the real identity service, with a software
// authenticator holding a P-256 key: the assertion is signed over
// authenticator data whose flags say presence (UP) or presence and
// verification (UP|UV). It then reads the session the sign-in created, the
// amr tokens minted from it would carry, and what the step-up gate decides.
func TestAPasskeySignInIsMultiFactorOnlyWhenTheAuthenticatorVerifiedThePerson(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newMFAGraceFixture(t)
	f.s.clients = NewPostgresOAuthClientStore(f.db)
	const (
		rpID   = "login.example.test"
		origin = "https://login.example.test"
	)
	// The fixture's identity service holds the same config, so this is the
	// relying party it verifies assertions for.
	f.s.config.WebAuthn = config.WebAuthnConfig{RPID: rpID, RPOrigins: []string{origin}, Timeout: 60}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: f.org}))
		c.Next()
	})
	router.POST("/oauth/passkey-begin", f.s.handlePasskeyBegin)
	router.POST("/oauth/passkey-finish", f.s.handlePasskeyFinish)
	post := func(path string, body interface{}) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	b64 := base64.RawURLEncoding.EncodeToString
	ctx := context.Background()

	type signIn struct {
		sessionID string
		amr       []string
		stamped   bool
	}
	// signInWithPasskey registers a passkey for a new user, then signs them in
	// with an assertion carrying flags, and returns the session it opened.
	signInWithPasskey := func(t *testing.T, name string, flags byte) signIn {
		t.Helper()
		u := f.user(name)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		pub, err := key.PublicKey.ECDH()
		if err != nil {
			t.Fatalf("public key: %v", err)
		}
		point := pub.Bytes() // 0x04 || X || Y
		cose := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
		cose = append(cose, point[1:33]...)
		cose = append(cose, 0x22, 0x58, 0x20)
		cose = append(cose, point[33:65]...)
		credID := make([]byte, 16)
		_, _ = rand.Read(credID)
		f.exec(`INSERT INTO mfa_webauthn (user_id, credential_id, public_key, sign_count, aaguid, transports, name,
		                                  backup_eligible, backup_state, attestation_format, org_id)
		        VALUES ($1::uuid, $2, $3, 0, '', '{}', 'Windows Hello', false, false, 'none', $4::uuid)`,
			u.ID, b64(credID), b64(cose), f.org)

		ls := GenerateRandomToken(32)
		params, _ := json.Marshal(map[string]string{
			"client_id": "admin-console", "redirect_uri": "https://app.example.test/callback",
			"scope": "openid", "state": "st-1",
		})
		if err := f.s.redis.Client.Set(ctx, "login_session:"+ls, params, time.Minute).Err(); err != nil {
			t.Fatalf("seed login session: %v", err)
		}

		w := post("/oauth/passkey-begin", map[string]string{"login_session": ls})
		if w.Code != http.StatusOK {
			t.Fatalf("passkey-begin answered %d: %s", w.Code, w.Body.String())
		}
		var options struct {
			PublicKey struct {
				Challenge        string `json:"challenge"`
				UserVerification string `json:"userVerification"`
			} `json:"publicKey"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &options); err != nil || options.PublicKey.Challenge == "" {
			t.Fatalf("passkey-begin answered no challenge (%v): %s", err, w.Body.String())
		}
		// The relying party asks for user verification the browser's way by
		// default ("preferred" when the field is absent). "discouraged" would
		// tell authenticators not to verify, and no sign-in would then count.
		if options.PublicKey.UserVerification == "discouraged" {
			t.Fatalf("passkey sign-in discourages user verification: %s", w.Body.String())
		}

		rpHash := sha256.Sum256([]byte(rpID))
		authData := append(append([]byte{}, rpHash[:]...), flags, 0, 0, 0, 1)
		clientData, _ := json.Marshal(map[string]interface{}{
			"type": "webauthn.get", "challenge": options.PublicKey.Challenge, "origin": origin, "crossOrigin": false,
		})
		clientDataHash := sha256.Sum256(clientData)
		digest := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash[:]...))
		sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		userHandle := uuid.MustParse(u.ID)
		w = post("/oauth/passkey-finish", map[string]interface{}{
			"login_session": ls,
			"credential": map[string]interface{}{
				"id": b64(credID), "rawId": b64(credID), "type": "public-key",
				"response": map[string]interface{}{
					"clientDataJSON":    b64(clientData),
					"authenticatorData": b64(authData),
					"signature":         b64(sig),
					"userHandle":        b64(userHandle[:]),
				},
			},
		})
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "code=") {
			t.Fatalf("passkey-finish answered %d, want 200 with a code: %s", w.Code, w.Body.String())
		}

		var s signIn
		var stampedAt *time.Time
		if err := f.db.Pool.QueryRow(ctx, `
			SELECT id::text, COALESCE(auth_methods, '{}'), mfa_verified_at FROM sessions
			 WHERE user_id = $1::uuid AND org_id = $2::uuid ORDER BY started_at DESC LIMIT 1`,
			u.ID, f.org).Scan(&s.sessionID, &s.amr, &stampedAt); err != nil {
			t.Fatalf("the sign-in opened no session: %v", err)
		}
		s.stamped = stampedAt != nil
		return s
	}
	gate := func(s signIn) stepup.Decision {
		return stepup.Gate(f.orgCtx, f.db, stepup.ModeEnforce, 15*time.Minute,
			stepup.Caller{UserID: "u", OrgID: f.org, SessionID: s.sessionID})
	}
	const (
		flagUP = 0x01
		flagUV = 0x04
	)

	t.Run("with user verification the session is multi-factor and clears step-up", func(t *testing.T) {
		s := signInWithPasskey(t, "passkey-uv", flagUP|flagUV)
		if got := strings.Join(s.amr, " "); got != "hwk user mfa" {
			t.Errorf("the session records amr %q, want %q", got, "hwk user mfa")
		}
		if got := strings.Join(f.s.sessionAuthMethods(f.orgCtx, []string{s.sessionID}), " "); got != "hwk user mfa" {
			t.Errorf("tokens minted from the session would carry amr %q, want %q", got, "hwk user mfa")
		}
		if !s.stamped {
			t.Fatal("the session has no mfa_verified_at, so the step-up gate treats it as never verified")
		}
		if d := gate(s); !d.Allowed {
			t.Errorf("the step-up gate refused a session the authenticator verified the person for: %+v", d)
		}
	})

	t.Run("with presence only the session is one factor and does not clear step-up", func(t *testing.T) {
		s := signInWithPasskey(t, "passkey-up", flagUP)
		if got := strings.Join(s.amr, " "); got != "hwk" {
			t.Errorf("the session records amr %q, want %q", got, "hwk")
		}
		if s.stamped {
			t.Fatal("a presence-only passkey stamped mfa_verified_at; the column would assert a factor nobody proved")
		}
		if d := gate(s); d.Allowed {
			t.Errorf("the step-up gate let a single-factor passkey session through: %+v", d)
		}
	})
}
