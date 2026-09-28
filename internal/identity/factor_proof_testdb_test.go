package identity

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/pushenroll"
)

// A CHANGE TO SOMEONE'S SECOND FACTORS NEEDS THEM, NOT ONLY THEIR TOKEN.
//
// Each self-service route that removes, replaces or adds a second factor is
// driven through identity's route table, as cmd/identity-service wires it,
// with a signed token for an account that already has one (TOTP). Every one
// refuses the request with the token alone and with a wrong password, and
// changes nothing; every one makes the change with the account's password; the
// routes that remove or replace the TOTP credential make it with a current
// code from it as well, and the others do not take a code for the password.
// The state each route changes is read from the database around every request.

// proofSubject is one account and what the case seeded on it.
type proofSubject struct {
	id, bearer, secret string
	// row is the id of the factor row a removal targets; code is a one-time
	// code a verification step expects; the enrollment case's new secret.
	row, code, newSecret string
}

type proofRoute struct {
	name, method string
	path         func(h *selfServiceHarness, p *proofSubject) string
	// give leaves the account with the state the request acts on, beyond the
	// TOTP credential every case starts with.
	give func(h *selfServiceHarness, p *proofSubject)
	// body is the request, without proof; it may run the steps before it (a
	// ceremony's begin).
	body     func(h *selfServiceHarness, p *proofSubject) map[string]interface{}
	state    func(h *selfServiceHarness, p *proofSubject) string
	okStatus int
	// totp: the route removes or replaces the TOTP credential, so a current
	// code from it is proof as well as the password.
	totp bool
}

func noState(*selfServiceHarness, *proofSubject) {}

func pathOf(path string) func(*selfServiceHarness, *proofSubject) string {
	return func(*selfServiceHarness, *proofSubject) string { return path }
}

func noBody(*selfServiceHarness, *proofSubject) map[string]interface{} {
	return map[string]interface{}{}
}

// factorRoutes is every self-service route that changes a second factor.
func factorRoutes() []proofRoute {
	return []proofRoute{
		{
			name: "disable MFA", method: http.MethodPost, path: pathOf("/api/v1/identity/users/me/mfa/disable"),
			give: noState, body: noBody, okStatus: http.StatusOK, totp: true,
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT enabled::text FROM mfa_totp WHERE user_id = $1::uuid`, p.id)
			},
		},
		{
			name: "remove the TOTP credential", method: http.MethodDelete, path: pathOf("/api/v1/identity/mfa/totp"),
			give: noState, body: noBody, okStatus: http.StatusOK, totp: true,
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT enabled::text FROM mfa_totp WHERE user_id = $1::uuid`, p.id)
			},
		},
		{
			// The console's path: setup caches a new secret, enable replaces the
			// credential with it.
			name: "replace the TOTP credential (setup, enable)", method: http.MethodPost,
			path: pathOf("/api/v1/identity/users/me/mfa/enable"), okStatus: http.StatusOK, totp: true,
			give: func(h *selfServiceHarness, p *proofSubject) {
				status, out := h.do(http.MethodPost, "/api/v1/identity/users/me/mfa/setup", p.bearer, nil)
				if status != http.StatusOK {
					h.t.Fatalf("setup: status %d (%v)", status, out)
				}
				p.newSecret, _ = out["secret"].(string)
			},
			body: func(h *selfServiceHarness, p *proofSubject) map[string]interface{} {
				return map[string]interface{}{"code": totpCode(h.t, p.newSecret, time.Now())}
			},
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT secret FROM mfa_totp WHERE user_id = $1::uuid`, p.id)
			},
		},
		{
			name: "replace the TOTP credential (enroll)", method: http.MethodPost,
			path: pathOf("/api/v1/identity/mfa/totp/enroll"), okStatus: http.StatusOK, totp: true,
			give: func(h *selfServiceHarness, p *proofSubject) {
				key, err := totp.Generate(totp.GenerateOpts{Issuer: "OpenIDX", AccountName: "replacement"})
				if err != nil {
					h.t.Fatalf("generate key: %v", err)
				}
				p.newSecret = key.Secret()
			},
			body: func(h *selfServiceHarness, p *proofSubject) map[string]interface{} {
				return map[string]interface{}{"secret": p.newSecret, "code": totpCode(h.t, p.newSecret, time.Now())}
			},
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT secret FROM mfa_totp WHERE user_id = $1::uuid`, p.id)
			},
		},
		{
			name: "regenerate the backup codes", method: http.MethodPost,
			path: pathOf("/api/v1/identity/mfa/backup/generate"), okStatus: http.StatusOK,
			give: func(h *selfServiceHarness, p *proofSubject) {
				if _, err := h.svc.GenerateBackupCodes(orgctx.With(h.seedCtx(), orgctx.Org{ID: middleware.DefaultOrgID}), p.id, 5); err != nil {
					h.t.Fatalf("seed backup codes: %v", err)
				}
			},
			body: noBody,
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT COALESCE(string_agg(code_hash, ',' ORDER BY code_hash), '')
					FROM mfa_backup_codes WHERE user_id = $1::uuid AND NOT used`, p.id)
			},
		},
		{
			name: "delete a passkey", method: http.MethodDelete, okStatus: http.StatusNoContent,
			path: func(_ *selfServiceHarness, p *proofSubject) string {
				return "/api/v1/identity/mfa/webauthn/credentials/" + p.row
			},
			give: func(h *selfServiceHarness, p *proofSubject) {
				p.row = h.scalar(`INSERT INTO mfa_webauthn (user_id, credential_id, public_key, name, org_id)
					VALUES ($1::uuid, $2, 'cose', 'Security key', $3::uuid) RETURNING id::text`,
					p.id, "cred-"+p.id, middleware.DefaultOrgID)
			},
			body: noBody,
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT COUNT(*)::text FROM mfa_webauthn WHERE user_id = $1::uuid`, p.id)
			},
		},
		{
			name: "add a passkey", method: http.MethodPost, okStatus: http.StatusCreated,
			path: pathOf("/api/v1/identity/mfa/webauthn/register/finish"), give: noState,
			body: func(h *selfServiceHarness, p *proofSubject) map[string]interface{} {
				status, begin := h.do(http.MethodPost, "/api/v1/identity/mfa/webauthn/register/begin", p.bearer, nil)
				if status != http.StatusOK {
					h.t.Fatalf("register/begin: status %d (%v)", status, begin)
				}
				return softAttestation(h.t, begin, "localhost", "http://localhost:3000")
			},
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT COUNT(*)::text FROM mfa_webauthn WHERE user_id = $1::uuid`, p.id)
			},
		},
		{
			name: "register a push device", method: http.MethodPost, okStatus: http.StatusCreated,
			path: pathOf("/api/v1/identity/mfa/push/devices"), give: noState,
			body: func(_ *selfServiceHarness, p *proofSubject) map[string]interface{} {
				return map[string]interface{}{"device_token": "tok-" + p.id + "-" + randomTag(), "platform": "android", "device_name": "Pixel"}
			},
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT COUNT(*)::text FROM mfa_push_devices WHERE user_id = $1::uuid`, p.id)
			},
		},
		{
			name: "register a push token", method: http.MethodPost, okStatus: http.StatusCreated,
			path: pathOf("/api/v1/identity/mfa/push/register"), give: noState,
			body: func(_ *selfServiceHarness, p *proofSubject) map[string]interface{} {
				return map[string]interface{}{"device_token": "tok-" + p.id + "-" + randomTag(), "platform": "ios", "device_name": "iPhone"}
			},
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT COUNT(*)::text FROM mfa_push_devices WHERE user_id = $1::uuid`, p.id)
			},
		},
		{
			// The ticket the scanned QR completes with, unauthenticated.
			name: "start a push enrollment", method: http.MethodPost, okStatus: http.StatusOK,
			path: pathOf("/api/v1/identity/mfa/push/enroll/start"), give: noState, body: noBody,
			state: func(h *selfServiceHarness, _ *proofSubject) string {
				n := 0
				for _, k := range h.redis.Keys() {
					if strings.HasPrefix(k, "push_enroll:") {
						n++
					}
				}
				return fmt.Sprint(n)
			},
		},
		{
			name: "remove a push device", method: http.MethodDelete, okStatus: http.StatusNoContent,
			path: func(_ *selfServiceHarness, p *proofSubject) string {
				return "/api/v1/identity/mfa/push/devices/" + p.row
			},
			give: func(h *selfServiceHarness, p *proofSubject) {
				p.row = h.scalar(`INSERT INTO mfa_push_devices (user_id, device_token, platform, device_name, enabled, org_id)
					VALUES ($1::uuid, $2, 'android', 'Pixel', true, $3::uuid) RETURNING id::text`,
					p.id, "seeded-"+p.id, middleware.DefaultOrgID)
			},
			body: noBody,
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT COUNT(*)::text FROM mfa_push_devices WHERE user_id = $1::uuid`, p.id)
			},
		},
		{
			// The step that makes an SMS number a factor.
			name: "verify an SMS number", method: http.MethodPost, okStatus: http.StatusOK,
			path: pathOf("/api/v1/identity/mfa/sms/verify"),
			give: func(h *selfServiceHarness, p *proofSubject) {
				h.exec(`INSERT INTO mfa_sms (user_id, phone_number, country_code, verified, enabled, org_id)
					VALUES ($1::uuid, '5550100', '+1', false, true, $2::uuid)`, p.id, middleware.DefaultOrgID)
				code, err := h.svc.createOTPChallenge(h.seedCtx(), p.id, "sms", "+15550100")
				if err != nil {
					h.t.Fatalf("seed SMS challenge: %v", err)
				}
				p.code = code
			},
			body: func(_ *selfServiceHarness, p *proofSubject) map[string]interface{} {
				return map[string]interface{}{"code": p.code}
			},
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT verified::text FROM mfa_sms WHERE user_id = $1::uuid`, p.id)
			},
		},
		{
			name: "remove the SMS number", method: http.MethodDelete, okStatus: http.StatusOK,
			path: pathOf("/api/v1/identity/mfa/sms"),
			give: func(h *selfServiceHarness, p *proofSubject) {
				h.exec(`INSERT INTO mfa_sms (user_id, phone_number, country_code, verified, enabled, org_id)
					VALUES ($1::uuid, '5550100', '+1', true, true, $2::uuid)`, p.id, middleware.DefaultOrgID)
			},
			body: noBody,
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT COUNT(*)::text FROM mfa_sms WHERE user_id = $1::uuid`, p.id)
			},
		},
		{
			// Email OTP is a factor from the moment it is enrolled.
			name: "enroll an email address", method: http.MethodPost, okStatus: http.StatusOK,
			path: pathOf("/api/v1/identity/mfa/email/enroll"), give: noState,
			body: func(_ *selfServiceHarness, p *proofSubject) map[string]interface{} {
				return map[string]interface{}{"email": "otp-" + p.id + "@elsewhere.test"}
			},
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT COUNT(*)::text FROM mfa_email_otp WHERE user_id = $1::uuid`, p.id)
			},
		},
		{
			name: "remove the email address", method: http.MethodDelete, okStatus: http.StatusOK,
			path: pathOf("/api/v1/identity/mfa/email"),
			give: func(h *selfServiceHarness, p *proofSubject) {
				h.exec(`INSERT INTO mfa_email_otp (user_id, email_address, enabled, org_id)
					VALUES ($1::uuid, $2, true, $3::uuid)`, p.id, "otp-"+p.id+"@example.test", middleware.DefaultOrgID)
			},
			body: noBody,
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT COUNT(*)::text FROM mfa_email_otp WHERE user_id = $1::uuid`, p.id)
			},
		},
		{
			// Enrolling again re-points a verified number in place.
			name: "re-point the phone-call number", method: http.MethodPost, okStatus: http.StatusOK,
			path: pathOf("/api/v1/identity/mfa/phone/enroll"),
			give: func(h *selfServiceHarness, p *proofSubject) {
				h.exec(`INSERT INTO mfa_phone_call (user_id, phone_number, country_code, verified, enabled, org_id)
					VALUES ($1::uuid, '5550100', '+1', true, true, $2::uuid)`, p.id, middleware.DefaultOrgID)
			},
			body: func(*selfServiceHarness, *proofSubject) map[string]interface{} {
				return map[string]interface{}{"phone_number": "5550199", "country_code": "+1"}
			},
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT phone_number || ' ' || verified::text FROM mfa_phone_call WHERE user_id = $1::uuid`, p.id)
			},
		},
		{
			// The step that makes a phone-call number a factor.
			name: "verify a phone-call number", method: http.MethodPost, okStatus: http.StatusOK,
			path: pathOf("/api/v1/identity/mfa/phone/verify"),
			give: func(h *selfServiceHarness, p *proofSubject) {
				h.exec(`INSERT INTO mfa_phone_call (user_id, phone_number, country_code, verified, enabled, org_id)
					VALUES ($1::uuid, '5550100', '+1', false, true, $2::uuid)`, p.id, middleware.DefaultOrgID)
				p.code = "482915"
				hash, err := bcrypt.GenerateFromPassword([]byte(p.code), bcrypt.MinCost)
				if err != nil {
					h.t.Fatalf("hash call code: %v", err)
				}
				h.exec(`INSERT INTO phone_call_challenges (user_id, phone_number, code_hash, call_type, status, attempts, expires_at, org_id)
					VALUES ($1::uuid, '+15550100', $2, 'outbound', 'pending', 0, NOW() + INTERVAL '5 minutes', $3::uuid)`,
					p.id, string(hash), middleware.DefaultOrgID)
			},
			body: func(_ *selfServiceHarness, p *proofSubject) map[string]interface{} {
				return map[string]interface{}{"code": p.code}
			},
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT verified::text FROM mfa_phone_call WHERE user_id = $1::uuid`, p.id)
			},
		},
		{
			name: "remove the phone-call number", method: http.MethodDelete, okStatus: http.StatusOK,
			path: pathOf("/api/v1/identity/mfa/phone"),
			give: func(h *selfServiceHarness, p *proofSubject) {
				h.exec(`INSERT INTO mfa_phone_call (user_id, phone_number, country_code, verified, enabled, org_id)
					VALUES ($1::uuid, '5550100', '+1', true, true, $2::uuid)`, p.id, middleware.DefaultOrgID)
			},
			body: noBody,
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT COUNT(*)::text FROM mfa_phone_call WHERE user_id = $1::uuid`, p.id)
			},
		},
		{
			// A remembered browser skips the second factor at sign-in, and the
			// body can name any browser: the hash sign-in computes from a
			// subnet and a User-Agent, both the caller's to choose.
			name: "remember a browser", method: http.MethodPost, okStatus: http.StatusOK,
			path: pathOf("/api/v1/identity/trusted-browsers"), give: noState,
			body: func(*selfServiceHarness, *proofSubject) map[string]interface{} {
				return map[string]interface{}{"browser_hash": "attacker-browser-" + randomTag(), "name": "Firefox"}
			},
			state: func(h *selfServiceHarness, p *proofSubject) string {
				return h.scalar(`SELECT COUNT(*)::text FROM trusted_browsers WHERE user_id = $1::uuid AND NOT revoked`, p.id)
			},
		},
	}
}

func randomTag() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// subject creates an account with a password and a TOTP credential, and the
// case's own state.
func (h *selfServiceHarness) subject(route proofRoute, label string) *proofSubject {
	h.t.Helper()
	p := &proofSubject{}
	p.id = h.seedUser(strings.ReplaceAll(route.name, " ", "-") + "-" + label)
	p.bearer = h.bearer(p.id)
	p.secret = h.seedTOTP(p.id)
	route.give(h, p)
	return p
}

func withProof(body map[string]interface{}, proof map[string]string) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range body {
		out[k] = v
	}
	for k, v := range proof {
		out[k] = v
	}
	return out
}

func accepts(out map[string]interface{}) []string {
	raw, _ := out["accepts"].([]interface{})
	var got []string
	for _, v := range raw {
		s, _ := v.(string)
		got = append(got, s)
	}
	sort.Strings(got)
	return got
}

func TestFactorChangesNeedProofFromTheAccountHolder(t *testing.T) {
	h := newSelfServiceHarness(t)

	for _, route := range factorRoutes() {
		route := route
		wantAccepts := []string{"current_password"}
		if route.totp {
			wantAccepts = []string{"current_password", "totp_code"}
		}

		t.Run(route.name, func(t *testing.T) {
			refused := func(p *proofSubject, proof map[string]string, wantError string) {
				t.Helper()
				before := route.state(h, p)
				status, out := h.do(route.method, route.path(h, p), p.bearer, withProof(route.body(h, p), proof))
				after := route.state(h, p)
				if status != http.StatusForbidden || out["error"] != wantError {
					t.Fatalf("status %d (%v), want 403 %s", status, out, wantError)
				}
				if got := accepts(out); strings.Join(got, ",") != strings.Join(wantAccepts, ",") {
					t.Errorf("the refusal offers %v, want %v", got, wantAccepts)
				}
				if before != after {
					t.Errorf("refused, but the factor changed: %q -> %q", before, after)
				}
			}
			admitted := func(p *proofSubject, proof map[string]string) {
				t.Helper()
				before := route.state(h, p)
				status, out := h.do(route.method, route.path(h, p), p.bearer, withProof(route.body(h, p), proof))
				after := route.state(h, p)
				if status != route.okStatus {
					t.Fatalf("status %d (%v), want %d", status, out, route.okStatus)
				}
				if before == after {
					t.Errorf("admitted, but the factor did not change: %q", after)
				}
			}

			t.Run("the token alone is refused", func(t *testing.T) {
				refused(h.subject(route, "bare"), nil, reauthRequired)
			})
			t.Run("a wrong password is refused", func(t *testing.T) {
				refused(h.subject(route, "wrong"), map[string]string{"current_password": "not the password"}, reauthFailed)
			})
			t.Run("the password is accepted", func(t *testing.T) {
				admitted(h.subject(route, "password"), map[string]string{"current_password": harnessPassword})
			})
			p := h.subject(route, "code")
			code := map[string]string{"totp_code": totpCode(t, p.secret, time.Now())}
			if route.totp {
				t.Run("a current code from the credential is accepted", func(t *testing.T) {
					admitted(p, code)
				})
			} else {
				t.Run("a TOTP code does not stand in for the password", func(t *testing.T) {
					refused(p, code, reauthRequired)
				})
			}
		})
	}
}

// Enrolling the first factor of an account that has none needs the token
// alone: there is nothing yet to protect, and an account that signs in through
// an identity provider has no password to give.
func TestAFirstFactorNeedsNoProof(t *testing.T) {
	h := newSelfServiceHarness(t)
	for _, route := range factorRoutes() {
		route := route
		switch route.name {
		case "register a push device", "register a push token", "start a push enrollment",
			"add a passkey", "enroll an email address", "verify an SMS number",
			"verify a phone-call number", "remember a browser", "regenerate the backup codes":
		default:
			continue
		}
		t.Run(route.name, func(t *testing.T) {
			p := &proofSubject{}
			p.id = h.seedUser("first-" + strings.ReplaceAll(route.name, " ", "-"))
			p.bearer = h.bearer(p.id)
			if route.name != "regenerate the backup codes" {
				route.give(h, p)
			}
			before := route.state(h, p)
			status, out := h.do(route.method, route.path(h, p), p.bearer, route.body(h, p))
			if status != route.okStatus {
				t.Fatalf("status %d (%v), want %d", status, out, route.okStatus)
			}
			if after := route.state(h, p); before == after {
				t.Errorf("admitted, but nothing changed: %q", after)
			}
		})
	}

	t.Run("enroll TOTP", func(t *testing.T) {
		user := h.seedUser("first-totp")
		key, err := totp.Generate(totp.GenerateOpts{Issuer: "OpenIDX", AccountName: user})
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		status, out := h.do(http.MethodPost, "/api/v1/identity/mfa/totp/enroll", h.bearer(user),
			map[string]string{"secret": key.Secret(), "code": totpCode(t, key.Secret(), time.Now())})
		if status != http.StatusOK {
			t.Fatalf("status %d (%v), want 200", status, out)
		}
	})

	// The other side: once the account has that one factor, adding a second
	// is a factor change like any other.
	t.Run("a second factor after the first needs the password", func(t *testing.T) {
		user := h.seedUser("second-factor")
		bearer := h.bearer(user)
		body := map[string]interface{}{"device_token": "tok-" + user, "platform": "android", "device_name": "Pixel"}
		if status, out := h.do(http.MethodPost, "/api/v1/identity/mfa/push/devices", bearer, body); status != http.StatusCreated {
			t.Fatalf("first factor: status %d (%v), want 201", status, out)
		}
		body["device_token"] = "tok-2-" + user
		if status, out := h.do(http.MethodPost, "/api/v1/identity/mfa/push/devices", bearer, body); status != http.StatusForbidden || out["error"] != reauthRequired {
			t.Fatalf("second factor with the token alone: status %d (%v), want 403 %s", status, out, reauthRequired)
		}
	})
}

// The address is where a password reset goes: a token that could change it
// could reset the password, and then give the password as proof.
func TestChangingTheAccountAddressNeedsThePassword(t *testing.T) {
	h := newSelfServiceHarness(t)
	user := h.seedUser("address")
	bearer := h.bearer(user)
	h.exec(`UPDATE users SET email_verified = true WHERE id = $1::uuid`, user)
	address := func() string {
		return h.scalar(`SELECT email || ' ' || email_verified::text || ' ' || enabled::text FROM users WHERE id = $1::uuid`, user)
	}
	original := address()
	newAddress := "moved-" + h.suffix + "@elsewhere.test"
	// A live sign-in, which a profile update must leave alone.
	h.exec(`INSERT INTO sessions (user_id, client_id, expires_at, org_id)
		VALUES ($1::uuid, 'admin-console', NOW() + INTERVAL '1 day', $2::uuid)`, user, middleware.DefaultOrgID)
	signedIn := func(when string) {
		t.Helper()
		if revoked := h.scalar(`SELECT revoked::text FROM sessions WHERE user_id = $1::uuid`, user); revoked != "false" {
			t.Fatalf("%s: the user's session was revoked (revoked = %s): a profile update signed them out", when, revoked)
		}
	}

	for _, tc := range []struct {
		name  string
		proof map[string]string
		want  string
	}{
		{"the token alone", nil, reauthRequired},
		{"a wrong password", map[string]string{"current_password": "not the password"}, reauthFailed},
	} {
		status, out := h.do(http.MethodPut, "/api/v1/identity/users/me", bearer,
			withProof(map[string]interface{}{"firstName": "Moved", "lastName": "Away", "email": newAddress}, tc.proof))
		if status != http.StatusForbidden || out["error"] != tc.want {
			t.Fatalf("%s: status %d (%v), want 403 %s", tc.name, status, out, tc.want)
		}
		if got := address(); got != original {
			t.Fatalf("%s: refused, but the account changed: %q -> %q", tc.name, original, got)
		}
	}

	// Names alone need nothing, and a field the request leaves out keeps its
	// value: the console's "Update" sends no `enabled`, and used to be handed
	// to UpdateUser as a disabled user, which deprovisioned it.
	status, out := h.do(http.MethodPut, "/api/v1/identity/users/me", bearer,
		map[string]interface{}{"firstName": "Renamed", "lastName": "Person", "email": strings.ToUpper(strings.Split(original, " ")[0])})
	if status != http.StatusOK || out["enabled"] != true {
		t.Fatalf("a name change with the same address: status %d (%v), want 200 and still enabled", status, out)
	}
	if got := address(); got != original {
		t.Fatalf("a name change touched the address or the account: %q -> %q", original, got)
	}
	if name := h.scalar(`SELECT first_name FROM users WHERE id = $1::uuid`, user); name != "Renamed" {
		t.Fatalf("first_name = %q, want Renamed", name)
	}
	signedIn("after a name change")

	status, out = h.do(http.MethodPut, "/api/v1/identity/users/me", bearer,
		map[string]interface{}{"email": newAddress, "current_password": harnessPassword})
	if status != http.StatusOK {
		t.Fatalf("with the password: status %d (%v), want 200", status, out)
	}
	if got, want := address(), newAddress+" false true"; got != want {
		t.Fatalf("after the change: %q, want %q (the new address unverified, the account still enabled)", got, want)
	}
	signedIn("after an address change")
}

// A wrong password given as proof counts against the same lockout sign-in
// uses, so a stolen token cannot guess the password without limit, and a
// locked account refuses the right one too.
func TestAWrongPasswordGivenAsProofCountsTowardsTheLockout(t *testing.T) {
	h := newSelfServiceHarness(t)
	user := h.seedUser("lockout")
	bearer := h.bearer(user)
	h.seedTOTP(user)
	remove := func(password string) (int, map[string]interface{}) {
		return h.do(http.MethodPost, "/api/v1/identity/users/me/mfa/disable", bearer,
			map[string]string{"current_password": password})
	}

	for i := 0; i < 5; i++ {
		if status, out := remove(fmt.Sprintf("guess-%d", i)); status != http.StatusForbidden {
			t.Fatalf("guess %d: status %d (%v), want 403", i, status, out)
		}
	}
	if n := h.count(`SELECT failed_login_count FROM users WHERE id = $1::uuid`, user); n != 5 {
		t.Errorf("failed_login_count = %d after five wrong passwords, want 5", n)
	}
	status, out := remove(harnessPassword)
	if status != http.StatusForbidden || out["error"] != reauthLocked {
		t.Fatalf("the right password on a locked account: status %d (%v), want 403 %s", status, out, reauthLocked)
	}
	if enabled := h.scalar(`SELECT enabled::text FROM mfa_totp WHERE user_id = $1::uuid`, user); enabled != "true" {
		t.Fatal("a locked account's factor was removed")
	}
	username := h.scalar(`SELECT username FROM users WHERE id = $1::uuid`, user)
	_, err := h.svc.AuthenticateUser(orgctx.With(h.seedCtx(), orgctx.Org{ID: middleware.DefaultOrgID}), username, harnessPassword)
	if !errors.Is(err, ErrAccountLocked) {
		t.Errorf("sign-in after the guesses: %v, want ErrAccountLocked", err)
	}

	// The other side: the lock over, the password works, and clears the count.
	h.exec(`UPDATE users SET locked_until = NOW() - INTERVAL '1 minute' WHERE id = $1::uuid`, user)
	if status, out := remove(harnessPassword); status != http.StatusOK {
		t.Fatalf("the right password after the lock: status %d (%v), want 200", status, out)
	}
	if n := h.count(`SELECT failed_login_count FROM users WHERE id = $1::uuid`, user); n != 0 {
		t.Errorf("failed_login_count = %d after the right password, want 0", n)
	}
}

// A TOTP code given as proof goes through VerifyTOTP, so it is spent: a
// request refused after the proof passed cannot be retried with the same code.
func TestATOTPCodeGivenAsProofIsSpent(t *testing.T) {
	h := newSelfServiceHarness(t)
	user := h.seedUser("spent")
	bearer := h.bearer(user)
	secret := h.seedTOTP(user)
	status, setup := h.do(http.MethodPost, "/api/v1/identity/users/me/mfa/setup", bearer, nil)
	if status != http.StatusOK {
		t.Fatalf("setup: status %d (%v)", status, setup)
	}
	newSecret, _ := setup["secret"].(string)
	proof := totpCode(t, secret, time.Now())

	// The proof passes, and the new code is wrong.
	status, out := h.do(http.MethodPost, "/api/v1/identity/users/me/mfa/enable", bearer,
		map[string]string{"code": "000000", "totp_code": proof})
	if status != http.StatusBadRequest {
		t.Fatalf("enable with a wrong new code: status %d (%v), want 400", status, out)
	}
	status, out = h.do(http.MethodPost, "/api/v1/identity/users/me/mfa/enable", bearer,
		map[string]string{"code": totpCode(t, newSecret, time.Now()), "totp_code": proof})
	if status != http.StatusForbidden || out["error"] != reauthFailed {
		t.Fatalf("the same proof code again: status %d (%v), want 403 %s", status, out, reauthFailed)
	}
	if got := h.scalar(`SELECT secret FROM mfa_totp WHERE user_id = $1::uuid`, user); got != secret {
		t.Fatal("the credential was replaced on a spent code")
	}
	// The next code from the same authenticator is proof again.
	status, out = h.do(http.MethodPost, "/api/v1/identity/users/me/mfa/enable", bearer,
		map[string]string{"code": totpCode(t, newSecret, time.Now()), "totp_code": totpCode(t, secret, time.Now().Add(30*time.Second))})
	if status != http.StatusOK {
		t.Fatalf("with the next code: status %d (%v), want 200", status, out)
	}
}

// An account with no password here -- one that signs in through an identity
// provider -- can still prove itself with its TOTP code where a code is
// accepted, and is told plainly when a change needs a password it does not
// have. A directory account's password is checked against the directory.
func TestAccountsWithoutALocalPassword(t *testing.T) {
	h := newSelfServiceHarness(t)

	t.Run("an identity-provider account", func(t *testing.T) {
		user := h.seedUser("federated")
		h.exec(`UPDATE users SET password_hash = NULL WHERE id = $1::uuid`, user)
		bearer := h.bearer(user)
		secret := h.seedTOTP(user)
		passkey := h.scalar(`INSERT INTO mfa_webauthn (user_id, credential_id, public_key, name, org_id)
			VALUES ($1::uuid, 'cred-federated', 'cose', 'Key', $2::uuid) RETURNING id::text`, user, middleware.DefaultOrgID)

		status, out := h.do(http.MethodDelete, "/api/v1/identity/mfa/webauthn/credentials/"+passkey, bearer,
			map[string]string{"current_password": "anything"})
		if status != http.StatusForbidden || out["error"] != reauthUnavailable || len(accepts(out)) != 0 {
			t.Fatalf("a change that needs a password the account lacks: status %d (%v), want 403 %s with nothing accepted",
				status, out, reauthUnavailable)
		}
		status, out = h.do(http.MethodPost, "/api/v1/identity/users/me/mfa/disable", bearer, nil)
		if status != http.StatusForbidden || strings.Join(accepts(out), ",") != "totp_code" {
			t.Fatalf("disabling MFA: status %d (%v), want 403 offering totp_code alone", status, out)
		}
		status, out = h.do(http.MethodPost, "/api/v1/identity/users/me/mfa/disable", bearer,
			map[string]string{"totp_code": totpCode(t, secret, time.Now())})
		if status != http.StatusOK {
			t.Fatalf("disabling MFA with a current code: status %d (%v), want 200", status, out)
		}
	})

	t.Run("a directory account", func(t *testing.T) {
		dir := &fakeDirectory{password: "directory-secret"}
		h.svc.SetDirectoryService(dir)
		t.Cleanup(func() { h.svc.SetDirectoryService(nil) })

		user := h.seedUser("directory")
		h.exec(`UPDATE users SET source = 'ldap', directory_id = gen_random_uuid() WHERE id = $1::uuid`, user)
		bearer := h.bearer(user)
		h.seedTOTP(user)

		if status, out := h.do(http.MethodPost, "/api/v1/identity/users/me/mfa/disable", bearer,
			map[string]string{"current_password": harnessPassword}); status != http.StatusForbidden || out["error"] != reauthFailed {
			t.Fatalf("the local hash's password for a directory account: status %d (%v), want 403 %s", status, out, reauthFailed)
		}
		if status, out := h.do(http.MethodPost, "/api/v1/identity/users/me/mfa/disable", bearer,
			map[string]string{"current_password": "directory-secret"}); status != http.StatusOK {
			t.Fatalf("the directory's password: status %d (%v), want 200", status, out)
		}
		if dir.calls < 2 {
			t.Errorf("the directory was asked %d times, want 2", dir.calls)
		}
	})
}

type fakeDirectory struct {
	password string
	calls    int
}

func (d *fakeDirectory) AuthenticateUser(_ context.Context, _, _, password string) error {
	d.calls++
	if password != d.password {
		return errors.New("invalid credentials")
	}
	return nil
}
func (d *fakeDirectory) ChangePassword(context.Context, string, string, string, string) error {
	return nil
}
func (d *fakeDirectory) ResetPassword(context.Context, string, string, string) error { return nil }

// An administrator's reset of someone else's factors is a separate path and
// stays one: minting a bypass code to sign in without the lost factor,
// revoking a user's bypass codes, setting a password the user can then give as
// proof, and taking back a hardware token. Each needs the admin role.
func TestAdministratorResetsNeedTheAdminRole(t *testing.T) {
	h := newSelfServiceHarness(t)
	target := h.seedUser("reset-target")
	h.seedTOTP(target)
	plain := h.seedUser("reset-plain")
	admin := h.seedUser("reset-admin")
	adminBearer := h.bearerWithRoles(admin, "admin")
	plainBearer := h.bearer(plain)

	tokenID := h.scalar(`INSERT INTO hardware_tokens (org_id, serial_number, token_type, secret_key, status, assigned_to, assigned_at)
		VALUES ($1::uuid, $2, 'oath-totp', 'seed', 'assigned', $3::uuid, NOW()) RETURNING id::text`,
		middleware.DefaultOrgID, "HW-"+h.suffix, target)

	for _, rt := range []struct {
		name, method, path string
		body               map[string]interface{}
		ok                 int
	}{
		{"mint a bypass code", http.MethodPost, "/api/v1/identity/mfa/bypass-codes",
			map[string]interface{}{"user_id": target, "reason": "lost phone", "valid_hours": 1, "max_uses": 1}, http.StatusCreated},
		{"revoke a user's bypass codes", http.MethodDelete, "/api/v1/identity/users/" + target + "/bypass-codes", nil, http.StatusOK},
		{"set a user's password", http.MethodPost, "/api/v1/identity/users/" + target + "/set-password",
			map[string]interface{}{"password": "A-new-password-for-the-user-9"}, http.StatusOK},
		{"take back a hardware token", http.MethodPost, "/api/v1/identity/hardware-tokens/" + tokenID + "/unassign", nil, http.StatusOK},
	} {
		t.Run(rt.name, func(t *testing.T) {
			if status, out := h.do(rt.method, rt.path, plainBearer, rt.body); status != http.StatusForbidden {
				t.Fatalf("a user without the admin role: status %d (%v), want 403", status, out)
			}
			if status, out := h.do(rt.method, rt.path, adminBearer, rt.body); status != rt.ok {
				t.Fatalf("an administrator: status %d (%v), want %d", status, out, rt.ok)
			}
		})
	}
}

// Regenerating the backup codes replaces the set. They used to accumulate, so
// a user who regenerated because a printed list went astray still had every
// code on it working.
func TestRegeneratingBackupCodesRetiresTheOldSet(t *testing.T) {
	h := newSelfServiceHarness(t)
	user := h.seedUser("backup-set")
	ctx := orgctx.With(h.seedCtx(), orgctx.Org{ID: middleware.DefaultOrgID})
	old, err := h.svc.GenerateBackupCodes(ctx, user, 5)
	if err != nil {
		t.Fatalf("seed backup codes: %v", err)
	}

	status, out := h.do(http.MethodPost, "/api/v1/identity/mfa/backup/generate", h.bearer(user),
		map[string]interface{}{"count": 8, "current_password": harnessPassword})
	if status != http.StatusOK {
		t.Fatalf("regenerate: status %d (%v), want 200", status, out)
	}
	fresh, _ := out["backup_codes"].([]interface{})
	if len(fresh) != 8 {
		t.Fatalf("regenerate answered %d codes, want 8", len(fresh))
	}
	if n := h.count(`SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id = $1::uuid AND NOT used`, user); n != 8 {
		t.Errorf("%d unused codes after regenerating 8, want 8: the old set is still live", n)
	}
	if ok, _ := h.svc.ValidateBackupCode(ctx, user, old[0]); ok {
		t.Error("a code from the old set still verifies")
	}
	if code, _ := fresh[0].(string); code == "" {
		t.Fatal("the new set holds an empty code")
	} else if ok, err := h.svc.ValidateBackupCode(ctx, user, code); !ok || err != nil {
		t.Errorf("a code from the new set: ok=%v err=%v, want true", ok, err)
	}
}

// A device enrollment in the access service (POST /agent/enroll/session with a
// bearer token, then the agent's enrollment) mints a push-enrollment ticket, so
// the phone becomes a push approver without the push devices page. Nothing on
// that path asks for proof, so its ticket binds a first factor only, or
// re-registers a phone the account already has; the start route's ticket,
// which asked for the password, binds a phone to any account.
func TestADeviceEnrollmentTicketBindsOnlyAFirstFactor(t *testing.T) {
	h := newSelfServiceHarness(t)
	ctx := h.seedCtx()
	agentTicket := func(user string) string {
		t.Helper()
		tok, err := pushenroll.Mint(ctx, h.svc.redis.Client, pushenroll.TicketData{
			UserID: user, OrgID: middleware.DefaultOrgID,
			AgentID: "agent-" + randomTag(), DeviceID: "device-" + randomTag(), EnrollmentSessionID: uuid.NewString(),
		}, 0)
		if err != nil {
			t.Fatalf("mint ticket: %v", err)
		}
		return tok
	}
	complete := func(ticket, deviceToken string) (int, map[string]interface{}) {
		t.Helper()
		return h.do(http.MethodPost, "/api/v1/identity/mfa/push/enroll/complete", "", map[string]interface{}{
			"enrollment_token": ticket, "device_token": deviceToken, "platform": "android", "device_name": "Pixel",
		})
	}
	devices := func(user string) int {
		return h.count(`SELECT COUNT(*) FROM mfa_push_devices WHERE user_id = $1::uuid`, user)
	}

	protected := h.seedUser("ticket-protected")
	h.seedTOTP(protected)
	if status, out := complete(agentTicket(protected), "attacker-phone-"+randomTag()); status != http.StatusBadRequest {
		t.Fatalf("an agent ticket for an account with a second factor: status %d (%v), want 400", status, out)
	}
	if n := devices(protected); n != 0 {
		t.Fatalf("an agent ticket bound %d phones to an account with a second factor", n)
	}

	fresh := h.seedUser("ticket-fresh")
	phone := "first-phone-" + randomTag()
	if status, out := complete(agentTicket(fresh), phone); status != http.StatusCreated {
		t.Fatalf("an agent ticket for an account with no factor: status %d (%v), want 201", status, out)
	}
	if status, out := complete(agentTicket(fresh), phone); status != http.StatusCreated {
		t.Fatalf("the same phone enrolled again: status %d (%v), want 201", status, out)
	}
	if status, out := complete(agentTicket(fresh), "second-phone-"+randomTag()); status != http.StatusBadRequest {
		t.Fatalf("a second phone by agent ticket: status %d (%v), want 400", status, out)
	}
	if n := devices(fresh); n != 1 {
		t.Fatalf("the account holds %d phones, want 1", n)
	}

	// The start route asks for the password, and its ticket binds a phone to
	// an account that has a second factor.
	status, out := h.do(http.MethodPost, "/api/v1/identity/mfa/push/enroll/start", h.bearer(protected),
		map[string]string{"current_password": harnessPassword})
	if status != http.StatusOK {
		t.Fatalf("start with the password: status %d (%v), want 200", status, out)
	}
	ticket, _ := out["enrollment_token"].(string)
	if ticket == "" {
		t.Fatalf("start answered no enrollment_token: %v", out)
	}
	if status, out := complete(ticket, "own-phone-"+randomTag()); status != http.StatusCreated {
		t.Fatalf("completing the start route's ticket: status %d (%v), want 201", status, out)
	}
}

// softAttestation is what a security key with no attestation statement
// ("none") answers to the registration ceremony `begin` started, for rpID and
// origin: a fresh P-256 key, a random credential id.
func softAttestation(t *testing.T, begin map[string]interface{}, rpID, origin string) map[string]interface{} {
	t.Helper()
	pk, _ := begin["publicKey"].(map[string]interface{})
	challenge, _ := pk["challenge"].(string)
	if challenge == "" {
		t.Fatalf("register/begin answered no challenge: %v", begin)
	}
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	point := key.PublicKey().Bytes() // 0x04 || X || Y
	cose := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	cose = append(cose, point[1:33]...)
	cose = append(cose, 0x22, 0x58, 0x20)
	cose = append(cose, point[33:65]...)

	credID := make([]byte, 16)
	_, _ = rand.Read(credID)
	rpHash := sha256.Sum256([]byte(rpID))
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, 0x41)                // user present, attested credential data
	authData = append(authData, 0, 0, 0, 0)          // sign count
	authData = append(authData, make([]byte, 16)...) // AAGUID
	authData = append(authData, 0, byte(len(credID)))
	authData = append(authData, credID...)
	authData = append(authData, cose...)

	att := []byte{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e',
		0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0,
		0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a', 0x58, byte(len(authData))}
	att = append(att, authData...)

	clientData, _ := json.Marshal(map[string]interface{}{
		"type": "webauthn.create", "challenge": challenge, "origin": origin, "crossOrigin": false,
	})
	b64 := base64.RawURLEncoding.EncodeToString
	return map[string]interface{}{
		"id": b64(credID), "rawId": b64(credID), "type": "public-key",
		"response": map[string]interface{}{
			"clientDataJSON":    b64(clientData),
			"attestationObject": b64(att),
		},
	}
}
