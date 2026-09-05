package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The checks in front of MFA verification.
//
// handleMFAVerify is where a partially-authenticated login becomes a session.
// Everything it does after the switch needs a database, but everything BEFORE
// the switch decides whether verification runs at all and against which factor
// — and that is where the interesting failure lives, so these tests stop at the
// first identityService call and never make one.

// mfaSessionData is what /oauth/login writes to Redis (createMFASession).
func putMFASession(t *testing.T, s *Service, id string, data map[string]string) {
	t.Helper()
	payload, err := json.Marshal(data)
	require.NoError(t, err)
	require.NoError(t, s.redis.Client.Set(context.Background(), "mfa_session:"+id, string(payload), 0).Err())
}

// postJSON runs one handler and returns what it wrote.
//
// The router recovers, and that is load-bearing rather than tidiness: every
// verifier past the gate needs an identity service this harness does not build,
// so reaching one is a nil dereference. Recovering turns "it got through the
// gate" into an observable 500 and keeps each case independent — without it the
// first case that passes the gate panics and takes the rest of the run with it.
func postJSON(t *testing.T, h gin.HandlerFunc, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.RecoveryWithWriter(io.Discard))
	r.POST("/x", h)

	var buf bytes.Buffer
	require.NoError(t, json.NewEncoder(&buf).Encode(body))
	req := httptest.NewRequest(http.MethodPost, "/x", &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func postRaw(t *testing.T, h gin.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.RecoveryWithWriter(io.Discard))
	r.POST("/x", h)
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func errorDescription(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	desc, _ := got["error_description"].(string)
	return desc
}

// --------------------------------------------------------------------------
// The risk policy's method restriction, which was written down and never read.
// --------------------------------------------------------------------------

// evaluateMFA filters the offerable factors by what the adaptive-MFA policy
// allows (mfa_policy.go), createMFASession pins that list into the session, and
// service.go's own comment says the pin exists "so a later /oauth/mfa-verify
// cannot be talked into a method this evaluation did not offer". Nothing read
// it: the console offered the narrowed list and the endpoint took whatever it
// was handed, so a login the policy had restricted to webauthn was completable
// with a TOTP code, a backup code or a bypass code.
//
// Every case below with a non-empty allowed_methods is red before the fix.
func TestMFAVerifyRefusesAMethodTheRiskPolicyExcluded(t *testing.T) {
	cases := []struct {
		name    string
		allowed string
		method  string
		ok      bool
	}{
		{"webauthn-only challenge refuses sms", "webauthn", "sms", false},
		{"webauthn-only challenge refuses email", "webauthn", "email", false},
		{"webauthn-only challenge refuses totp", "webauthn", "totp", false},
		{"webauthn-only challenge refuses a bypass code", "webauthn", "bypass", false},
		{"webauthn-only challenge refuses a backup code", "webauthn", "backup", false},
		{"webauthn-only challenge permits webauthn", "webauthn", "webauthn", true},
		{"a narrowed list permits any member", "webauthn,push", "push", true},
		{"a narrowed list refuses a non-member", "webauthn,push", "email", false},
		{"whitespace in the stored list is tolerated", "webauthn, push", "push", true},
		// The default. An omitted method means totp, so a challenge that does
		// not offer totp must refuse the omission too, not fall through it.
		{"an omitted method is totp and is refused when totp is excluded", "webauthn", "", false},
		// No pin: sessions from the passwordless path (which pins a single
		// required method instead) and any session minted by an older build
		// during a rollout. Unrestricted, as before.
		{"an unpinned session is unrestricted", "", "sms", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, cleanup := newTestServiceWithRedis(t)
			defer cleanup()

			data := map[string]string{"user_id": "user-1"}
			if tc.allowed != "" {
				data["allowed_methods"] = tc.allowed
			}
			putMFASession(t, svc, "sess-1", data)

			body := map[string]interface{}{"mfa_session": "sess-1", "code": "123456"}
			if tc.method != "" {
				body["method"] = tc.method
			}

			if !tc.ok {
				w := postJSON(t, svc.handleMFAVerify, body)
				assert.Equal(t, 400, w.Code)
				assert.Contains(t, errorDescription(t, w), "cannot be completed with")
				return
			}
			// A permitted method reaches the verifier and dies there on the
			// identity service this harness does not build, which the router
			// records as a 500. That 500 IS the observation that the gate let
			// it through; a 400 would mean it did not.
			w := postJSON(t, svc.handleMFAVerify, body)
			assert.Equal(t, 500, w.Code, "a permitted method must reach the verifier")
		})
	}
}

// The same restriction on the three endpoints that START a factor. An excluded
// factor should not be startable either: leaving those open means an SMS is
// sent, a push lands on someone's phone, and only the final step refuses.
func TestMFAChallengeStartersRefuseAnExcludedMethod(t *testing.T) {
	t.Run("mfa-send-otp", func(t *testing.T) {
		for _, method := range []string{"sms", "email"} {
			svc, _, cleanup := newTestServiceWithRedis(t)
			putMFASession(t, svc, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", map[string]string{
				"user_id": "user-1", "allowed_methods": "webauthn,push",
			})
			w := postJSON(t, svc.handleMFASendOTP, map[string]interface{}{
				"mfa_session": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "method": method,
			})
			assert.Equal(t, 400, w.Code, method)
			assert.Contains(t, errorDescription(t, w), "cannot be completed with "+method)
			cleanup()
		}
	})

	t.Run("mfa-webauthn-begin", func(t *testing.T) {
		svc, _, cleanup := newTestServiceWithRedis(t)
		defer cleanup()
		putMFASession(t, svc, "sess-1", map[string]string{
			"user_id": "user-1", "allowed_methods": "sms",
		})
		w := postJSON(t, svc.handleMFAWebAuthnBegin, map[string]interface{}{"mfa_session": "sess-1"})
		assert.Equal(t, 400, w.Code)
		assert.Contains(t, errorDescription(t, w), "cannot be completed with webauthn")
	})

	t.Run("mfa-push-begin", func(t *testing.T) {
		svc, _, cleanup := newTestServiceWithRedis(t)
		defer cleanup()
		putMFASession(t, svc, "sess-1", map[string]string{
			"user_id": "user-1", "allowed_methods": "totp",
		})
		w := postJSON(t, svc.handleMFAPushBegin, map[string]interface{}{"mfa_session": "sess-1"})
		assert.Equal(t, 400, w.Code)
		assert.Contains(t, errorDescription(t, w), "cannot be completed with push")
	})
}

// The passwordless pin, which WAS enforced. Kept beside the new one so the two
// restrictions are visibly different things: this one names a single required
// method, the one above names the set the risk evaluation offered.
func TestMFAVerifyHonoursThePasswordlessMethodPin(t *testing.T) {
	svc, _, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	putMFASession(t, svc, "sess-1", map[string]string{
		"user_id":             "user-1",
		"passwordless":        "phone",
		"required_mfa_method": "push",
	})

	w := postJSON(t, svc.handleMFAVerify, map[string]interface{}{
		"mfa_session": "sess-1", "code": "123456", "method": "totp",
	})
	assert.Equal(t, 400, w.Code)
	assert.Contains(t, errorDescription(t, w), "must be completed with push")
}

// --------------------------------------------------------------------------
// The rest of the pre-verification gate.
// --------------------------------------------------------------------------

func TestMFAVerifyRejectsMalformedAndIncompleteRequests(t *testing.T) {
	svc, _, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	t.Run("body that is not JSON", func(t *testing.T) {
		w := postRaw(t, svc.handleMFAVerify, "{not json")
		assert.Equal(t, 400, w.Code)
	})
	t.Run("no session", func(t *testing.T) {
		w := postJSON(t, svc.handleMFAVerify, map[string]interface{}{"code": "123456"})
		assert.Equal(t, 400, w.Code)
		assert.Contains(t, errorDescription(t, w), "required")
	})
	t.Run("no code", func(t *testing.T) {
		w := postJSON(t, svc.handleMFAVerify, map[string]interface{}{"mfa_session": "sess-1"})
		assert.Equal(t, 400, w.Code)
		assert.Contains(t, errorDescription(t, w), "required")
	})
	t.Run("a session that does not exist", func(t *testing.T) {
		w := postJSON(t, svc.handleMFAVerify, map[string]interface{}{"mfa_session": "nope", "code": "123456"})
		assert.Equal(t, 400, w.Code)
		assert.Contains(t, errorDescription(t, w), "invalid or expired MFA session")
	})
	t.Run("an unsupported method is refused, not defaulted", func(t *testing.T) {
		// A method the switch does not know must land in the default arm. If it
		// ever fell through to a verifier instead, "method": "none" would be a
		// login.
		putMFASession(t, svc, "sess-ok", map[string]string{"user_id": "user-1"})
		w := postJSON(t, svc.handleMFAVerify, map[string]interface{}{
			"mfa_session": "sess-ok", "code": "123456", "method": "none",
		})
		assert.Equal(t, 400, w.Code)
		assert.Contains(t, errorDescription(t, w), "unsupported MFA method")
	})
}

// handleMFASendOTP guards its session id against Redis key injection before it
// builds the key; handleMFAVerify does not, which is the asymmetry this pins.
// Both are bounded to the mfa_session: namespace by construction (go-redis
// frames the command, so a newline is a key byte, not a second command), so
// this is about the endpoint refusing shapes it never mints — not a bypass.
func TestMFASendOTPRefusesASessionIDItWouldNeverHaveMinted(t *testing.T) {
	svc, _, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	for _, id := range []string{
		"short",
		"550e8400-e29b-41d4-a716:malicious",
		"550e8400-e29b-41d4-a716-44665544000*",
		"../../../etc/passwd--invalid-shape-x",
	} {
		w := postJSON(t, svc.handleMFASendOTP, map[string]interface{}{"mfa_session": id, "method": "sms"})
		assert.Equal(t, 400, w.Code, id)
		assert.Contains(t, errorDescription(t, w), "invalid mfa_session format", id)
	}
}

func TestMFASendOTPRejectsAMethodItCannotSend(t *testing.T) {
	svc, _, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	// Checked before the session is loaded: only sms and email have a sender.
	for _, method := range []string{"", "totp", "push", "webauthn", "carrier-pigeon"} {
		w := postJSON(t, svc.handleMFASendOTP, map[string]interface{}{
			"mfa_session": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "method": method,
		})
		assert.Equal(t, 400, w.Code, method)
		assert.Contains(t, errorDescription(t, w), "must be 'sms' or 'email'", method)
	}
}

func TestMFASendOTPRefusesASessionWithNoUser(t *testing.T) {
	svc, _, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	// A session whose payload parses but names nobody would otherwise send an
	// OTP for the empty user id.
	putMFASession(t, svc, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", map[string]string{"location": "TR"})
	w := postJSON(t, svc.handleMFASendOTP, map[string]interface{}{
		"mfa_session": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "method": "sms",
	})
	assert.Equal(t, 400, w.Code)
	assert.Contains(t, errorDescription(t, w), "missing user identity")
}

// --------------------------------------------------------------------------
// The parser under both restrictions.
// --------------------------------------------------------------------------

func TestAllowedMFAMethodsParsing(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{",,", nil},
		{"totp", []string{"totp"}},
		{"totp,webauthn", []string{"totp", "webauthn"}},
		{" totp , webauthn ", []string{"totp", "webauthn"}},
		{"totp,,webauthn", []string{"totp", "webauthn"}},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, allowedMFAMethods(map[string]string{"allowed_methods": tc.in}), tc.in)
	}
	assert.Nil(t, allowedMFAMethods(map[string]string{}), "an absent key is not a restriction")
}

// --------------------------------------------------------------------------
// The two verifier switches, which are supposed to be the same one.
// --------------------------------------------------------------------------

// verifyStepUpFactor's doc comment says it verifies "using the same verifiers
// as the primary login MFA flow (handleMFAVerify)". They had drifted: step-up
// handled "sms" and "email" and handleMFAVerify's switch had no arm for either,
// so evaluateMFA offered SMS, handleMFASendOTP delivered the code, and the
// endpoint that consumes it answered "unsupported MFA method" — a user whose
// only enrolled factor was an OTP could not log in, while the same credential
// re-authenticated them for a sensitive action.
//
// Both halves are read from the source rather than exercised, because
// exercising either needs the identity service. A method that appears in one
// switch and not the other fails here.
func TestLoginAndStepUpVerifyTheSameMethods(t *testing.T) {
	src, err := os.ReadFile("service.go")
	require.NoError(t, err)
	stepup, err := os.ReadFile("stepup.go")
	require.NoError(t, err)

	login := switchMethods(t, string(src), "func (s *Service) handleMFAVerify(")
	step := switchMethods(t, string(stepup), "func (s *Service) verifyStepUpFactor(")

	assert.Equal(t, step, login,
		"handleMFAVerify and verifyStepUpFactor must accept the same factors; "+
			"a method in one and not the other is offered somewhere and refused somewhere else")
	// A guard on the guard: an empty set on either side would make the equality
	// above vacuous.
	assert.Contains(t, login, "totp")
	assert.Contains(t, login, "sms")
	assert.Contains(t, login, "webauthn")
}

// switchMethods collects the case labels of the FIRST `switch` inside the named
// function — the method dispatch in both of these functions.
func switchMethods(t *testing.T, source, funcHeader string) []string {
	t.Helper()
	i := strings.Index(source, funcHeader)
	require.GreaterOrEqual(t, i, 0, "did not find %s", funcHeader)
	body := source[i:]

	inSwitch := false
	var methods []string
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if !inSwitch {
			if strings.HasPrefix(trimmed, "switch req.Method") || strings.HasPrefix(trimmed, "switch method") {
				inSwitch = true
			}
			continue
		}
		if strings.HasPrefix(trimmed, "default:") {
			break
		}
		if !strings.HasPrefix(trimmed, "case ") {
			continue
		}
		for _, part := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(trimmed, "case "), ":"), ",") {
			if m := strings.Trim(strings.TrimSpace(part), `"`); m != "" {
				methods = append(methods, m)
			}
		}
	}
	require.NotEmpty(t, methods, "no case labels found in %s", funcHeader)
	sort.Strings(methods)
	return methods
}
