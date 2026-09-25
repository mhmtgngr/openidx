package oauth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/gin-gonic/gin"
)

// OpenID Connect Core §3.1.2.1: the authorization endpoint MUST support GET
// and POST. POST /oauth/authorize was only the consent endpoint, behind
// flowAuth, so the conformance suite's oidcc-ensure-post-request-succeeds got a
// 401 for a well-formed authorization request. These drive the mounted routes.

// authorizeRequest is a valid request for ssoTestClient (a public client, so it
// carries a PKCE challenge), plus extra.
func authorizeRequest(extra url.Values) url.Values {
	q := url.Values{
		"client_id":             {"c"},
		"redirect_uri":          {ssoTestRedirect},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"st-1"},
		"nonce":                 {"n-1"},
		"code_challenge":        {testCodeChallenge},
		"code_challenge_method": {"S256"},
	}
	for k, vs := range extra {
		q[k] = vs
	}
	return q
}

// flowAuthRecorder stands in for the production auth middleware: with no
// bearer token it refuses with a body only it produces, so a test can tell a
// flowAuth refusal from the consent handler's own.
type flowAuthRecorder struct{ ran int }

func (f *flowAuthRecorder) middleware(c *gin.Context) {
	f.ran++
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "flow_auth_refused"})
}

func authorizeGET(r *gin.Engine, q url.Values) *httptest.ResponseRecorder {
	return serve(r, http.MethodGet, "/oauth/authorize?"+q.Encode(), "", "")
}

func authorizePOST(r *gin.Engine, q url.Values) *httptest.ResponseRecorder {
	return serve(r, http.MethodPost, "/oauth/authorize", "application/x-www-form-urlencoded", q.Encode())
}

func TestAuthorizationRequestByPOSTIsServedLikeGET(t *testing.T) {
	svc := newLoginUITestService(t, "", ssoTestClient())
	flowAuth := &flowAuthRecorder{}
	r := routedService(t, svc, ssoTestOrg, flowAuth.middleware)

	t.Run("a form POST reaches the login UI with the same pending request as a GET", func(t *testing.T) {
		q := authorizeRequest(nil)
		getSession, _ := loginSessionOf(t, authorizeGET(r, q))

		w := authorizePOST(r, q)
		if flowAuth.ran != 0 {
			t.Fatalf("the authorization request was sent through flowAuth (%d times); the authorization endpoint is public", flowAuth.ran)
		}
		postSession, _ := loginSessionOf(t, w)

		got, want := stashOf(t, svc, postSession), stashOf(t, svc, getSession)
		if len(got) != len(want) {
			t.Fatalf("POST stashed %v, GET stashed %v", got, want)
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("pending request %s = %q after POST, %q after GET", k, got[k], v)
			}
		}
		// The two values a relying party checks on the way back.
		if got["state"] != "st-1" || got["nonce"] != "n-1" {
			t.Errorf("state/nonce lost from a POSTed request: %v", got)
		}
	})

	t.Run("a Content-Type with parameters is still a form", func(t *testing.T) {
		w := serve(r, http.MethodPost, "/oauth/authorize",
			"application/x-www-form-urlencoded; charset=UTF-8", authorizeRequest(nil).Encode())
		loginSessionOf(t, w)
	})

	t.Run("request errors are answered as they are for GET", func(t *testing.T) {
		// Reported to the client once redirect_uri is validated (RFC 6749 §4.1.2.1)...
		w := authorizePOST(r, authorizeRequest(url.Values{"scope": {"openid admin"}}))
		u := locationOf(t, w)
		if u.Host != "app.example.test" || u.Query().Get("error") != ErrorInvalidScope || u.Query().Get("state") != "st-1" {
			t.Fatalf("an invalid scope by POST answered %s, want invalid_scope with state at the client", u)
		}
		// ...and in-band when it is not.
		w = authorizePOST(r, authorizeRequest(url.Values{"redirect_uri": {"https://evil.example/cb"}}))
		if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
			t.Fatalf("an unregistered redirect_uri by POST answered %d Location=%q, want 400 in-band",
				w.Code, w.Header().Get("Location"))
		}
		// A POST's parameters are its body: the same request in the query
		// string of an empty-bodied form POST is not an authorization request.
		w = serve(r, http.MethodPost, "/oauth/authorize?"+authorizeRequest(nil).Encode(),
			"application/x-www-form-urlencoded", "")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("a form POST with its parameters in the query string answered %d, want 400 (no client_id)", w.Code)
		}
	})

	t.Run("the JSON consent submission still goes through flowAuth", func(t *testing.T) {
		before := flowAuth.ran
		body, _ := json.Marshal(map[string]string{"client_id": "c", "redirect_uri": ssoTestRedirect})
		w := serve(r, http.MethodPost, "/oauth/authorize", "application/json", string(body))
		if flowAuth.ran != before+1 {
			t.Fatal("a JSON POST to /oauth/authorize skipped flowAuth; the consent endpoint needs an authenticated session")
		}
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "flow_auth_refused") {
			t.Fatalf("got %d %s, want flowAuth's refusal", w.Code, w.Body.String())
		}
	})

	t.Run("without flowAuth a JSON POST reaches the consent handler", func(t *testing.T) {
		// Development mounts the interactive routes without flowAuth; the
		// consent handler then refuses on its own for want of a session.
		dev := routedService(t, svc, ssoTestOrg, nil)
		w := serve(dev, http.MethodPost, "/oauth/authorize", "application/json", "{}")
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "authenticated session required") {
			t.Fatalf("got %d %s, want handleAuthorizeConsent's own refusal", w.Code, w.Body.String())
		}
	})
}

// OIDC Core §6: a request object this server does not process is refused with
// request_not_supported / request_uri_not_supported at the redirect_uri, and
// never ignored. Ignoring it lost the state and nonce a client put inside it
// (oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported).
func TestRequestObjectsAreRefusedAtTheRedirectURI(t *testing.T) {
	svc := newLoginUITestService(t, "", ssoTestClient())
	svc.authorizeHandler = NewAuthorizeHandler(svc, zap.NewNop())
	r := routedService(t, svc, ssoTestOrg, (&flowAuthRecorder{}).middleware)

	// An unsigned request object (alg none) holding the state and nonce, the
	// shape the conformance suite sends.
	enc := base64.RawURLEncoding.EncodeToString
	requestObject := enc([]byte(`{"alg":"none"}`)) + "." +
		enc([]byte(`{"client_id":"c","response_type":"code","state":"inner-state","nonce":"inner-nonce"}`)) + "."

	refusal := func(t *testing.T, w *httptest.ResponseRecorder, wantError, wantState string) {
		t.Helper()
		u := locationOf(t, w)
		if u.Host != "app.example.test" || u.Path != "/callback" {
			t.Fatalf("answered %s, want the client's redirect_uri", u)
		}
		if got := u.Query().Get("error"); got != wantError {
			t.Fatalf("error = %q, want %q (%s)", got, wantError, u)
		}
		if got := u.Query().Get("state"); got != wantState {
			t.Errorf("state = %q, want %q", got, wantState)
		}
		if u.Query().Get("code") != "" {
			t.Error("a code was issued for a request whose object was not processed")
		}
	}

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		send := authorizeGET
		if method == http.MethodPost {
			send = authorizePOST
		}
		t.Run(method+" request", func(t *testing.T) {
			refusal(t, send(r, authorizeRequest(url.Values{"request": {requestObject}})),
				ErrorRequestNotSupported, "st-1")
		})
		t.Run(method+" request with state only inside the object", func(t *testing.T) {
			q := authorizeRequest(url.Values{"request": {requestObject}})
			q.Del("state")
			q.Del("nonce")
			// The object is not opened, so its state is not echoed.
			refusal(t, send(r, q), ErrorRequestNotSupported, "")
		})
		t.Run(method+" request_uri", func(t *testing.T) {
			refusal(t, send(r, authorizeRequest(url.Values{"request_uri": {"https://rp.example.test/ro.jwt"}})),
				ErrorRequestURINotSupported, "st-1")
		})
		t.Run(method+" request with an unregistered redirect_uri stays in-band", func(t *testing.T) {
			// oidcc-ensure-request-object-with-redirect-uri: the valid
			// redirect_uri is inside the object, an invalid one outside. The
			// refusal must not be sent to the unregistered address.
			w := send(r, authorizeRequest(url.Values{
				"request":      {requestObject},
				"redirect_uri": {"https://evil.example/cb"},
			}))
			if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
				t.Fatalf("got %d Location=%q, want 400 in-band", w.Code, w.Header().Get("Location"))
			}
		})
	}

	t.Run("the v2 authorization endpoint refuses them too", func(t *testing.T) {
		w := serve(r, http.MethodGet, "/oauth/authorize/v2?"+authorizeRequest(url.Values{"request": {requestObject}}).Encode(), "", "")
		refusal(t, w, ErrorRequestNotSupported, "st-1")
	})
}
