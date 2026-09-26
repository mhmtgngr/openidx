package access

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// loginSessionPattern is the one shape of login_session the OAuth service
// mints: GenerateRandomToken(32), thirty-two random bytes in padded base64url.
// The callback serves its sign-in page for that shape only, so nothing else a
// link carries reaches the page at all.
var loginSessionPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}=$`)

// loginPageOriginPattern is what an OAuth issuer's origin may look like before
// it is written into the page's Content-Security-Policy, where a space or a
// semicolon would start another directive.
var loginPageOriginPattern = regexp.MustCompile(`^https?://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?$`)

// loginPageData is everything the sign-in page shows that is not markup.
// html/template escapes each value for the context it lands in: the two
// strings in the script become JavaScript string literals, so a value cannot
// close the script element or the string.
type loginPageData struct {
	Nonce        string
	LoginSession string
	OAuthURL     string
}

// loginPageTemplate is the sign-in form the callback serves for a pending
// login_session. Its script and style carry the response's nonce: the policy
// the page is served with admits nothing inline without it.
//
// The form never submits itself. The script sends the credentials to the
// OAuth service with fetch, and the policy's form-action 'none' stops a
// browser that is not running the script from sending them anywhere.
var loginPageTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenIDX - Sign In</title>
<style nonce="{{.Nonce}}">
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;border-radius:12px;padding:2.5rem;width:100%;max-width:400px;box-shadow:0 25px 50px rgba(0,0,0,.3)}
h1{font-size:1.5rem;text-align:center;margin-bottom:.5rem;color:#f8fafc}
.subtitle{text-align:center;color:#94a3b8;margin-bottom:2rem;font-size:.875rem}
label{display:block;font-size:.875rem;color:#94a3b8;margin-bottom:.375rem}
input{width:100%;padding:.75rem 1rem;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#f8fafc;font-size:1rem;margin-bottom:1rem;outline:none;transition:border-color .2s}
input:focus{border-color:#3b82f6}
button{width:100%;padding:.75rem;background:#3b82f6;color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer;transition:background .2s}
button:hover{background:#2563eb}
button:disabled{opacity:.6;cursor:not-allowed}
.error{background:#7f1d1d;border:1px solid #991b1b;color:#fca5a5;padding:.75rem;border-radius:8px;margin-bottom:1rem;font-size:.875rem;display:none}
.mfa-section{display:none}
.logo{text-align:center;margin-bottom:1.5rem;font-size:2rem}
</style>
</head>
<body>
<div class="card">
<div class="logo">&#x1f510;</div>
<h1>OpenIDX Access</h1>
<p class="subtitle">Sign in to continue to your application</p>
<div id="error" class="error"></div>
<form id="loginForm">
<div id="credentials-section">
<label for="username">Username or Email</label>
<input type="text" id="username" name="username" required autocomplete="username" autofocus>
<label for="password">Password</label>
<input type="password" id="password" name="password" required autocomplete="current-password">
</div>
<div id="mfa-section" class="mfa-section">
<label for="mfa_code">MFA Verification Code</label>
<input type="text" id="mfa_code" name="mfa_code" placeholder="Enter 6-digit code" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6">
</div>
<button type="submit" id="submitBtn">Sign In</button>
</form>
</div>
<script nonce="{{.Nonce}}">
const loginSession = {{.LoginSession}};
const oauthURL = {{.OAuthURL}};
let mfaSession = '';

document.getElementById('loginForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const errEl = document.getElementById('error');
  errEl.style.display = 'none';
  const btn = document.getElementById('submitBtn');
  btn.disabled = true;
  btn.textContent = 'Signing in...';

  try {
    if (mfaSession) {
      const resp = await fetch(oauthURL + '/oauth/mfa-verify', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({mfa_session: mfaSession, code: document.getElementById('mfa_code').value})
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error_description || data.error || 'MFA verification failed');
      }
      if (data.redirect_url) {
        window.location.href = data.redirect_url;
        return;
      }
    } else {
      const resp = await fetch(oauthURL + '/oauth/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          username: document.getElementById('username').value,
          password: document.getElementById('password').value,
          login_session: loginSession
        })
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error_description || data.error || 'Authentication failed');
      }
      if (data.mfa_required) {
        mfaSession = data.mfa_session;
        document.getElementById('credentials-section').style.display = 'none';
        document.getElementById('mfa-section').style.display = 'block';
        document.getElementById('mfa_code').focus();
        btn.disabled = false;
        btn.textContent = 'Verify';
        return;
      }
      if (data.redirect_url) {
        window.location.href = data.redirect_url;
        return;
      }
    }
  } catch(err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  }
  btn.disabled = false;
  btn.textContent = mfaSession ? 'Verify' : 'Sign In';
});
</script>
</body>
</html>
`))

// serveLoginPage writes the sign-in form for a login_session the caller has
// already checked against loginSessionPattern.
//
// The page used to be built with fmt.Sprintf and %q, which escapes for Go and
// not for HTML, so a login_session carrying </script> ended the script element
// and the rest of it was markup on the proxied application's own origin: a
// fake form, a <base> for the page's relative URLs, or script wherever the
// policy allowed inline code. It was served under the service-wide policy,
// whose script-src 'self' also refused the page's own inline script, so the
// form never worked and its Sign In button submitted the password in the URL.
//
// The page now gets its own policy. A fresh nonce admits its one script and
// its one style block; connect-src names the OAuth issuer the script posts to;
// form-action, base-uri, object-src and frame-ancestors admit nothing. The
// header replaces the service-wide one, so an operator's OPENIDX_CSP_POLICY
// cannot loosen this page and a second policy cannot block its script.
func (s *Service) serveLoginPage(c *gin.Context, loginSession string) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		s.logger.Error("could not draw a nonce for the sign-in page", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not render the sign-in page"})
		return
	}
	nonce := hex.EncodeToString(raw)

	var page bytes.Buffer
	if err := loginPageTemplate.Execute(&page, loginPageData{
		Nonce:        nonce,
		LoginSession: loginSession,
		OAuthURL:     strings.TrimRight(s.oauthIssuer, "/"),
	}); err != nil {
		s.logger.Error("could not render the sign-in page", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not render the sign-in page"})
		return
	}

	c.Header("Content-Security-Policy", loginPageCSP(nonce, s.oauthIssuer))
	// The URL carries the login_session, and the page is good for one sign-in.
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	c.Data(http.StatusOK, "text/html; charset=utf-8", page.Bytes())
}

// loginPageCSP is the policy the sign-in page is served with. connect-src is
// the issuer's origin because that is where the script sends the credentials;
// an issuer that does not parse as an http(s) origin leaves it 'none', and the
// page then cannot post anywhere.
func loginPageCSP(nonce, issuer string) string {
	connect := "'none'"
	if origin := httpOrigin(issuer); origin != "" {
		connect = origin
	}
	return "default-src 'none'; " +
		"script-src 'nonce-" + nonce + "'; " +
		"style-src 'nonce-" + nonce + "'; " +
		"connect-src " + connect + "; " +
		"form-action 'none'; " +
		"base-uri 'none'; " +
		"object-src 'none'; " +
		"frame-ancestors 'none'"
}

// httpOrigin returns the scheme://host[:port] origin of an http(s) URL, in
// lower case, or "" when raw is not one.
func httpOrigin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return ""
	}
	origin := strings.ToLower(u.Scheme + "://" + u.Host)
	if !loginPageOriginPattern.MatchString(origin) {
		return ""
	}
	return origin
}
