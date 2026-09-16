package docker

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A CHALLENGE THE BROWSER IS NOT ALLOWED TO LOAD IS NOT A CHALLENGE.
//
// The login page renders Cloudflare Turnstile when the bot gate refuses a
// login and sends a site key (web/admin-console/src/components/turnstile-
// challenge.tsx, and challengeRefusal in internal/oauth). That widget is a
// script from challenges.cloudflare.com which draws itself in an iframe from
// the same origin, so a Content-Security-Policy of script-src 'self' with no
// frame-src blocks BOTH halves -- and blocks them silently, in the browser,
// long after every test in this repository has passed.
//
// Measured on this tree when the widget was added:
//
//   - nginx/admin-console.conf, the config the shipped console image actually
//     uses, sets no CSP at all. The widget loads there today.
//   - oidx-nginx/nginx.conf serves the SPA itself (root + try_files) and sets
//     a document CSP three times. Two of those serve documents.
//   - conf.d/openidx.tdv.org.conf sets one, for a deployment that fronts the
//     console.
//
// So this was a live break in two of the three, and the fix is one pinned
// origin in the directives Turnstile needs, in the blocks that serve the
// LOGIN DOCUMENT -- not in the static-asset block, which serves no document
// and keeps the narrower policy.
//
// The guard is derived in both directions: the allowance must exist while the
// console uses Turnstile, and the console's use of it is read from the console
// rather than assumed, so removing the widget makes this test say the
// allowance is now an unnecessary widening.

const challengeOrigin = "https://challenges.cloudflare.com"

// documentCSPConfigs are the nginx configs that set a CSP on a response that
// is (or may be) the console's HTML document.
var documentCSPConfigs = []string{
	"oidx-nginx/nginx.conf",
	"nginx/conf.d/openidx.tdv.org.conf",
}

func consoleUsesTurnstile(t *testing.T) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "web", "admin-console", "src", "components", "turnstile-challenge.tsx"))
	if err != nil {
		return false
	}
	return strings.Contains(string(b), challengeOrigin)
}

// cspHeaders returns every add_header Content-Security-Policy value in a file.
var cspLine = regexp.MustCompile(`add_header\s+Content-Security-Policy\s+"([^"]*)"`)

func cspHeaders(t *testing.T, rel string) []string {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	var out []string
	for _, m := range cspLine.FindAllStringSubmatch(string(b), -1) {
		out = append(out, m[1])
	}
	if len(out) == 0 {
		t.Fatalf("%s declares no Content-Security-Policy; this guard is reading the wrong file", rel)
	}
	return out
}

func directive(csp, name string) (string, bool) {
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if part == name || strings.HasPrefix(part, name+" ") {
			return part, true
		}
	}
	return "", false
}

func TestTheLoginDocumentMayLoadTheChallenge(t *testing.T) {
	if !consoleUsesTurnstile(t) {
		t.Skip("the console no longer loads Turnstile; TestTheChallengeAllowanceIsNotLeftBehind covers the other direction")
	}

	for _, rel := range documentCSPConfigs {
		headers := cspHeaders(t, rel)

		var allowed int
		for _, csp := range headers {
			script, _ := directive(csp, "script-src")
			frame, hasFrame := directive(csp, "frame-src")
			if strings.Contains(script, challengeOrigin) && hasFrame && strings.Contains(frame, challengeOrigin) {
				allowed++
			}
		}
		if allowed == 0 {
			t.Errorf("%s sets %d Content-Security-Policy header(s) and not one of them lets the login "+
				"document load %s.\nThe widget is a script from that origin that draws itself in an iframe "+
				"from it, so BOTH script-src and frame-src must name it. Without them the refusal tells the "+
				"person to complete a challenge the browser then refuses to render -- the same dead end the "+
				"site key was added to fix, one layer down.", rel, len(headers), challengeOrigin)
		}
	}
}

// The other direction, so the widening cannot outlive its reason: an origin in
// a CSP is a standing permission, and one nobody needs any more is a hole.
func TestTheChallengeAllowanceIsNotLeftBehind(t *testing.T) {
	if consoleUsesTurnstile(t) {
		return
	}
	for _, rel := range documentCSPConfigs {
		for _, csp := range cspHeaders(t, rel) {
			if strings.Contains(csp, challengeOrigin) {
				t.Errorf("%s still allows %s, but the console no longer loads it. Remove the origin from "+
					"script-src and frame-src: a permission with no user is a widening for nothing.", rel, challengeOrigin)
			}
		}
	}
}

// And the block that must NOT have been widened. The static-asset location
// serves javascript and images, never the login document, so it keeps the
// narrow policy -- widening it would buy nothing and cost the distinction.
func TestTheStaticAssetPolicyStaysNarrow(t *testing.T) {
	b, err := os.ReadFile("oidx-nginx/nginx.conf")
	if err != nil {
		t.Fatalf("read oidx-nginx/nginx.conf: %v", err)
	}
	src := string(b)

	i := strings.Index(src, `location ~* \.(js|css|png`)
	if i < 0 {
		t.Fatal("the static-asset location is no longer recognisable; this guard is checking nothing")
	}
	end := strings.Index(src[i:], "\n    }")
	if end < 0 {
		t.Fatal("could not find the end of the static-asset location")
	}
	if strings.Contains(src[i:i+end], challengeOrigin) {
		t.Errorf("the static-asset location now allows %s. It serves no document and renders no widget; "+
			"the allowance belongs only where the login page is served.", challengeOrigin)
	}
}
