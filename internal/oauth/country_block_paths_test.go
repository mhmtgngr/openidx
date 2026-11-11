package oauth

import (
	"os"
	"strings"
	"testing"
)

// TestCountryBlockOnEverySignInPath pins that the social and passkey sign-in
// paths apply checkCountryBlock before a session is created, like the
// password login. Before this, a blocked country was refused only at the
// password form.
func TestCountryBlockOnEverySignInPath(t *testing.T) {
	cases := []struct{ file, fn, session string }{
		{"social_login.go", "func (s *Service) handleSocialLoginCallback(", "s.identityService.CreateSession("},
		{"handlers_passwordless.go", "func (s *Service) handlePasskeyFinish(", "s.identityService.CreateSession("},
	}
	for _, tc := range cases {
		raw, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatal(err)
		}
		src := string(raw)
		start := strings.Index(src, tc.fn)
		if start < 0 {
			t.Fatalf("%s: %s not found", tc.file, tc.fn)
		}
		body := src[start:]
		if end := strings.Index(body[1:], "\nfunc "); end > 0 {
			body = body[:end+1]
		}
		block := strings.Index(body, "s.checkCountryBlock(")
		sess := strings.Index(body, tc.session)
		if block < 0 {
			t.Errorf("%s: %s does not call checkCountryBlock", tc.file, tc.fn)
			continue
		}
		if sess >= 0 && block > sess {
			t.Errorf("%s: checkCountryBlock must run before a session is created", tc.file)
		}
	}
}
