package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"strings"
)

// usernameKeyedPaths are credential-submitting endpoints where the caller is
// not yet authenticated, so there is no user_id in the context. With
// RATE_LIMIT_PER_USER=true the limiter additionally counts these requests
// against the submitted username (in its own "uname" bucket, on top of the
// per-IP bucket), so a password-spraying botnet that rotates source IPs still
// hits the auth-tier limit for any single account. Matched by prefix.
var usernameKeyedPaths = []string{
	"/oauth/login",
	"/eam/",
}

// maxUsernamePeekBytes bounds how much of the request body the limiter reads
// to find the username. Login bodies are tiny; anything larger is not peeked.
const maxUsernamePeekBytes = 64 << 10

func isUsernameKeyedPath(path string) bool {
	for _, p := range usernameKeyedPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// peekUsername extracts the submitted username from a JSON or form body (or
// the query string, for EAM's login_hint) WITHOUT consuming it: the body is
// restored so the handler can still bind it. The result is lower-cased and
// trimmed so "Alice" and "alice " share one bucket. Returns "" when none.
func peekUsername(body *io.ReadCloser, contentType string, query url.Values) string {
	if v := firstNonEmpty(query.Get("username"), query.Get("login_hint")); v != "" {
		return normalizeUsername(v)
	}
	if body == nil || *body == nil {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(*body, maxUsernamePeekBytes+1))
	rest := *body
	*body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(raw), rest), rest}
	if err != nil || len(raw) > maxUsernamePeekBytes {
		return ""
	}
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "json"):
		var v struct {
			Username  string `json:"username"`
			LoginHint string `json:"login_hint"`
		}
		if json.Unmarshal(raw, &v) == nil {
			return normalizeUsername(firstNonEmpty(v.Username, v.LoginHint))
		}
	case strings.Contains(ct, "x-www-form-urlencoded"):
		if f, err := url.ParseQuery(string(raw)); err == nil {
			return normalizeUsername(firstNonEmpty(f.Get("username"), f.Get("login_hint")))
		}
	}
	return ""
}

func normalizeUsername(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
