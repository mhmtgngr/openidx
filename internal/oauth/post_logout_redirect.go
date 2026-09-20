package oauth

// OpenID Connect RP-Initiated Logout 1.0 — where a browser may be sent after
// a logout, and what the relying party gets back when it lands.
//
// THE ALLOWLIST. §2 requires the OP to verify post_logout_redirect_uri
// against values REGISTERED for the client, and the registration the spec
// means is post_logout_redirect_uris: a list that exists precisely because
// the landing page is usually NOT the OAuth callback path. Before v199 there
// was no such list, so the allowlist was derived from redirect_uris by
// comparing ORIGIN and ignoring the path. That refuses another domain, which
// is what PR #82 was for, but it says yes to EVERY path on the relying
// party's host: an open redirector, a user-content page, a half-finished
// route. A relying party that registered two callbacks got its whole site.
//
// TWO RULES, AND WHICH ONE APPLIES IS THE CLIENT'S OWN DOING:
//
//   - a client with a registered list is matched EXACTLY (modulo the
//     case-insensitivity URLs actually have: scheme and host). That is the
//     spec's rule and the one worth having.
//   - a client with an empty list keeps the origin derivation. Unconditional
//     exact-match would refuse the logout redirect of every client in every
//     existing install on the upgrade that adds the column — none of them has
//     registered anything yet — and the default has to stay installable.
//     The fallback logs the client id so an operator can see who is still on
//     the loose rule instead of assuming everyone is on the tight one.
//
// A QUERY OR FRAGMENT IS PART OF THE MATCH, deliberately. RFC 8252 and the
// OAuth redirect-URI rules treat the registered value as a whole; a landing
// page that wants ?from=logout registers it. What the RP varies per request
// is `state`, which travels separately and comes back below.

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// maxPostLogoutRedirectURIs bounds the registered list. It is not a spec
// number; it is the same shape of bound the rest of the client model carries,
// so a registration cannot turn into an unbounded row.
const maxPostLogoutRedirectURIs = 20

// ErrInvalidPostLogoutRedirectURI is returned when a registration carries a
// value that could never be matched, which is better refused at registration
// than discovered at logout.
var ErrInvalidPostLogoutRedirectURI = errors.New(
	"post_logout_redirect_uris entries must be absolute URIs with a scheme and host, and must not carry credentials")

// validatePostLogoutRedirectURIs checks a registration. An empty list is
// valid: it means "no registration", which the matcher reads as the fallback.
func validatePostLogoutRedirectURIs(uris []string) error {
	if len(uris) > maxPostLogoutRedirectURIs {
		return ErrInvalidPostLogoutRedirectURI
	}
	for _, raw := range uris {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
			return ErrInvalidPostLogoutRedirectURI
		}
	}
	return nil
}

// marshalPostLogoutRedirectURIs renders the list for storage. An empty list
// becomes SQL NULL rather than `[]`, because the column's whole job is to
// tell "registered nothing" from "registered something", and a stored empty
// array would read as the latter to any later query.
func marshalPostLogoutRedirectURIs(uris []string) []byte {
	cleaned := make([]string, 0, len(uris))
	for _, raw := range uris {
		if trimmed := strings.TrimSpace(raw); trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	if len(cleaned) == 0 {
		return nil
	}
	out, err := json.Marshal(cleaned)
	if err != nil {
		return nil
	}
	return out
}

// samePostLogoutTarget compares a registered value with a requested one the
// way URLs actually compare: scheme and host case-insensitively, everything
// else byte for byte.
func samePostLogoutTarget(registered, requested *url.URL) bool {
	return strings.EqualFold(registered.Scheme, requested.Scheme) &&
		strings.EqualFold(registered.Host, requested.Host) &&
		registered.EscapedPath() == requested.EscapedPath() &&
		registered.RawQuery == requested.RawQuery &&
		registered.Fragment == requested.Fragment
}

// sameOrigin is the fallback rule for a client that registered no list.
func sameOrigin(registered, requested *url.URL) bool {
	return strings.EqualFold(registered.Scheme, requested.Scheme) &&
		strings.EqualFold(registered.Host, requested.Host)
}

// withLogoutState appends the RP's state to the landing page it registered.
//
// It is appended rather than folded into the match: the registered value is
// what the RP wrote down once, and `state` is what it varies per request. A
// landing page that already carries a query keeps it — the state is one more
// parameter, not a replacement — and a target the RP registered WITH its own
// `state` is left exactly as registered when the request sends none.
func withLogoutState(target, state string) string {
	if state == "" {
		return target
	}
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	q := u.Query()
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}
