package logsafe

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"go.uber.org/zap"
)

// RedactedMarker is what replaces a value that must not be logged. One constant
// so a test can assert on it and a reader can grep for it.
const RedactedMarker = "***REDACTED***"

// DefaultSensitiveFieldNames are field and parameter names whose VALUE must not
// reach a log.
//
// The list this replaced was written by naming secrets, which is the wrong
// direction: it had "access_token" and "refresh_token" but not "id_token_hint",
// "token" but not "session_token", and nothing at all for "code" -- the OAuth
// AUTHORIZATION CODE, which five live callback routes take in the query string.
// A list of remembered names cannot cover what nobody remembered, so it is only
// the exact-match half of the rule; SensitiveWords is the other half, and
// internal/common/middleware/query_param_census_test.go is the guard that makes
// an unclassified parameter impossible to add quietly.
var DefaultSensitiveFieldNames = []string{
	"password", "token", "secret", "key", "api_key", "access_token",
	"refresh_token", "authorization", "bearer", "credentials",
	"client_secret", "private_key", "passphrase", "otp", "ssn",

	// Added after the census. Each is read from a query string by a live route.
	"code",          // the OAuth authorization code (social login/link, SSO callback, multi-IdP)
	"session_token", // a session bearer (passwordless, advanced MFA)
	"login_session", // the interactive login handle
	"state",         // the flow's CSRF token; useful to an attacker who reads the log
	"nonce",         // the OIDC replay nonce, same reasoning
	"id_token_hint", // a signed ID token, in full
	"user_code",     // the device-flow pairing code
	"samlrequest",   // SAML: the request, its response and the client-chosen relay
	"samlresponse",  // value -- SAMLResponse carries the assertion itself
	"relaystate",
	"assertion", // RFC 7521 JWT/SAML bearer assertion
	"client_assertion",
}

// SensitiveWords are matched against the WORDS of a field name -- the parts
// separated by _, - or . -- rather than against the whole name.
//
// This is what covers names nobody listed: "session_token", "backup_code" and
// "provisioning_key" all redact because one of their words is here. Whole-word
// rather than substring is deliberate: "monkey" contains "key" and is not a
// secret, while "sort_key" is not a secret either but costs nothing to redact.
// Over-redaction in a log line is cheap; the other direction is what this file
// exists for.
var SensitiveWords = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "passphrase": true,
	"token": true, "secret": true, "key": true, "credential": true,
	"credentials": true, "bearer": true, "authorization": true,
	"code": true, "otp": true, "pin": true, "ssn": true,
	"assertion": true, "signature": true, "sig": true,
}

var defaultSensitiveSet = func() map[string]bool {
	m := make(map[string]bool, len(DefaultSensitiveFieldNames))
	for _, f := range DefaultSensitiveFieldNames {
		m[strings.ToLower(f)] = true
	}
	return m
}()

// IsSensitiveFieldName reports whether a parameter or JSON field named name
// carries a value that must not reach a log.
//
// extra holds any caller-configured names on top of the defaults; the word rule
// applies over both and cannot be configured off, because the whole point is
// that it covers names the configuration did not anticipate.
func IsSensitiveFieldName(name string, extra map[string]bool) bool {
	lower := strings.ToLower(name)
	if defaultSensitiveSet[lower] || extra[lower] {
		return true
	}
	for _, word := range strings.FieldsFunc(lower, func(r rune) bool {
		return r == '_' || r == '-' || r == '.'
	}) {
		if SensitiveWords[word] {
			return true
		}
		// A trailing "s" is stripped so the plural matches the singular. This is
		// not tidiness: "recovery_codes" is a field this platform really has, it
		// holds a list of one-time login credentials, and it slipped past the word
		// rule on the first draft because the list said "code".
		if len(word) > 1 && word[len(word)-1] == 's' && SensitiveWords[word[:len(word)-1]] {
			return true
		}
	}
	return false
}

// QueryString redacts the values of sensitive parameters in a raw query string.
//
// The key is URL-DECODED before it is classified, because a handler's
// c.Query("token") decodes too. Without that the two disagree about what a
// parameter is called, and the disagreement is one character wide: a request for
// ?%74oken=hunter2 was read by the handler as token=hunter2 and written to the
// log as %74oken=hunter2, in clear. Measured, not theorised.
//
// A key that will not decode is redacted rather than passed through: it is not a
// name this platform can reason about, so it does not get the benefit of the
// doubt.
func QueryString(rawQuery string, extra map[string]bool) string {
	if rawQuery == "" {
		return ""
	}

	params := strings.Split(rawQuery, "&")
	sanitized := make([]string, 0, len(params))

	for _, param := range params {
		parts := strings.SplitN(param, "=", 2)
		if len(parts) != 2 {
			sanitized = append(sanitized, param)
			continue
		}

		key, err := url.QueryUnescape(parts[0])
		if err != nil || IsSensitiveFieldName(key, extra) {
			sanitized = append(sanitized, parts[0]+"="+RedactedMarker)
		} else {
			sanitized = append(sanitized, param)
		}
	}

	return strings.Join(sanitized, "&")
}

// QueryField is the field to log a request's query string with: redacted, then
// cleaned of control characters. Both halves are needed and neither implies the
// other -- redaction decides WHICH values appear, Clean decides what bytes a
// surviving one may contain.
func QueryField(key, rawQuery string) zap.Field {
	return String(key, QueryString(rawQuery, nil))
}

// JSONBody redacts the values of sensitive fields in a request body.
//
// The implementation this replaced searched the raw text for `"field":"` and cut
// to the next quote. It was wrong in three ways at once, and all three failed
// OPEN: its five "variations" were three byte-identical duplicates plus one with
// a space, so `"password" : "x"` was missed; it redacted only the FIRST
// occurrence of each pattern, so a second password survived; and it matched only
// a quoted string value, so a numeric pin, an array of recovery codes or a
// nested {"credentials":{...}} object went to the log whole.
//
// Parsing is the fix. A body that is not JSON cannot have its field boundaries
// found safely, so it is redacted whole rather than guessed at -- except a
// form-encoded one, which QueryString already understands.
// MaxParsedBodyBytes bounds what JSONBody will hand to the JSON parser.
//
// Decoding into an interface{} tree costs several times the input in small
// allocations, and the caller reads the request body with a bare io.ReadAll,
// so without a bound here a single large POST is amplified rather than merely
// copied. 64 KiB is comfortably above the 10 KiB a request logger keeps, so an
// ordinary body still parses and gets its secrets redacted; past it, the size
// is reported and nothing is parsed.
//
// Depth needs no bound of its own: encoding/json refuses beyond 10,000 levels
// of nesting ("exceeded max depth"), so redactValues' recursion is bounded by
// the parser before it starts.
const MaxParsedBodyBytes = 64 << 10

func JSONBody(body string, extra map[string]bool) string {
	if len(body) > MaxParsedBodyBytes {
		return fmt.Sprintf("[body redacted: %d bytes, over the %d-byte parse limit]",
			len(body), MaxParsedBodyBytes)
	}

	var parsed interface{}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		if strings.Contains(body, "=") && !strings.ContainsAny(body, "{}[]") {
			return QueryString(body, extra)
		}
		// The size is kept because it is the one thing that can be reported
		// safely, and an operator debugging an upload needs to know a body
		// arrived and how big it was, not just that it was withheld.
		return fmt.Sprintf("[body redacted: %d bytes, not parseable, so its fields cannot be located]", len(body))
	}

	redacted, err := json.Marshal(redactValues(parsed, extra))
	if err != nil {
		return "[body redacted: could not be re-encoded after redaction]"
	}
	return string(redacted)
}

// redactValues walks a decoded JSON tree and replaces the value of every
// sensitive field, at any depth and in any container. The whole value goes --
// object, array or scalar -- because "credentials" holding an object is exactly
// the case the string-matching version let through.
func redactValues(v interface{}, extra map[string]bool) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, val := range t {
			if IsSensitiveFieldName(k, extra) {
				out[k] = RedactedMarker
				continue
			}
			out[k] = redactValues(val, extra)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, val := range t {
			out[i] = redactValues(val, extra)
		}
		return out
	default:
		return v
	}
}
