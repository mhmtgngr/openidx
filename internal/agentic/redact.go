package agentic

import "regexp"

// Redaction is how much of what a model is shown is masked first.
type Redaction string

const (
	// RedactOff shows text as it is. Only for a model the organization runs.
	RedactOff Redaction = "off"
	// RedactMask hides e-mail addresses, IP addresses and secrets.
	RedactMask Redaction = "mask"
	// RedactStrict also hides host names and the user name in file paths.
	RedactStrict Redaction = "strict"
)

// ParseRedaction accepts the three levels; anything else is the safe default,
// mask.
func ParseRedaction(s string) Redaction {
	switch Redaction(s) {
	case RedactOff, RedactMask, RedactStrict:
		return Redaction(s)
	}
	return RedactMask
}

var (
	reEmail = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	reIPv4  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// An IPv6 address either has "::" or all eight groups; a time of day
	// (12:30:45) has neither and must survive, or clock skew cannot be explained.
	reIPv6   = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,5})?|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?`)
	reBearer = regexp.MustCompile(`(?i)\b(bearer|token|secret|password|passwd|apikey|api_key|authorization)(["']?\s*[:=]?\s*["']?)[A-Za-z0-9._~+/=\-]{8,}`)
	reJWT    = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*`)
	reLong   = regexp.MustCompile(`\b[A-Za-z0-9+/_\-]{32,}={0,2}`)
	reUUID   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reHost   = regexp.MustCompile(`\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b`)
	reWinUsr = regexp.MustCompile(`(?i)([A-Z]:\\Users\\)[^\\\s"']+`)
	reNixUsr = regexp.MustCompile(`(/(?:home|Users)/)[^/\s"']+`)
)

// Mask hides what a model does not need in order to explain a problem. It is
// a floor, not a guarantee: free text can always carry something a pattern
// does not know, which is why cloud models are an organization's explicit
// choice and why tools return structured fields, not raw logs.
func Mask(s string, level Redaction) string {
	if level == RedactOff || s == "" {
		return s
	}
	s = reJWT.ReplaceAllString(s, "[secret]")
	s = reBearer.ReplaceAllString(s, "${1}${2}[secret]")
	s = reEmail.ReplaceAllString(s, "[email]")
	s = reIPv4.ReplaceAllString(s, "[ip]")
	s = reIPv6.ReplaceAllString(s, "[ip]")
	s = reLong.ReplaceAllStringFunc(s, func(m string) string {
		if reUUID.MatchString(m) {
			return m // an id the model may need to name, not a secret
		}
		return "[secret]"
	})
	if level == RedactStrict {
		s = reWinUsr.ReplaceAllString(s, "${1}[user]")
		s = reNixUsr.ReplaceAllString(s, "${1}[user]")
		s = reHost.ReplaceAllString(s, "[host]")
	}
	return s
}
