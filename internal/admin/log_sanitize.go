package admin

import "strings"

// sanitizeLogValue strips CR/LF from request-derived values before they are
// written to logs, preventing forged or split log entries (CWE-117 log
// injection).
func sanitizeLogValue(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}
