package tray

import (
	"net/url"
	"strings"
	"unicode/utf8"
)

// Written justification (Faz B8.11). An entry with require_justification is
// refused until the person says why they need it. The tray answers that
// refusal by opening openidx://justify?request=<entry>, which the OS routes
// back to the agent; the agent asks for the reason and files the access
// request with it, so the approver reads the person's own words.

const (
	justifyMinLen = 10
	justifyMaxLen = 500
)

// JustifyLink is the openidx:// link that asks for a reason for entryID.
func JustifyLink(entryID string) string {
	return "openidx://justify?request=" + url.QueryEscape(entryID)
}

// ParseJustifyLink returns the entry an openidx://justify link names.
func ParseJustifyLink(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "openidx" || u.Host != "justify" {
		return "", false
	}
	id := strings.TrimSpace(u.Query().Get("request"))
	if id == "" || len(id) > 128 || strings.ContainsAny(id, "/?#\\ ") {
		return "", false
	}
	return id, true
}

// validJustification checks a typed reason; "" when it is acceptable,
// otherwise what to tell the person.
func validJustification(reason string) string {
	n := utf8.RuneCountInString(strings.TrimSpace(reason))
	switch {
	case n < justifyMinLen:
		return "Please write at least 10 characters: what you need to do and why."
	case n > justifyMaxLen:
		return "Please keep the reason under 500 characters."
	}
	return ""
}
