package provisioning

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// errUnsupportedFilter is returned when a SCIM filter expression uses an
// operator or attribute we do not implement. Callers translate it into an
// HTTP 400 with scimType=invalidFilter (RFC 7644 §3.4.3) rather than silently
// returning an unfiltered list: an IdP (Okta/Entra) issues
// GET /Users?filter=userName eq "x" as an existence/dedup check before it
// creates or deprovisions, and an inert filter that returns the whole page
// would make it wrongly conclude the resource is absent (duplicate create) or
// present (skipped deprovision). Failing loud is safer than a silent superset.
var errUnsupportedFilter = errors.New("unsupported SCIM filter")

// scimEqFilter matches the single SCIM idiom IdPs use for existence checks:
//
//	attribute eq "value"
//
// The attribute may carry a sub-attribute (emails.value) or a URN prefix; the
// operator eq is case-insensitive (SCIM keywords are); the value is a
// double-quoted string that may contain backslash escapes. Anything more
// complex (and/or/not, other operators, grouping) is deliberately rejected so
// we never guess at a query we cannot faithfully translate.
var scimEqFilter = regexp.MustCompile(`^\s*([A-Za-z][\w:.]*)\s+(?i:eq)\s+"((?:[^"\\]|\\.)*)"\s*$`)

// scimFilterAttr maps a supported SCIM attribute to the SQL column it filters
// and whether the comparison is case-insensitive (userName/email are; opaque
// identifiers like externalId are compared exactly).
type scimFilterAttr struct {
	column          string
	caseInsensitive bool
}

// scimFilterPredicate is a parsed, validated `attr eq "value"` filter. The
// column is drawn from an internal allowlist (never user input), so building a
// clause from it is injection-safe; the value is always a bound parameter.
type scimFilterPredicate struct {
	column          string
	caseInsensitive bool
	value           string
}

// clause renders the SQL predicate for the given 1-based placeholder index,
// e.g. " AND LOWER(username) = LOWER($4)". The list and COUNT queries bind the
// org/paging params at different positions, so the caller supplies the index.
func (p *scimFilterPredicate) clause(placeholder int) string {
	if p.caseInsensitive {
		return fmt.Sprintf(" AND LOWER(%s) = LOWER($%d)", p.column, placeholder)
	}
	return fmt.Sprintf(" AND %s = $%d", p.column, placeholder)
}

// parseSCIMFilter parses a SCIM filter expression against the allowed
// attributes for a resource. An empty/whitespace filter yields (nil, nil) —
// no predicate, no error. Any filter we cannot honor (unsupported operator or
// unknown/unfilterable attribute) yields errUnsupportedFilter so the handler
// can answer 400 invalidFilter instead of returning an unfiltered page.
func parseSCIMFilter(filter string, allowed map[string]scimFilterAttr) (*scimFilterPredicate, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return nil, nil
	}

	m := scimEqFilter.FindStringSubmatch(filter)
	if m == nil {
		return nil, fmt.Errorf(`%w: only 'attribute eq "value"' is supported`, errUnsupportedFilter)
	}

	attr := strings.ToLower(m[1])
	col, ok := allowed[attr]
	if !ok {
		return nil, fmt.Errorf("%w: attribute %q is not filterable", errUnsupportedFilter, m[1])
	}

	return &scimFilterPredicate{
		column:          col.column,
		caseInsensitive: col.caseInsensitive,
		value:           unescapeSCIMValue(m[2]),
	}, nil
}

// unescapeSCIMValue resolves the backslash escapes SCIM permits inside a
// quoted value (\" and \\), leaving the value ready to bind as a parameter.
func unescapeSCIMValue(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// scimUserFilterAttrs are the SCIM User attributes we can filter on. Keys are
// lowercased because SCIM attribute names are case-insensitive (RFC 7644).
var scimUserFilterAttrs = map[string]scimFilterAttr{
	"username":     {column: "username", caseInsensitive: true},
	"email":        {column: "email", caseInsensitive: true},
	"emails.value": {column: "email", caseInsensitive: true},
	"externalid":   {column: "external_id", caseInsensitive: false},
}

// scimGroupFilterAttrs are the SCIM Group attributes we can filter on.
var scimGroupFilterAttrs = map[string]scimFilterAttr{
	"displayname": {column: "name", caseInsensitive: true},
	"externalid":  {column: "external_id", caseInsensitive: false},
}
