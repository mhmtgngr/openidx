package provisioning

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every SCIM filter expression the documentation prints must be one this
// parser accepts.
//
// WHAT THIS CAUGHT. docs/SCIM.md advertised seven operators -- eq, ne, co, sw,
// ew, gt, lt -- and an `and` composition, over an example filtering on
// `active`. This parser implements exactly one form, `attr eq "value"`, over a
// four-attribute allowlist, and answers 400 invalidFilter to everything else.
// So six of the seven documented operators, the composition and the attribute
// were all published instructions that fail against the running product.
// docs/SCIM-FEATURES-LOCATION.md printed two curl commands, one using `sw` on
// an unfilterable attribute and both quoting values with ' rather than ", which
// this parser also rejects.
//
// The documentation was not careless. It was written against a DIFFERENT SCIM
// implementation that lived in internal/identity: a recursive-descent filter
// parser with the full operator set and a SQL renderer, 7,000 lines with
// handlers, schemas and tests, whose route registration function no binary ever
// called. Two complete implementations of one feature, the reachable one
// narrower than the dead one, and the docs describing the dead one -- which is
// how an operator configuring Okta against this product would have followed the
// instructions and got a 400.
//
// A prose sweep does not prevent that recurring; the next person to widen the
// operator table in Markdown has no way to know. Executing the examples does.
var scimDocs = []string{
	"docs/SCIM.md",
	"docs/SCIM-FEATURES-LOCATION.md",
	"docs/docs/api/provisioning.md",
}

// filterInDoc pulls the expression out of `?filter=<expr>` in a documented URL.
// It keeps spaces, since a SCIM filter is spaced (`userName eq "x"`) and
// stopping at the first space would test a fragment rather than the filter, and
// it stops at whatever ends the example: & (the next query parameter), the
// single quote closing a shell argument, or the backtick closing an inline
// code span. That last terminator is not hypothetical -- without it this test
// swallowed the rest of a sentence in SCIM.md that mentions a filter inline and
// reported the prose as a broken example.
var filterInDoc = regexp.MustCompile("[?&]filter=([^&\\n'\"`]*(?:\"[^\"\\n]*\"[^&\\n'\"`]*)*)")

func TestEveryDocumentedSCIMFilterIsOneTheProductAccepts(t *testing.T) {
	root := filepath.Join("..", "..")

	examples := 0
	for _, rel := range scimDocs {
		path := filepath.Join(root, rel)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v (if this document moved, move this test's list with it -- a "+
				"filter example nobody checks is how the last set came to be wrong)", rel, err)
		}

		for i, line := range strings.Split(string(src), "\n") {
			for _, m := range filterInDoc.FindAllStringSubmatch(line, -1) {
				expr := strings.TrimSpace(m[1])
				if expr == "" {
					continue
				}
				examples++

				attrs := scimUserFilterAttrs
				resource := "Users"
				if strings.Contains(line, "/Groups") {
					attrs, resource = scimGroupFilterAttrs, "Groups"
				}

				if _, err := parseSCIMFilter(expr, attrs); err != nil {
					t.Errorf("%s:%d documents a %s filter the product refuses:\n  filter: %s\n  error:  %v\n"+
						"An operator following this line gets 400 invalidFilter. Either implement it in "+
						"parseSCIMFilter or correct the document -- the one thing that must not stay is a "+
						"published example that does not work.", rel, i+1, resource, expr, err)
				}
			}
		}
	}

	// A regex that matched nothing would make this test pass by finding no
	// examples to check, which is the failure mode of every documentation
	// guard. There are examples in these files; require that we saw them.
	if examples < 4 {
		t.Fatalf("found only %d filter example(s) across %v; the extraction pattern is not matching the "+
			"documented URLs, so this test is checking nothing", examples, scimDocs)
	}
}

// The other half of the same contract: what the documentation says is NOT
// supported must actually be refused. A parser quietly widened to accept `sw`
// while the document still calls it unsupported is a smaller problem than the
// reverse, but it is the same drift, and here it is free to check.
func TestWhatTheDocumentationCallsUnsupportedIsRefused(t *testing.T) {
	refused := []struct {
		expr string
		why  string
	}{
		{`userName eq "john.doe" and active eq true`, "an and-composition"},
		{`userName ne "john.doe"`, "the ne operator"},
		{`userName co "john"`, "the co operator"},
		{`name.givenName sw "John"`, "the sw operator on an unfilterable attribute"},
		{`userName ew "doe"`, "the ew operator"},
		{`createdAt gt "2026-01-01T00:00:00Z"`, "the gt operator"},
		{`emails.value eq 'user@example.com'`, "a single-quoted value"},
		{`active eq "true"`, "an attribute outside the allowlist"},
		{`password eq "hunter2"`, "an attribute that must never be filterable"},
	}

	for _, c := range refused {
		if _, err := parseSCIMFilter(c.expr, scimUserFilterAttrs); err == nil {
			t.Errorf("parseSCIMFilter accepted %q (%s). The documentation states this is answered with 400 "+
				"invalidFilter; if the parser has genuinely grown this capability, say so in docs/SCIM.md "+
				"in the same change.", c.expr, c.why)
		}
	}
}
