package abac

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The console page that authors ABAC policies. A Go test reaches into the
// console because the vocabulary belongs to the evaluator: the page is offering
// choices about what THIS package can decide, and the only way for the two to
// agree by construction is for one of them to be checked against the other.
const abacPage = "../../web/admin-console/src/pages/abac-policies.tsx"

// assignedAttribute matches `attrs["x"] =` and the keys of the map literal
// SubjectAttributes starts from, which is where the vocabulary really lives.
var (
	assignedAttribute = regexp.MustCompile(`attrs\["([a-z_]+)"\]\s*=`)
	literalAttribute  = regexp.MustCompile(`(?m)^\s*"([a-z_]+)":\s`)
	tsStringList      = regexp.MustCompile(`(?s)const\s+%s\s*=\s*\[(.*?)\]`)
	tsQuoted          = regexp.MustCompile(`'([^']+)'`)
	tsValueField      = regexp.MustCompile(`value:\s*'([^']+)'`)
)

// SubjectAttributes is the implementation; SubjectAttributeKeys is what the rest
// of the product is told about it. If they drift, a policy can be written
// against an attribute the subject never carries -- which is the whole defect --
// or the console stops offering one that works.
func TestSubjectAttributeKeysMatchWhatSubjectAttributesBuilds(t *testing.T) {
	src, err := os.ReadFile("subject.go")
	if err != nil {
		t.Fatalf("cannot read subject.go: %v", err)
	}
	body := string(src)
	// Only the function body, so the doc comment's key list is not the source.
	if i := strings.Index(body, "func SubjectAttributes("); i >= 0 {
		body = body[i:]
	}

	built := map[string]bool{}
	for _, m := range assignedAttribute.FindAllStringSubmatch(body, -1) {
		built[m[1]] = true
	}
	for _, m := range literalAttribute.FindAllStringSubmatch(body, -1) {
		built[m[1]] = true
	}
	if len(built) < 5 {
		t.Fatalf("only %d attribute(s) parsed out of SubjectAttributes; this test's parser no "+
			"longer matches the function and would pass over anything", len(built))
	}

	declared := map[string]bool{}
	for _, k := range SubjectAttributeKeys {
		declared[k] = true
	}

	var missing, extra []string
	for k := range built {
		if !declared[k] {
			missing = append(missing, k)
		}
	}
	for k := range declared {
		if !built[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(missing) > 0 {
		t.Errorf("SubjectAttributes builds attribute(s) that SubjectAttributeKeys does not "+
			"declare: %s\n\nThe declared list is what the console offers and what the guard "+
			"below checks, so an undeclared attribute is one no administrator can write a "+
			"policy against.", strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		t.Errorf("SubjectAttributeKeys declares attribute(s) SubjectAttributes never puts on "+
			"the map: %s\n\nEvaluateCondition returns false for an attribute the subject does "+
			"not carry, so a policy written against one of these matches nothing, silently, "+
			"forever.", strings.Join(extra, ", "))
	}
}

// What the ABAC page lets an administrator choose must be what this package can
// decide. Both dropdowns, both directions.
func TestTheConsoleOffersOnlyAttributesTheEvaluatorPopulates(t *testing.T) {
	page := readABACPage(t)

	offered := tsList(t, page, "attributeOptions", tsQuoted)
	if len(offered) < 3 {
		t.Fatalf("only %d attribute option(s) parsed out of %s; the page changed shape and this "+
			"guard is checking almost nothing", len(offered), abacPage)
	}

	populated := map[string]bool{}
	for _, k := range SubjectAttributeKeys {
		populated[k] = true
	}

	var dead []string
	for _, a := range offered {
		if !populated[a] {
			dead = append(dead, a)
		}
	}
	if len(dead) > 0 {
		sort.Strings(dead)
		t.Errorf("the ABAC policy editor offers attribute(s) no subject ever carries:\n  %s\n\n"+
			"A condition on one of these is false for every user, so the policy never matches. "+
			"With Gate composing deny-wins-else-allow-else-allow, a DENY written on one of them "+
			"permits precisely what it was written to stop, and nothing on screen or in a log "+
			"says so. Offer what SubjectAttributes populates (%s), or populate the attribute "+
			"first.", strings.Join(dead, "\n  "), strings.Join(SubjectAttributeKeys, ", "))
	}

	// The other direction is a note rather than a failure: an attribute the
	// evaluator carries but the page does not offer is a usable condition an
	// administrator cannot reach from the UI, which is a smaller problem than a
	// choice that decides nothing.
	offeredSet := map[string]bool{}
	for _, a := range offered {
		offeredSet[a] = true
	}
	var unoffered []string
	for _, k := range SubjectAttributeKeys {
		if !offeredSet[k] {
			unoffered = append(unoffered, k)
		}
	}
	if len(unoffered) > 0 {
		t.Logf("attributes the evaluator populates that the page does not offer: %s",
			strings.Join(unoffered, ", "))
	}
}

func TestTheConsoleOffersOnlyResourceTypesSomethingEvaluates(t *testing.T) {
	page := readABACPage(t)

	offered := tsList(t, page, "resourceTypes", tsValueField)
	if len(offered) < 2 {
		t.Fatalf("only %d resource type(s) parsed out of %s; the page changed shape and this "+
			"guard is checking almost nothing", len(offered), abacPage)
	}

	evaluated := map[string]bool{}
	for _, r := range EvaluatedResourceTypes {
		evaluated[r] = true
	}

	var dead []string
	for _, r := range offered {
		if !evaluated[r] {
			dead = append(dead, r)
		}
	}
	if len(dead) > 0 {
		sort.Strings(dead)
		t.Errorf("the ABAC policy editor offers resource type(s) no enforcement point ever asks "+
			"about: %s\n\nGate selects `resource_type IN ($1, '*')` for the type a PEP passes, "+
			"and the only type any PEP passes is %q. A policy scoped to anything else is never "+
			"even selected, so it cannot allow or deny. Add an enforcement point that asks about "+
			"the type, or stop offering it.",
			strings.Join(dead, ", "), ResourceTypeApplication)
	}
}

func readABACPage(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(abacPage)
	if err != nil {
		t.Fatalf("cannot read the ABAC policy page (%s): %v\n\nIf the page moved, move this "+
			"guard with it -- the vocabulary it checks is still this package's.", abacPage, err)
	}
	return string(raw)
}

// tsList pulls a module-level `const <name> = [ ... ]` out of the page and
// returns every value `item` finds in it.
func tsList(t *testing.T, page, name string, item *regexp.Regexp) []string {
	t.Helper()
	block := regexp.MustCompile(strings.Replace(tsStringList.String(), "%s", regexp.QuoteMeta(name), 1))
	m := block.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no `const %s = [...]` in %s; this guard cannot see what the page offers",
			name, abacPage)
	}
	var out []string
	for _, v := range item.FindAllStringSubmatch(m[1], -1) {
		out = append(out, v[1])
	}
	return out
}
