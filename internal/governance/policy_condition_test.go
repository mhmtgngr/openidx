package governance

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// WHAT A POLICY RULE'S CONDITION MAY SAY, AND WHO DECIDES.
//
// EvaluatePolicy dispatches on the policy type and each evaluator reads its
// rules' conditions with a Go type assertion:
//
//	rule.Condition["start_hour"].(float64)
//	rule.Condition["allowed_days"].([]interface{})
//	rule.Condition["require_mfa"].(bool)
//
// An assertion that fails is not an error and does not disable the rule. The
// `if ok` is simply false, the loop moves on, and the evaluator uses the DEFAULT
// it was written with -- 09:00-18:00 Monday to Friday for timebound, the RFC1918
// private ranges for location, a risk threshold of 50. So a condition the
// evaluator cannot read does not turn a policy off. It quietly enforces a
// different policy than the one an administrator wrote, and the console shows
// them the text they typed.
//
// The policy editor got both halves wrong. It offered `days` where the evaluator
// reads `allowed_days`, `allowed_ips` where it reads `allowed_ip_prefixes`,
// `min_risk_score` and `max_risk_score` on risk_based where it reads
// `risk_threshold`, and `blocked_ips`, which no evaluator has ever had a concept
// of. And it sent every value as a string, so even the keys whose names matched
// -- start_hour, end_hour, conflicting_roles, require_mfa,
// device_trust_required -- failed their assertion. Of the thirteen inputs the
// page offered, three could be read, and all three belong to the one policy type
// the form cannot create.
//
// This derives the contract from the assertions themselves, which is the only
// place it is really written down, and checks the page against it.

const policiesPage = "../../web/admin-console/src/pages/policies.tsx"

// conditionRead matches an evaluator reading a condition with its Go type:
// `rule.Condition["start_hour"].(float64)`.
var conditionRead = regexp.MustCompile(`Condition\["([a-z_]+)"\]\.\(([^)]+)\)`)

// goTypeToTS maps the assertion's Go type to the ConditionType the page uses to
// coerce the form's text before sending it.
var goTypeToTS = map[string]string{
	"float64":       "number",
	"bool":          "boolean",
	"[]interface{}": "stringList",
	"string":        "string",
}

// evaluatorConditions returns every condition key the governance evaluators
// read, with the TS type the page must send for it.
func evaluatorConditions(t *testing.T) map[string]string {
	t.Helper()
	src, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("cannot read service.go: %v", err)
	}
	out := map[string]string{}
	for _, m := range conditionRead.FindAllStringSubmatch(string(src), -1) {
		key, goType := m[1], strings.TrimSpace(m[2])
		ts, known := goTypeToTS[goType]
		if !known {
			t.Errorf("the evaluator reads Condition[%q] as %s, a type this guard does not know "+
				"how to ask the console for. Add it to goTypeToTS along with the coercion the "+
				"page needs, or the console cannot be checked against this condition.", key, goType)
			continue
		}
		if prev, seen := out[key]; seen && prev != ts {
			t.Errorf("the evaluator reads Condition[%q] as both %s and %s; the console can only "+
				"send one, so one of the two reads is dead", key, prev, ts)
		}
		out[key] = ts
	}
	if len(out) < 8 {
		t.Fatalf("only %d condition read(s) parsed out of service.go; this guard's parser no "+
			"longer matches the evaluators and would pass over anything", len(out))
	}
	return out
}

// pageConditions returns what the policy editor offers, as key -> declared type.
var (
	templateBlock = regexp.MustCompile(`(?s)const conditionTemplates:[^=]*=\s*\{(.*?)\n\}`)
	templateEntry = regexp.MustCompile(`\{\s*key:\s*'([a-z_]+)',\s*type:\s*'([a-zA-Z]+)'`)
)

func pageConditions(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(policiesPage)
	if err != nil {
		t.Fatalf("cannot read the policy editor (%s): %v\n\nIf the page moved, move this guard "+
			"with it — the contract it checks is this package's.", policiesPage, err)
	}
	block := templateBlock.FindStringSubmatch(string(raw))
	if block == nil {
		t.Fatalf("no `const conditionTemplates` in %s; this guard cannot see what the page "+
			"offers", policiesPage)
	}
	out := map[string]string{}
	for _, m := range templateEntry.FindAllStringSubmatch(block[1], -1) {
		out[m[1]] = m[2]
	}
	if len(out) < 5 {
		t.Fatalf("only %d condition template(s) parsed out of %s; the page changed shape and "+
			"this guard is checking almost nothing", len(out), policiesPage)
	}
	return out
}

func TestThePolicyEditorOffersOnlyConditionsTheEvaluatorReads(t *testing.T) {
	read := evaluatorConditions(t)
	offered := pageConditions(t)

	var unread, mistyped []string
	for key, tsType := range offered {
		want, ok := read[key]
		if !ok {
			unread = append(unread, key)
			continue
		}
		if want != tsType {
			mistyped = append(mistyped, key+" (page sends "+tsType+", evaluator asserts "+want+")")
		}
	}
	sort.Strings(unread)
	sort.Strings(mistyped)

	if len(unread) > 0 {
		t.Errorf("the policy editor offers condition(s) no evaluator reads:\n  %s\n\nA condition "+
			"the evaluator cannot find is not a disabled rule — the evaluator falls back to the "+
			"default it was written with (09:00-18:00 Mon-Fri, the private IP ranges, a risk "+
			"threshold of 50), so the policy enforces something other than what was typed, and "+
			"nothing says so. The keys it does read: %s",
			strings.Join(unread, "\n  "), strings.Join(sortedKeys(read), ", "))
	}
	if len(mistyped) > 0 {
		t.Errorf("the policy editor sends condition(s) as the wrong JSON type:\n  %s\n\nThe "+
			"evaluator's type assertion fails, `ok` is false, and the rule is skipped in favour "+
			"of the same hardcoded default. The page's coerceCondition is what has to produce "+
			"the type the assertion wants.", strings.Join(mistyped, "\n  "))
	}
}

// The other direction: a condition the evaluator reads that no policy type
// offers is a rule an administrator cannot write from the console. That is a
// smaller problem than a condition that decides nothing, so it is reported
// rather than failed — but it is worth seeing, because it is how `risk_threshold`
// came to be unreachable while two invented keys sat in its place.
func TestEveryConditionTheEvaluatorReadsCanBeAuthored(t *testing.T) {
	read := evaluatorConditions(t)
	offered := pageConditions(t)

	var unreachable []string
	for key := range read {
		if _, ok := offered[key]; !ok {
			unreachable = append(unreachable, key)
		}
	}
	sort.Strings(unreachable)
	if len(unreachable) > 0 {
		t.Logf("conditions the evaluator reads that the policy editor does not offer: %s",
			strings.Join(unreachable, ", "))
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
