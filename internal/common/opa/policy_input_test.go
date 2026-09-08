package opa

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// WHAT THE POLICY READS, AGAINST WHAT THE PRODUCT SENDS.
//
// A rego rule that reads an input field the client never marshals is not a
// stricter policy or a looser one. It is a rule that cannot fire, and nothing
// reports it: OPA answers "undefined" for the missing path, the rule's body
// fails, and the decision comes out of whatever other rules matched. There is no
// error, no log line, and no denial to notice.
//
// Two rules in deployments/docker/opa/policies/authz.rego were written that way.
// "Users can modify their own resources" required input.resource.owner, and
// ResourceContext had an Owner field that nothing ever set -- OPAAuthz runs
// before the handler and never loads the row it is authorizing, so it cannot
// know who owns it. The cross-tenant deny required input.resource.tenant_id,
// which ResourceContext did not even declare. Both are gone; the field is gone;
// this is what stops the third one being written.
//
// Both halves are derived. The policy's side comes from parsing the .rego for
// every `input.<path>` it mentions. The product's side comes from reflecting
// over the Input struct's JSON tags. Neither is a list somebody maintains.

// canonicalPolicy is the policy docker-compose mounts and a Helm install ships.
const canonicalPolicy = "../../../deployments/docker/opa/policies/authz.rego"

// repoRoot is where the sweep below starts. Every policy in the tree is checked,
// not a named one: the second copy of this policy lives inside a Kubernetes
// ConfigMap in dev-kube/opa.yaml, and a guard that read only the .rego file
// would have declared the contract sound while that copy denied every request.
const repoRoot = "../../.."

// authzPackage is the package internal/common/opa queries (/v1/data/openidx/authz).
//
// It is also the ONLY package that can reach a decision in this product. No Go
// code here reads a .rego file or embeds a rego evaluator -- there is no
// open-policy-agent dependency in go.mod at all -- so the single path from rego
// to an answer is this HTTP client against a running OPA, at that one policy
// path. A rego file in any other package is inert, whatever its header claims,
// which is why TestNoInertPolicyFilesInTheTree below refuses to let one sit in
// the repository unexplained.
const authzPackage = "package openidx.authz"

// authzPolicy is one policy source found in the tree.
type authzPolicy struct {
	where  string // path, plus the YAML key when embedded
	source string // the rego itself, un-indented
}

// findAuthzPolicies walks the repository for openidx.authz policies: .rego files
// and rego embedded in a YAML block scalar (a ConfigMap).
func findAuthzPolicies(t *testing.T) []authzPolicy {
	t.Helper()
	var found []authzPolicy
	skip := map[string]bool{".git": true, "node_modules": true, "dist": true, "bin": true}

	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skip[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".rego":
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			if strings.Contains(string(raw), authzPackage) {
				found = append(found, authzPolicy{where: path, source: string(raw)})
			}
		case ".yaml", ".yml":
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			if !strings.Contains(string(raw), authzPackage) {
				return nil
			}
			for key, body := range embeddedBlocks(string(raw), authzPackage) {
				found = append(found, authzPolicy{where: path + " (" + key + ")", source: body})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s for policies: %v", repoRoot, err)
	}
	if len(found) < 2 {
		t.Fatalf("found %d %q policy source(s) in the tree; there are at least two (the .rego "+
			"and the dev-kube ConfigMap), so this sweep is no longer finding them and would "+
			"pass over a policy nobody checked", len(found), authzPackage)
	}
	return found
}

// embeddedBlocks pulls YAML block scalars ("key: |") whose body contains marker,
// returning them keyed by the YAML key with the block indent removed.
func embeddedBlocks(yaml, marker string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(yaml, "\n")
	blockKey := regexp.MustCompile(`^(\s*)([A-Za-z0-9_.\-]+):\s*\|\s*$`)
	for i := 0; i < len(lines); i++ {
		m := blockKey.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		keyIndent := len(m[1])
		var body []string
		bodyIndent := -1
		for j := i + 1; j < len(lines); j++ {
			line := lines[j]
			if strings.TrimSpace(line) == "" {
				body = append(body, "")
				continue
			}
			indent := len(line) - len(strings.TrimLeft(line, " "))
			if indent <= keyIndent {
				break
			}
			if bodyIndent < 0 {
				bodyIndent = indent
			}
			if len(line) >= bodyIndent {
				line = line[bodyIndent:]
			}
			body = append(body, line)
		}
		text := strings.Join(body, "\n")
		if strings.Contains(text, marker) {
			out[m[2]] = text
		}
	}
	return out
}

// inputRef matches an input reference in rego source: input.user.roles,
// input.resource.type, input.method. Bracket lookups (input.resource[k]) are not
// matched -- there are none, and the assertion below on the count would catch
// the policy growing them.
var inputRef = regexp.MustCompile(`\binput((?:\.[A-Za-z_][A-Za-z0-9_]*)+)`)

// regoCode strips rego comments before the scan. This matters more than usual
// here: the two deleted rules are quoted verbatim in the comment that replaced
// them, so a scan that read comments would still see the very paths this test
// exists to forbid.
func regoCode(source string) string {
	var b strings.Builder
	for _, line := range strings.Split(source, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// inputPathsIn returns every input path a policy's CODE reads, e.g. "user.roles",
// "resource.type", "method".
func inputPathsIn(source string) []string {
	seen := map[string]bool{}
	for _, m := range inputRef.FindAllStringSubmatch(regoCode(source), -1) {
		seen[strings.TrimPrefix(m[1], ".")] = true
	}
	var out []string
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// policyInputPaths returns the union of what every openidx.authz policy reads.
func policyInputPaths(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, p := range findAuthzPolicies(t) {
		for _, path := range inputPathsIn(p.source) {
			seen[path] = true
		}
	}
	var out []string
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	if len(out) < 5 {
		t.Fatalf("only %d input path(s) found across the openidx.authz policies; either they "+
			"are empty or this test's parser no longer matches their syntax, and either way "+
			"it is checking nothing", len(out))
	}
	return out
}

// sentInputPaths returns every JSON path Input marshals, derived from the struct
// tags: "user", "user.id", "user.roles", "resource", "resource.type", ...
// Parents are included because a rule may legitimately read a whole object.
func sentInputPaths() map[string]bool {
	out := map[string]bool{}
	var walk func(t reflect.Type, prefix string)
	walk = func(t reflect.Type, prefix string) {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			out[path] = true
			walk(f.Type, path)
		}
	}
	walk(reflect.TypeOf(Input{}), "")
	return out
}

func TestEveryInputThePolicyReadsIsSent(t *testing.T) {
	sent := sentInputPaths()

	var unsendable []string
	for _, policy := range findAuthzPolicies(t) {
		for _, path := range inputPathsIn(policy.source) {
			if !sent[path] {
				unsendable = append(unsendable, path+"   ("+policy.where+")")
			}
		}
	}
	sort.Strings(unsendable)

	if len(unsendable) > 0 {
		var known []string
		for p := range sent {
			known = append(known, p)
		}
		sort.Strings(known)
		t.Errorf("authz.rego reads input field(s) that opa.Input does not carry:\n  input.%s\n\n"+
			"A rule whose body reads an absent path never fires -- OPA answers undefined, the "+
			"body fails, and no error or log says so. Either add the field to Input AND populate "+
			"it in OPAAuthz (which sees only the request: it runs before the handler and never "+
			"loads the row), or delete the rule and record where that control really lives.\n\n"+
			"What Input actually carries: input.%s",
			strings.Join(unsendable, "\n  input."), strings.Join(known, ", input."))
	}
}

// The other direction is informational rather than a failure. Input carries
// context the SHIPPED policy does not happen to use -- user.id and
// user.tenant_id, for instance -- and that is legitimate: the input is the
// contract an operator writes their own rules against, and a field the product
// can genuinely fill is worth offering whether or not the default policy reads
// it. The failure case is the opposite one, above.
//
// What this does catch is a field the product cannot fill at all, which is what
// Owner was: it is reported here so it is noticed, with the reasoning left in
// ResourceContext's comment.
func TestInputCarriesNothingTheAuthorizerCannotFill(t *testing.T) {
	read := map[string]bool{}
	for _, p := range policyInputPaths(t) {
		read[p] = true
	}

	// Every leaf Input declares, and whether the shipped policy reads it.
	var unread []string
	for path := range sentInputPaths() {
		if strings.Count(path, ".") == 0 && path != "method" && path != "path" {
			continue // an object, not a leaf
		}
		if !read[path] {
			unread = append(unread, path)
		}
	}
	sort.Strings(unread)
	t.Logf("input fields the shipped policy does not read (available to an operator's own "+
		"rules, and each one something OPAAuthz can actually fill): input.%s",
		strings.Join(unread, ", input."))

	// The hard part: every field must be fillable from the request alone.
	// ResourceContext is the one that invited a rule it could not serve, so it is
	// pinned by name — Type is derived from the matched route, and there is
	// nothing else the authorizer knows about the resource.
	rt := reflect.TypeOf(ResourceContext{})
	if rt.NumField() != 1 || rt.Field(0).Name != "Type" {
		var got []string
		for i := 0; i < rt.NumField(); i++ {
			got = append(got, rt.Field(i).Name)
		}
		t.Errorf("ResourceContext now carries %v. OPAAuthz builds its input before the handler "+
			"runs and never loads the row being authorized, so the only thing it can say about "+
			"the resource is the type it derives from the matched route. A field it cannot fill "+
			"reads as available in the policy contract and invites a rule that never fires -- "+
			"which is exactly what the deleted Owner field did. If the authorizer can genuinely "+
			"fill this one, populate it in OPAAuthz and update this test to say so.", got)
	}
}

// Every openidx.authz policy in the tree must be the same policy. There are two
// copies -- the .rego docker-compose mounts and a Helm install ships, and the
// ConfigMap in dev-kube -- and they were not the same: the dev-kube copy was a
// policy of its own whose every rule read a field the product does not send, so
// with `default allow = false` above them it denied everything. It was inert
// only because nothing in dev-kube sets ENABLE_OPA_AUTHZ, which is exactly the
// flag the readiness guide tells an operator to turn on first.
//
// Copies drift; that is what copies do. This fails when they do.
func TestEveryAuthzPolicyIsTheSamePolicy(t *testing.T) {
	canonical, err := os.ReadFile(canonicalPolicy)
	if err != nil {
		t.Fatalf("cannot read %s: %v", canonicalPolicy, err)
	}
	want := strings.TrimRight(string(canonical), "\n")

	for _, policy := range findAuthzPolicies(t) {
		if strings.HasSuffix(policy.where, filepath.Base(canonicalPolicy)) {
			continue
		}
		got := strings.TrimRight(policy.source, "\n")
		if got == want {
			continue
		}
		t.Errorf("the openidx.authz policy in %s is not the one in %s.\n\n"+
			"Both are queried at /v1/data/openidx/authz by the same middleware with the same "+
			"input, so a second version of this policy is a second set of authorization rules "+
			"nobody reviews. Copy the canonical file in verbatim.\n\n%s",
			policy.where, canonicalPolicy, firstDifference(want, got))
	}
}

// firstDifference reports the first line where two policies diverge, because a
// whole-file diff in a test failure is unreadable.
func firstDifference(want, got string) string {
	w := strings.Split(want, "\n")
	g := strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return "first difference at line " + strconv.Itoa(i+1) + ":\n  canonical: " +
				strconv.Quote(wl) + "\n  this copy: " + strconv.Quote(gl)
		}
	}
	return "the two differ only in trailing whitespace"
}

// A .rego file that is not an openidx.authz policy cannot affect any decision
// this product makes, and saying so needs no judgement: nothing in the Go tree
// reads rego from disk or compiles it in-process, and go.mod carries no
// open-policy-agent dependency, so the only rego that is ever evaluated is what
// an operator mounts into the OPA server at /v1/data/openidx/authz.
//
// policies/access_control.rego was 255 lines in package `openidx`, and
// internal/governance/POLICY_README.md was 385 lines documenting the
// `PolicyEvaluator` that would have loaded it -- in-memory compilation, hot
// reload, a policy cache, Prometheus metrics, `go get
// github.com/open-policy-agent/opa@v0.69.0`, and two more .rego files. None of
// it exists. There is no PolicyEvaluator, no LoadPoliciesFromDirectory, no
// internal/governance/policy.go and no OPA dependency. The guide had already
// recorded that policy as deleted (§P5.4 item 4) while it sat in the tree, which
// is the same defect one layer up: a scorecard entry describing work nobody did.
//
// Both are gone. This keeps a third from arriving as documentation of a module.
func TestNoInertPolicyFilesInTheTree(t *testing.T) {
	var inert []string
	skip := map[string]bool{".git": true, "node_modules": true, "dist": true, "bin": true}
	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skip[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".rego" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if !strings.Contains(string(raw), authzPackage) {
			inert = append(inert, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s for policies: %v", repoRoot, err)
	}
	if len(inert) > 0 {
		sort.Strings(inert)
		t.Errorf("rego file(s) in the tree that are not %q and therefore cannot be evaluated "+
			"by anything this product runs:\n  %s\n\nNo Go code here reads or compiles rego; "+
			"the only policy that reaches a decision is the one served to OPA at "+
			"/v1/data/openidx/authz. A policy file that nothing evaluates reads as a control "+
			"and is not one. Delete it, or make it the policy that is actually served.",
			authzPackage, strings.Join(inert, "\n  "))
	}
}
