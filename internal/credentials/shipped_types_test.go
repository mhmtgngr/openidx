package credentials

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// repoRoot walks up from the package directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not a git checkout, cannot locate repo root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	return string(b)
}

// TestShippedTypesMatchesCompiledRotators is the anchor: the canonical list has
// to describe the rotators that actually exist in this package. Every
// non-test file declaring Type() must appear, and nothing may be listed that
// no longer compiles.
func TestShippedTypesMatchesCompiledRotators(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "internal", "credentials")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot list %s: %v", dir, err)
	}

	// Test files define fake rotators (fake, fake_minter, gen). Counting those
	// would overstate what we ship, so they are excluded deliberately.
	re := regexp.MustCompile(`Type\(\) string \{ return "([a-z_]+)"`)
	var compiled []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		for _, m := range re.FindAllStringSubmatch(mustRead(t, filepath.Join(dir, name)), -1) {
			compiled = append(compiled, m[1])
		}
	}
	sort.Strings(compiled)

	want := append([]string(nil), ShippedTypes...)
	sort.Strings(want)

	if strings.Join(compiled, ",") != strings.Join(want, ",") {
		t.Errorf("ShippedTypes drifted from the rotators that compile:\n  compiled: %v\n  declared: %v",
			compiled, want)
	}
}

// TestShippedTypesAreRegistered guards the gap between "the type compiles" and
// "the running binary can actually use it". A rotator that is never passed to
// NewService is dead code no operator can reach.
func TestShippedTypesAreRegistered(t *testing.T) {
	root := repoRoot(t)
	main := mustRead(t, filepath.Join(root, "cmd", "admin-api", "main.go"))

	start := strings.Index(main, "rotators := []credentials.Rotator{")
	if start < 0 {
		t.Fatal("could not find the rotator registration slice in cmd/admin-api/main.go")
	}
	end := strings.Index(main[start:], "}")
	if end < 0 {
		t.Fatal("rotator registration slice is not terminated")
	}
	block := main[start : start+end]

	// NewGenerateOnlyRotator -> generate_only, NewAWSIAMRotator -> aws_iam.
	// Matching on the constructor name is too brittle across naming styles, so
	// each shipped type is checked for a plausible constructor instead.
	ctor := regexp.MustCompile(`credentials\.New([A-Za-z]+)Rotator\(`)
	got := map[string]bool{}
	for _, m := range ctor.FindAllStringSubmatch(block, -1) {
		got[strings.ToLower(m[1])] = true
	}

	for _, typ := range ShippedTypes {
		// aws_iam -> awsiam, generate_only -> generateonly, ssh_key -> sshkey
		key := strings.ReplaceAll(typ, "_", "")
		switch key {
		case "generateonly":
			key = "generateonly"
		case "gcpsa":
			key = "gcpsa"
		}
		if !got[key] {
			t.Errorf("rotation type %q is declared in ShippedTypes but never registered in cmd/admin-api/main.go; "+
				"an operator cannot select it", typ)
		}
	}
	if len(got) != len(ShippedTypes) {
		t.Errorf("main.go registers %d rotators but ShippedTypes declares %d", len(got), len(ShippedTypes))
	}
}

// TestConsoleOffersEveryShippedType closes the last gap. The engine can support
// a connector while the admin console never offers it, which looks to the
// operator exactly like it does not exist.
//
// The connector dropdown is generated from the page's CONNECTOR_TYPES list and
// labelled from the i18n catalog, so both halves are checked: a type missing
// from the list has no option at all, and one missing from the catalog renders
// as a raw key, which is just as unusable. English is the source of truth here;
// the i18n suite pins the same keys in every other declared language.
func TestConsoleOffersEveryShippedType(t *testing.T) {
	root := repoRoot(t)
	page := filepath.Join(root, "web", "admin-console", "src", "pages", "rotation-policies.tsx")
	catalog := filepath.Join(root, "web", "admin-console", "src", "i18n", "locales", "en.ts")
	if _, err := os.Stat(page); err != nil {
		t.Skipf("console page not present in this checkout: %v", err)
	}

	offered := consoleConnectorTypes(t, mustRead(t, page))
	labelled := catalogConnectorLabels(t, mustRead(t, catalog))

	for _, typ := range ShippedTypes {
		if !offered[typ] {
			t.Errorf("rotation type %q ships in the binary but the console offers no option for it", typ)
			continue
		}
		if !labelled[typ] {
			t.Errorf("rotation type %q is offered by the console but has no label in the English catalog "+
				"(pages.rotationPolicies.connectors.%s); the dropdown would show a raw key", typ, typ)
		}
	}
}

// consoleConnectorTypes reads the CONNECTOR_TYPES literal that drives the
// connector dropdown.
func consoleConnectorTypes(t *testing.T, src string) map[string]bool {
	t.Helper()
	block := betweenDelimiters(t, src, "const CONNECTOR_TYPES = [", "]",
		"rotation-policies.tsx no longer declares CONNECTOR_TYPES; if the dropdown moved, update this test")
	return quotedIdents(block)
}

// catalogConnectorLabels reads pages.rotationPolicies.connectors from the
// English catalog.
func catalogConnectorLabels(t *testing.T, src string) map[string]bool {
	t.Helper()
	section := betweenDelimiters(t, src, "    rotationPolicies: {", "\n    },",
		"en.ts no longer has a pages.rotationPolicies section")
	block := betweenDelimiters(t, section, "connectors: {", "}",
		"pages.rotationPolicies has no connectors block")
	keys := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s*([a-z_]+):`).FindAllStringSubmatch(block, -1) {
		keys[m[1]] = true
	}
	return keys
}

func betweenDelimiters(t *testing.T, src, open, close, missing string) string {
	t.Helper()
	start := strings.Index(src, open)
	if start < 0 {
		t.Fatal(missing)
	}
	rest := src[start+len(open):]
	end := strings.Index(rest, close)
	if end < 0 {
		t.Fatalf("%s: block starting at %q is not terminated", missing, open)
	}
	return rest[:end]
}

func quotedIdents(block string) map[string]bool {
	out := map[string]bool{}
	for _, m := range regexp.MustCompile(`'([a-z_]+)'`).FindAllStringSubmatch(block, -1) {
		out[m[1]] = true
	}
	return out
}

// TestDocsStateTheShippedCount is the check that was missing, and its absence
// is the entire defect: the guide said six for as long as nobody re-counted.
// The number in the docs is now measured against the code on every run.
func TestDocsStateTheShippedCount(t *testing.T) {
	root := repoRoot(t)
	doc := filepath.Join(root, "docs", "FEATURE_TEST_GUIDE_TR.md")
	if _, err := os.Stat(doc); err != nil {
		t.Skipf("guide not present in this checkout: %v", err)
	}
	src := mustRead(t, doc)

	re := regexp.MustCompile(`(\d+) connector tipi`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatal(`docs/FEATURE_TEST_GUIDE_TR.md no longer states "<n> connector tipi"; ` +
			"if the wording changed, update this test so the count stays measured")
	}
	stated, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("unparsable count %q: %v", m[1], err)
	}
	if stated != len(ShippedTypes) {
		t.Errorf("the test guide promises %d rotation connectors but this build ships %d (%v); "+
			"a stale number sends the field tester looking for features that moved",
			stated, len(ShippedTypes), ShippedTypes)
	}
}
