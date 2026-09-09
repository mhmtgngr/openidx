package updater

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The manifest this package refuses to accept without a digest — and now
// without a signature — is produced by a PowerShell step in
// .github/workflows/windows-client-build.yml, on a tag, in a different language
// from the one that reads it. Nothing checked the two agree.
//
// That gap is why the consumer's rules have to be visible from the producer's
// side too: the day someone simplifies that step, every agent stops updating —
// and the failure appears on customer endpoints, not in CI, because no job
// installs a release and then updates it.
//
// This reads the generator out of the workflow and requires everything Fetch
// demands. It is a source check, not a run: PowerShell is not available here and
// the point is the contract, not the bytes.

const manifestWorkflow = "../../../.github/workflows/windows-client-build.yml"

// generatorStepName is the step that builds latest.json. Named here because
// three tests below look for it and a rename should break in one place.
const generatorStepName = "name: Generate and sign latest.json"

func generatorStep(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(manifestWorkflow)
	if err != nil {
		t.Fatalf("%s: %v (this test reads the manifest generator; if the step moved, "+
			"point manifestWorkflow at its new home)", manifestWorkflow, err)
	}
	src := string(b)
	i := strings.Index(src, generatorStepName)
	if i < 0 {
		t.Fatalf("%s has no %q step. Either the release stopped publishing a manifest — "+
			"in which case update_manifest_url points at nothing — or it was renamed.",
			manifestWorkflow, generatorStepName)
	}
	// To the next step at the same indentation, so a later step's YAML cannot
	// satisfy the assertions below.
	rest := src[i:]
	if j := regexp.MustCompile(`\n      - name: `).FindStringIndex(rest[1:]); j != nil {
		rest = rest[:j[0]+1]
	}
	return rest
}

// TestTheReleaseManifestCarriesEverythingFetchRequires.
func TestTheReleaseManifestCarriesEverythingFetchRequires(t *testing.T) {
	step := generatorStep(t)

	for _, field := range []string{"version", "url", "sha256", "signature"} {
		// The generator builds the object as `@{ version = ...; url = ...; ... }`.
		if !regexp.MustCompile(`\b` + field + `\s*=`).MatchString(step) {
			t.Errorf("the release manifest generator does not set %q. Fetch rejects a "+
				"manifest missing it, so every agent configured with update_manifest_url "+
				"would refuse to update — correctly, and invisibly until someone looks at "+
				"an endpoint.", field)
		}
	}

	// The digest has to be computed from the artifact that is actually published,
	// not typed in. Get-FileHash over the MSI is what does that.
	if !strings.Contains(step, "Get-FileHash") {
		t.Error("the generator does not compute the digest with Get-FileHash; a literal " +
			"or carried-over value would pin the wrong artifact")
	}
	if !regexp.MustCompile(`SHA256`).MatchString(step) {
		t.Error("the generator's hash algorithm is not SHA256, which is the only one Fetch checks")
	}

	// requireSecureURL refuses anything but https off loopback, so a manifest
	// pointing at http would be rejected at the agent. Catch it here instead.
	if !strings.Contains(step, `"https://`) {
		t.Error("the artifact URL in the generator is not https; requireSecureURL refuses it")
	}
	if regexp.MustCompile(`"http://[^"]`).MatchString(step) {
		t.Error("the generator builds a plain-http URL")
	}
}

// TestTheReleaseRefusesToPublishAnUnsignedManifest.
//
// The Authenticode steps in this workflow all run only when
// WINDOWS_CERT_PFX_BASE64 is non-empty — optional by design, because an
// unsigned exe still runs. An unsigned
// MANIFEST does not: every agent refuses it. So this step must not be optional
// in the same way; it must fail the release, loudly, where someone is watching.
func TestTheReleaseRefusesToPublishAnUnsignedManifest(t *testing.T) {
	step := generatorStep(t)

	if regexp.MustCompile(`if:\s*\$\{\{\s*env\.WINDOWS_CERT_PFX_BASE64\s*!=\s*''`).MatchString(step) {
		t.Error("the manifest generator is skipped when no signing certificate is configured. " +
			"Then the release publishes no manifest at all and every agent's next poll 404s — " +
			"self-update off, silently. It must fail instead.")
	}
	if !strings.Contains(step, "throw") {
		t.Error("the manifest generator does not throw when the signing certificate is missing; " +
			"it would publish an unsigned manifest that every agent refuses")
	}
	if !strings.Contains(step, "WINDOWS_CERT_PFX_BASE64") {
		t.Error("the manifest generator does not check for the signing certificate at all")
	}

	// It must also verify what it produced, with the public half the agent
	// pins — otherwise a mismatched secret ships a release nothing can install.
	if !strings.Contains(step, "VerifyData") {
		t.Error("the generator signs but never verifies. A WINDOWS_CERT_PFX_BASE64 holding a " +
			"different key from agent/packaging/openidx-codesign.cer would publish a manifest " +
			"every agent refuses, and CI would be green")
	}
	if !strings.Contains(step, "openidx-codesign.cer") {
		t.Error("the generator's verification does not use the certificate the agent pins, so it " +
			"proves only that the key signed with itself")
	}
	if !strings.Contains(step, "Pkcs1") || !strings.Contains(step, "SHA256") {
		t.Error("the generator does not name RSA PKCS#1 v1.5 over SHA-256, which is the only " +
			"algorithm verifyWith implements")
	}
}

// TestTheProducersCanonicalFormIsTheOneTheAgentVerifies is the cross-language
// contract itself, rather than a check that both sides mention the same words.
//
// The signature covers a canonical string, and it is built twice: by PowerShell
// in the workflow and by signingInput here. A one-character disagreement — a
// reordered field, a lost trailing newline, CRLF — produces a signature that
// verifies nowhere, on a release that has already shipped. So this reads the
// producer's array out of the YAML, substitutes its variables, and requires the
// result to equal what Go signs for the same manifest.
func TestTheProducersCanonicalFormIsTheOneTheAgentVerifies(t *testing.T) {
	step := generatorStep(t)

	block := regexp.MustCompile(`(?s)\$lines\s*=\s*@\((.*?)\)`).FindStringSubmatch(step)
	if block == nil {
		t.Fatal("the generator no longer builds the signing input as `$lines = @( ... )`. " +
			"This test cannot read it, and nothing else compares the two languages' canonical forms.")
	}
	quoted := regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(block[1], -1)
	if len(quoted) == 0 {
		t.Fatal("the generator's $lines array holds no quoted strings")
	}

	const (
		ver = "1.34.0"
		url = "https://github.com/mhmtgngr/openidx/releases/download/agent-v1.34.0/OpenIDX-1.34.0.msi"
	)
	sha := strings.Repeat("ab", 32)
	repl := strings.NewReplacer("$ver", ver, "$url", url, "$sha", sha)

	lines := make([]string, 0, len(quoted))
	for _, q := range quoted {
		lines = append(lines, repl.Replace(q[1]))
	}
	// `($lines -join "`n") + "`n"` — LF-joined with one trailing newline.
	producer := strings.Join(lines, "\n") + "\n"

	want, err := signingInput(&Manifest{Version: ver, URL: url, SHA256: sha})
	if err != nil {
		t.Fatalf("signingInput: %v", err)
	}
	if producer != string(want) {
		t.Errorf("the release signs a different message from the one the agent verifies.\n"+
			"  release  (%d bytes): %q\n"+
			"  agent    (%d bytes): %q\n"+
			"Every manifest published this way would be refused by every agent.",
			len(producer), producer, len(want), string(want))
	}

	// And the join must be LF with a trailing newline, which the comparison
	// above only catches if the fixture happens to differ. Say it directly.
	if !strings.Contains(step, "-join \"`n\"") {
		t.Error("the generator does not join the signing input with LF; CRLF would change every byte " +
			"after the first line")
	}
}

// TestTheDocumentedManifestURLIsHTTPS. The install script and the workflow
// comment both hand operators an update_manifest_url; if either were http, the
// agent would refuse at the first poll.
func TestTheDocumentedManifestURLIsHTTPS(t *testing.T) {
	b, err := os.ReadFile(manifestWorkflow)
	if err != nil {
		t.Fatalf("%s: %v", manifestWorkflow, err)
	}
	for _, m := range regexp.MustCompile(`update_manifest_url\s*=\s*(\S+)`).FindAllStringSubmatch(string(b), -1) {
		if !strings.HasPrefix(m[1], "https://") {
			t.Errorf("a documented update_manifest_url is %q, which this agent will not fetch", m[1])
		}
	}
}
