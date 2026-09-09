package updater

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The manifest this package refuses to accept without a digest is produced by a
// PowerShell step in .github/workflows/windows-client-build.yml, on a tag, in a
// different language from the one that reads it. Nothing checked the two agree.
//
// That gap is why the consumer's rule has to be visible from the producer's
// side too: the day someone simplifies that step and drops sha256, every agent
// stops updating — and the failure appears on customer endpoints, not in CI,
// because no job installs a release and then updates it.
//
// This reads the generator out of the workflow and requires the three fields
// Fetch demands, over https. It is a source check, not a run: PowerShell is not
// available here and the point is the contract, not the bytes.

const manifestWorkflow = "../../../.github/workflows/windows-client-build.yml"

func generatorStep(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(manifestWorkflow)
	if err != nil {
		t.Fatalf("%s: %v (this test reads the manifest generator; if the step moved, "+
			"point manifestWorkflow at its new home)", manifestWorkflow, err)
	}
	src := string(b)
	const marker = "name: Generate latest.json"
	i := strings.Index(src, marker)
	if i < 0 {
		t.Fatalf("%s has no %q step. Either the release stopped publishing a manifest — "+
			"in which case update_manifest_url points at nothing — or it was renamed.",
			manifestWorkflow, marker)
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

	for _, field := range []string{"version", "url", "sha256"} {
		// The generator builds the object as `@{ version = ...; url = ...; sha256 = ... }`.
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
