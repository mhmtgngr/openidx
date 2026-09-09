package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// What this self-updater does with what it downloads: msiexec /i as SYSTEM on
// Windows, `sudo -n dpkg -i` / `rpm -U --force` / `installer -pkg` on Linux and
// macOS, or an atomic replace of its own executable followed by syscall.Exec.
// So the digest check is the whole of the trust boundary, and until now it was
// conditional on the manifest supplying one:
//
//	if wantSHA != "" { ...verify... }
//	return f.Name(), nil
//
// A manifest that omitted sha256 therefore installed an unverified artifact.
// Nothing tested it: artifactExt and Newer were covered, and Fetch,
// downloadVerified and CheckAndApply — every function that touches the network
// or decides what runs — were not.
//
// These cases are all about refusal. The one that matters most is the first:
// it is the exact manifest shape that used to work.

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// serveManifest returns a loopback server publishing one manifest body, and the
// URL of an artifact it hosts alongside.
//
// The artifact it serves is FETCHABLE, so it is only safe for tests that cannot
// reach apply() — either they call Fetch/downloadVerified directly, or the
// manifest is one Fetch refuses. A CheckAndApply test that gets as far as apply
// with a bare-extension artifact overwrites and re-execs the test binary on
// Linux and macOS (strategySelfReplace), and the payload's exit status then
// becomes the package's. See TestCheckAndApplyInstallsNothingFromAnUnsignedManifest,
// which serves a 404 and counts requests for exactly this reason.
func serveManifest(t *testing.T, artifact []byte, manifestFor func(artifactURL string) string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/artifact.bin", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	})
	mux.HandleFunc("/latest.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, manifestFor(srv.URL+"/artifact.bin"))
	})
	return srv
}

func TestFetchRejectsAManifestThatPinsNoDigest(t *testing.T) {
	artifact := []byte("#!/bin/sh\necho pwned\n")

	for _, tc := range []struct {
		name   string
		sha    string
		reason string
	}{
		{
			name:   "absent",
			sha:    "",
			reason: "the shape that used to install an unverified artifact",
		},
		{
			name:   "whitespace",
			sha:    "   ",
			reason: "non-empty but not a digest; the old check was `!= \"\"`",
		},
		{
			name:   "placeholder",
			sha:    "TODO",
			reason: "a value someone meant to fill in",
		},
		{
			name:   "truncated",
			sha:    digestOf(artifact)[:32],
			reason: "half a digest is not a digest",
		},
		{
			name:   "not hex",
			sha:    strings.Repeat("z", 64),
			reason: "right length, not hex",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := serveManifest(t, artifact, func(u string) string {
				return fmt.Sprintf(`{"version":"9.9.9","url":%q,"sha256":%q}`, u, tc.sha)
			})
			_, err := Fetch(context.Background(), srv.URL+"/latest.json", publisher(t).trust())
			if err == nil {
				t.Fatalf("Fetch accepted a manifest with sha256=%q (%s); "+
					"this agent would install what it advertises without checking it", tc.sha, tc.reason)
			}
			if !strings.Contains(err.Error(), "sha256") {
				t.Errorf("error does not name the digest as the problem: %v", err)
			}
		})
	}
}

func TestFetchAcceptsAWellFormedManifest(t *testing.T) {
	artifact := []byte("real installer bytes")
	pub := publisher(t)
	var signed *Manifest
	srv := serveManifest(t, artifact, func(u string) string {
		signed = pub.signedManifest(t, "9.9.9", u, digestOf(artifact))
		b, err := json.Marshal(signed)
		if err != nil {
			t.Fatalf("marshal manifest: %v", err)
		}
		return string(b)
	})
	m, err := Fetch(context.Background(), srv.URL+"/latest.json", pub.trust())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if m.Version != "9.9.9" || m.SHA256 != digestOf(artifact) {
		t.Errorf("manifest read back as %+v", m)
	}
}

// TestFetchRefusesAManifestTheTrustedPublisherDidNotSign is the network-level
// half of trust_test.go: not the verifier in isolation, but Fetch on a served
// document, which is where a real attacker meets this code.
//
// The three cases are the three documents an attacker can produce. Only the
// last one requires a key at all, and it is the one that a "is it signed?"
// check — rather than "is it signed by the publisher?" — would let through.
func TestFetchRefusesAManifestTheTrustedPublisherDidNotSign(t *testing.T) {
	artifact := []byte("#!/bin/sh\necho pwned\n")
	pub, other := publisher(t), impostor(t)

	for _, tc := range []struct {
		name string
		body func(u string) string
	}{
		{
			name: "unsigned",
			body: func(u string) string {
				// The exact document every release published before this change.
				return fmt.Sprintf(`{"version":"9.9.9","url":%q,"sha256":%q}`, u, digestOf(artifact))
			},
		},
		{
			name: "signature field present but empty",
			body: func(u string) string {
				return fmt.Sprintf(`{"version":"9.9.9","url":%q,"sha256":%q,"signature":""}`, u, digestOf(artifact))
			},
		},
		{
			name: "validly signed by somebody else",
			body: func(u string) string {
				b, err := json.Marshal(other.signedManifest(t, "9.9.9", u, digestOf(artifact)))
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				return string(b)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := serveManifest(t, artifact, tc.body)
			_, err := Fetch(context.Background(), srv.URL+"/latest.json", pub.trust())
			if err == nil {
				t.Fatalf("Fetch accepted a %s manifest. Its sha256 is correct for the artifact it "+
					"names, which is the point: the digest proves the download, never the publisher.", tc.name)
			}
			if !strings.Contains(err.Error(), "signature") && !strings.Contains(err.Error(), "not signed by") {
				t.Errorf("the refusal does not name the signature: %v", err)
			}
		})
	}
}

// TestCheckAndApplyInstallsNothingFromAnUnsignedManifest drives the whole path
// and asserts the strongest available fact: the artifact is never even
// REQUESTED. An error alone would not prove that — a download that failed for
// its own reasons produces one too.
//
// THE ARTIFACT IS DELIBERATELY NOT SERVED, and no test in this package should
// serve a fetchable one to a manifest that could pass verification. On Linux and
// macOS an artifact with no package extension takes strategySelfReplace, which
// overwrites os.Executable() and syscall.Exec's it — under `go test` that is the
// TEST BINARY. The replacement then decides the package's exit status: a payload
// that exits 0 makes `go test` print "ok" after a failing test has already
// reported "--- FAIL". This was observed, not theorised, while red-proofing this
// commit. A green that a downloaded file can manufacture is not a green.
func TestCheckAndApplyInstallsNothingFromAnUnsignedManifest(t *testing.T) {
	artifact := []byte("#!/bin/sh\necho pwned\n")

	var artifactRequests atomic.Int32
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	artifactURL := srv.URL + "/artifact.bin"
	mux.HandleFunc("/artifact.bin", func(w http.ResponseWriter, r *http.Request) {
		artifactRequests.Add(1)
		http.Error(w, "this test must never get here", http.StatusNotFound)
	})
	mux.HandleFunc("/latest.json", func(w http.ResponseWriter, r *http.Request) {
		// Unsigned, but otherwise perfect: the digest is the real digest of the
		// artifact this URL names. Everything the old code checked, checks out.
		_, _ = fmt.Fprintf(w, `{"version":"9.9.9","url":%q,"sha256":%q}`, artifactURL, digestOf(artifact))
	})

	applied, version, err := CheckAndApply(context.Background(), srv.URL+"/latest.json", "1.0.0", publisher(t).trust())
	if err == nil {
		t.Fatal("CheckAndApply accepted an unsigned manifest whose digest matched the artifact")
	}
	if applied {
		t.Error("an update was applied from an unsigned manifest")
	}
	if version != "" {
		t.Errorf("version = %q; the manifest was rejected before it was read as authoritative", version)
	}
	if n := artifactRequests.Load(); n != 0 {
		t.Errorf("the artifact was requested %d time(s) from an unsigned manifest. The refusal must "+
			"happen at the manifest, before anything is downloaded, or a machine that never installs "+
			"the update still fetches whatever an unauthenticated document points it at", n)
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("the refusal does not name the signature, so it may have come from somewhere else "+
			"in the path: %v", err)
	}
}

// TestFetchRejectsPlainHTTP. Over http the digest travels in the same channel
// as the artifact, so whoever can rewrite one rewrites both and the check
// protects nothing. Loopback is the documented exception and is what every case
// above relies on.
func TestFetchRejectsPlainHTTP(t *testing.T) {
	for _, raw := range []string{
		"http://updates.example.com/latest.json",
		"http://10.0.0.5/latest.json",
		"ftp://updates.example.com/latest.json",
		"file:///tmp/latest.json",
	} {
		if err := requireSecureURL("manifest URL", raw); err == nil {
			t.Errorf("requireSecureURL accepted %q", raw)
		}
	}
	for _, raw := range []string{
		"https://updates.example.com/latest.json",
		"http://127.0.0.1:8080/latest.json",
		"http://localhost:8080/latest.json",
	} {
		if err := requireSecureURL("manifest URL", raw); err != nil {
			t.Errorf("requireSecureURL rejected %q: %v", raw, err)
		}
	}
}

// TestFetchRejectsAnInsecureArtifactURL: an https manifest may still point the
// download at http, which is the same hole one hop along.
func TestFetchRejectsAnInsecureArtifactURL(t *testing.T) {
	artifact := []byte("x")
	srv := serveManifest(t, artifact, func(string) string {
		return fmt.Sprintf(`{"version":"9.9.9","url":"http://evil.example.com/a.deb","sha256":%q}`, digestOf(artifact))
	})
	_, err := Fetch(context.Background(), srv.URL+"/latest.json", publisher(t).trust())
	if err == nil {
		t.Fatal("Fetch accepted a manifest whose artifact URL is plain http")
	}
	if !strings.Contains(err.Error(), "artifact URL") {
		t.Errorf("error does not name the artifact URL: %v", err)
	}
}

func TestDownloadVerifiedRefusesASubstitutedArtifact(t *testing.T) {
	real := []byte("the installer the operator published")
	swapped := []byte("something else entirely")
	srv := serveManifest(t, swapped, func(string) string { return "" })

	path, err := downloadVerified(context.Background(), srv.URL+"/artifact.bin", digestOf(real))
	if err == nil {
		os.Remove(path)
		t.Fatal("downloadVerified returned a file whose digest does not match the manifest")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestDownloadVerifiedRefusesWithoutADigest is the second half of the fix: Fetch
// rejects such a manifest, and this function refuses independently, so a caller
// that skips Fetch cannot reintroduce the hole.
func TestDownloadVerifiedRefusesWithoutADigest(t *testing.T) {
	artifact := []byte("anything")
	srv := serveManifest(t, artifact, func(string) string { return "" })

	for _, sha := range []string{"", "   ", "TODO"} {
		path, err := downloadVerified(context.Background(), srv.URL+"/artifact.bin", sha)
		if err == nil {
			os.Remove(path)
			t.Fatalf("downloadVerified(sha=%q) returned a file it never checked", sha)
		}
	}
}

func TestDownloadVerifiedAcceptsTheRealArtifact(t *testing.T) {
	artifact := []byte("the installer the operator published")
	srv := serveManifest(t, artifact, func(string) string { return "" })

	path, err := downloadVerified(context.Background(), srv.URL+"/artifact.bin", digestOf(artifact))
	if err != nil {
		t.Fatalf("downloadVerified: %v", err)
	}
	defer os.Remove(path)
	got, err := os.ReadFile(path) //nolint:gosec // path is the temp file this test just created
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(artifact) {
		t.Errorf("downloaded file does not match what was served")
	}
}

// TestCheckAndApplyInstallsNothingWhenTheManifestIsUnverifiable drives the whole
// path. apply() is never reached, which is the point: the refusal happens before
// anything is handed to an installer.
func TestCheckAndApplyInstallsNothingWhenTheManifestIsUnverifiable(t *testing.T) {
	artifact := []byte("#!/bin/sh\necho pwned\n")
	srv := serveManifest(t, artifact, func(u string) string {
		return fmt.Sprintf(`{"version":"9.9.9","url":%q}`, u) // no sha256 at all
	})

	applied, version, err := CheckAndApply(context.Background(), srv.URL+"/latest.json", "1.0.0", publisher(t).trust())
	if err == nil {
		t.Fatal("CheckAndApply accepted a manifest with no digest")
	}
	if applied {
		t.Error("an update was applied from an unverifiable manifest")
	}
	if version != "" {
		t.Errorf("version = %q; the manifest was rejected before it was read as authoritative", version)
	}
}
