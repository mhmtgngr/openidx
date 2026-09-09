package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
			_, err := Fetch(context.Background(), srv.URL+"/latest.json")
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
	srv := serveManifest(t, artifact, func(u string) string {
		return fmt.Sprintf(`{"version":"9.9.9","url":%q,"sha256":%q}`, u, digestOf(artifact))
	})
	m, err := Fetch(context.Background(), srv.URL+"/latest.json")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if m.Version != "9.9.9" || m.SHA256 != digestOf(artifact) {
		t.Errorf("manifest read back as %+v", m)
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
	_, err := Fetch(context.Background(), srv.URL+"/latest.json")
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

	applied, version, err := CheckAndApply(context.Background(), srv.URL+"/latest.json", "1.0.0")
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
