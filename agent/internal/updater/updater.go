// Package updater implements cross-platform self-update: poll a version
// manifest, and when it advertises a newer artifact, download it, verify its
// SHA-256 against the manifest, and apply it with the platform-appropriate
// installer — msiexec on Windows, `installer` for a macOS .pkg, dpkg/rpm for
// Linux packages, or an atomic executable self-replace + re-exec for a bare
// binary/AppImage. The manifest URL is configured per-install; empty disables
// auto-update.
//
// Manifest format (JSON) — the url's file extension selects the install method:
//
//	{ "version": "1.2.0",
//	  "url": "https://.../OpenIDX-1.2.0.msi",   // or .pkg/.deb/.rpm/.AppImage/bare
//	  "sha256": "<64 hex chars>",
//	  "signature": "<base64 RSA PKCS#1 v1.5 over SHA-256>" }
//
// WHAT IS VERIFIED. Two independent things, and it took two rounds to get both:
//
//   - the ARTIFACT, against the SHA-256 the manifest pins. Mandatory. It used
//     to be optional — `if wantSHA != ""` — so a manifest that omitted sha256
//     installed an unverified artifact; a control the checked input can switch
//     off is not a control. Both URLs must also be https (loopback excepted,
//     see requireSecureURL), since over plain http the digest is rewritten
//     along with the artifact and protects nothing.
//
//   - the MANIFEST, against the pinned release publisher (see trust.go).
//     Mandatory. The digest alone could never say anything about WHO chose the
//     artifact, because the same document supplies the url and the digest that
//     matches it; the doc comment here used to record that as the next step.
//     It is done: Fetch refuses a manifest this agent's trusted publisher did
//     not sign, before a byte is downloaded.
//
// The order matters. Signature first, on the small document, over the network
// path an attacker most easily controls; then the download, whose digest is now
// a claim by a publisher rather than by whoever answered the request.
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// maxArtifactBytes caps a download. The digest catches a substituted artifact,
// but only after it has been written: without a ceiling, a manifest pointing at
// an endless response fills the disk of every machine that polls it, and the
// agent runs on endpoints rather than servers. Generous by two orders of
// magnitude over the ~50 MB the real installers weigh.
const maxArtifactBytes = 1 << 30 // 1 GiB

// Manifest describes the latest published release.
//
// Every field but Signature is covered by Signature (see signingInput); adding
// one without covering it fails TestTheSignatureCoversEveryManifestField,
// because a field outside the signature is a field an attacker can choose.
type Manifest struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	// Signature is base64 RSASSA-PKCS1-v1_5 over SHA-256 of signingInput,
	// made by the pinned release publisher. Verified by Verify, which Fetch
	// calls before returning; there is no path that returns an unverified
	// manifest.
	Signature string `json:"signature"`
}

// requireSecureURL rejects a URL this package must not fetch from.
//
// https, or http to a loopback address. The loopback exception is not a
// weakening: an attacker who can serve 127.0.0.1 is already running code on the
// machine and does not need the updater. It is there because the tests and a
// local artifact server need it, and an exception that is written down is safer
// than one improvised later.
func requireSecureURL(what, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a URL: %w", what, err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("%s uses http://%s: the digest that protects the download "+
			"travels in the same channel, so plain http protects nothing. Use https", what, host)
	default:
		return fmt.Errorf("%s uses scheme %q; only https (or http to loopback) is fetched", what, u.Scheme)
	}
}

// validDigest reports whether s is a 64-character hex SHA-256.
//
// Shape-checked rather than merely non-empty: "sha256": "TODO" is not a digest,
// and comparing it against the real one would fail with a confusing mismatch
// instead of naming the manifest as malformed.
func validDigest(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// Fetch retrieves, parses, validates and VERIFIES the version manifest. A
// manifest that does not pin a digest, that points anywhere this package will
// not fetch from, or that the trusted publisher did not sign, is rejected here
// — before anything is downloaded — so the refusal names the manifest rather
// than surfacing later as a failed install.
//
// trust is a required parameter and its zero value trusts nobody: a caller that
// has no anchor to offer gets a refusal, never a pass. See trust.go.
func Fetch(ctx context.Context, manifestURL string, trust Trust) (*Manifest, error) {
	if err := requireSecureURL("manifest URL", manifestURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest returned %d", resp.StatusCode)
	}
	var m Manifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if m.Version == "" || m.URL == "" {
		return nil, fmt.Errorf("manifest missing version/url")
	}
	if err := requireSecureURL("artifact URL", m.URL); err != nil {
		return nil, err
	}
	if !validDigest(strings.TrimSpace(m.SHA256)) {
		return nil, fmt.Errorf("manifest does not pin a valid sha256 (got %q): "+
			"the digest is what makes the downloaded installer safe to run, and this "+
			"agent will not install an artifact it cannot verify", m.SHA256)
	}
	m.SHA256 = strings.TrimSpace(m.SHA256)
	// The signature is checked LAST of the manifest's properties but BEFORE the
	// caller sees the manifest at all: the shape checks above produce precise
	// errors about a malformed document, and this one answers the different
	// question of whether the document is ours.
	if err := Verify(&m, trust); err != nil {
		return nil, fmt.Errorf("manifest at %s: %w", manifestURL, err)
	}
	return &m, nil
}

// Newer reports whether candidate is a strictly higher version than current.
// Compares dot/dash-separated numeric segments; a non-numeric current (e.g.
// "dev") is always considered older.
func Newer(current, candidate string) bool {
	if current == "dev" || current == "" {
		return true
	}
	return compare(segments(candidate), segments(current)) > 0
}

func segments(v string) []int {
	parts := strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' })
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n, ok := 0, len(p) > 0
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				ok = false
				break
			}
			n = n*10 + int(ch-'0')
		}
		if !ok {
			break
		}
		nums = append(nums, n)
	}
	return nums
}

func compare(a, b []int) int {
	max := len(a)
	if len(b) > max {
		max = len(b)
	}
	for i := 0; i < max; i++ {
		var av, bv int
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

// artifactExt returns the download URL's file extension (lowercased, with the
// leading dot), which selects the install method. Query/fragment suffixes are
// stripped first; a URL with no extension yields ".bin" (treated as a bare
// binary for self-replace).
func artifactExt(url string) string {
	u := url
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	ext := strings.ToLower(filepath.Ext(u))
	if ext == "" {
		return ".bin"
	}
	return ext
}

// downloadVerified downloads artifactURL to a temp file and verifies its
// SHA-256 against wantSHA. Returns the temp file path (caller removes it).
//
// There is no path through this function that returns a file it did not verify.
// An empty or malformed wantSHA is refused rather than treated as "no digest
// requested" — Fetch already rejects such a manifest, and a second caller that
// forgot to must fail here rather than hand an unchecked installer to msiexec.
func downloadVerified(ctx context.Context, artifactURL, wantSHA string) (string, error) {
	wantSHA = strings.TrimSpace(wantSHA)
	if !validDigest(wantSHA) {
		return "", fmt.Errorf("refusing to download %s without a valid sha256 to check it against", artifactURL)
	}
	if err := requireSecureURL("artifact URL", artifactURL); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifactURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned %d", resp.StatusCode)
	}

	f, err := os.CreateTemp("", "openidx-update-*"+artifactExt(artifactURL))
	if err != nil {
		return "", err
	}
	h := sha256.New()
	// One byte past the cap so a response that reaches it is reported as too
	// large rather than silently truncated into a digest mismatch, which would
	// name the wrong cause.
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxArtifactBytes+1))
	f.Close()
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	if n > maxArtifactBytes {
		os.Remove(f.Name())
		return "", fmt.Errorf("artifact exceeds %d bytes; refusing to fill the disk", maxArtifactBytes)
	}

	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, wantSHA) {
		os.Remove(f.Name())
		return "", fmt.Errorf("checksum mismatch: got %s want %s", got, wantSHA)
	}
	return f.Name(), nil
}

// CheckAndApply fetches the manifest, verifies the trusted publisher signed it,
// and if it advertises a newer version than currentVersion, downloads the
// artifact, verifies its digest, and applies it with the platform installer.
// Returns whether an update was applied and the new version. Every refusal above
// — an http URL, a missing or malformed digest, an unsigned or wrongly-signed
// manifest, a digest mismatch — reaches the caller as an error and installs
// nothing.
func CheckAndApply(ctx context.Context, manifestURL, currentVersion string, trust Trust) (applied bool, newVersion string, err error) {
	m, err := Fetch(ctx, manifestURL, trust)
	if err != nil {
		return false, "", err
	}
	if !Newer(currentVersion, m.Version) {
		return false, m.Version, nil
	}
	path, err := downloadVerified(ctx, m.URL, m.SHA256)
	if err != nil {
		return false, m.Version, err
	}
	// Move the artifact to a stable, predictable temp path before applying: the
	// Windows msiexec path runs asynchronously, and a self-replace reads it as
	// the new binary.
	stable := filepath.Join(os.TempDir(), "OpenIDX-"+m.Version+artifactExt(m.URL))
	_ = os.Rename(path, stable)
	if err := apply(stable); err != nil {
		return false, m.Version, err
	}
	return true, m.Version, nil
}
