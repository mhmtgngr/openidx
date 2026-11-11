package access

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// downloadsManifestSigningDomain separates a downloads-manifest signature from
// the update manifest (openidx-agent-update-manifest/v1) made by the same key.
const downloadsManifestSigningDomain = "openidx-agent-downloads-manifest/v1"

// manifestSignatureHeader carries the base64 RSASSA-PKCS1-v1_5/SHA-256
// signature of downloadsManifestSigningInput. A header, not a JSON field, so
// the per-OS map the wizard reads keeps its shape.
const manifestSignatureHeader = "X-OpenIDX-Manifest-Signature"

// downloadsManifestSigningInput is the canonical byte string signed for the
// downloads manifest: the domain line, then "<os>.<field>=<value>" lines for
// filename, sha256 and url, sorted by OS. Like the update manifest, fields are
// named rather than signing JSON bytes.
func downloadsManifestSigningInput(entries map[string]map[string]any) ([]byte, error) {
	oses := make([]string, 0, len(entries))
	for k := range entries {
		oses = append(oses, k)
	}
	sort.Strings(oses)
	var b strings.Builder
	b.WriteString(downloadsManifestSigningDomain + "\n")
	for _, osKey := range oses {
		for _, f := range []string{"filename", "sha256", "url"} {
			v, _ := entries[osKey][f].(string)
			if strings.ContainsAny(osKey, "\n\r=.") || strings.ContainsAny(v, "\n\r") {
				return nil, fmt.Errorf("downloads manifest %s.%s is ambiguous (line break or separator)", osKey, f)
			}
			fmt.Fprintf(&b, "%s.%s=%s\n", osKey, f, v)
		}
	}
	return []byte(b.String()), nil
}

var (
	manifestKeyOnce sync.Once
	manifestKey     *rsa.PrivateKey
	manifestKeyErr  error
)

// manifestSigningKey loads AGENT_MANIFEST_SIGNING_KEY (a PEM RSA private key,
// PKCS#1 or PKCS#8: the same key that signs latest.json, so agents and the
// trust script pin one publisher). Unset returns nil, nil: unsigned manifest.
func manifestSigningKey() (*rsa.PrivateKey, error) {
	manifestKeyOnce.Do(func() {
		manifestKey, manifestKeyErr = parseManifestSigningKey(os.Getenv("AGENT_MANIFEST_SIGNING_KEY"))
	})
	return manifestKey, manifestKeyErr
}

func parseManifestSigningKey(raw string) (*rsa.PrivateKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if !strings.HasPrefix(raw, "-----") {
		if data, err := os.ReadFile(raw); err == nil { // a path to the PEM
			raw = string(data)
		}
	}
	blk, _ := pem.Decode([]byte(raw))
	if blk == nil {
		return nil, fmt.Errorf("AGENT_MANIFEST_SIGNING_KEY is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("AGENT_MANIFEST_SIGNING_KEY: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("AGENT_MANIFEST_SIGNING_KEY must be an RSA key")
	}
	return rk, nil
}

func signDownloadsManifest(key *rsa.PrivateKey, entries map[string]map[string]any) (string, error) {
	input, err := downloadsManifestSigningInput(entries)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(input)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}
