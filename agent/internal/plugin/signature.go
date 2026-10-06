package plugin

// Who published a plugin.
//
// WHY THIS EXISTS. The permission checks in trust.go answer "who could have
// replaced this file". They cannot answer "who wrote it": an administrator, an
// installer or a configuration-management run that drops a binary into
// plugin_dir passes them, and the SYSTEM service then runs that binary on every
// check interval. The agent's updates already have an answer to the second
// question, a signature by a pinned publisher, and plugins run with the same
// privilege as an update installs with. So a plugin now has to carry the same
// kind of signature, verified against the same publisher (updater.Trust,
// resolved from update_trusted_cert), before it is registered.
//
// WHAT IS SIGNED is the signing input built below: the manifest's name and
// version, the SHA-256 of manifest.json exactly as read, the executable's file
// name and its SHA-256. The manifest is covered whole, so a timeout or a check
// type cannot be changed under a valid signature. The file name is covered so
// that a signed hello.sh cannot be presented as some other candidate name.
// Anything else in the folder, such as a DLL or a script the executable loads,
// is outside the signature and protected only by the folder's permissions.
//
// The publisher signs these bytes with their own tooling;
// `openidx-agent plugin digest --dir <folder>` prints them. No private key is
// handled by the agent.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// signatureFileName is the file in each plugin folder that carries the
// publisher's signature: base64 RSASSA-PKCS1-v1_5 over the SHA-256 of the
// signing input.
const signatureFileName = "plugin.sig"

// signingDomain separates a plugin signature from everything else the same key
// signs. The update manifest uses "openidx-agent-update-manifest/v1", and the
// key also Authenticode-signs the agent itself, so without this line a
// signature made for one purpose could be offered as another. Changing it
// invalidates every existing plugin signature, so it is versioned.
const signingDomain = "openidx-agent-plugin/v1"

// Verifier checks a publisher's signature over a plugin's signing input.
//
// updater.Trust is the implementation the agent passes. It is an interface here
// only because the updater package imports this one (for CheckTrustedPath), so
// this package cannot import the updater without a cycle.
type Verifier interface {
	VerifySignature(input []byte, sigB64 string) error
}

// Policy is what a plugin has to satisfy, beyond the permission checks, to be
// loaded. NewLoader takes it as a required argument so that every caller states
// it; its zero value verifies nothing and therefore loads nothing.
type Policy struct {
	// Verifier checks plugin.sig. Nil refuses every plugin unless
	// AllowUnsigned is set.
	Verifier Verifier
	// AllowUnsigned turns the signature check off, for a lab. It does not turn
	// off the permission checks, the refusal of reserved check types, or the
	// check before every run that the executable is the one that was loaded.
	AllowUnsigned bool
	// ReservedCheckTypes are check names a plugin may not declare: the agent's
	// built-in checks. A plugin that declares one is refused whole, because
	// registering it would silently replace the built-in check, such as
	// disk_encryption, with whatever the plugin reports.
	ReservedCheckTypes []string
}

// signedContent is what a plugin's signature covers, read once, so that the
// bytes verified are the bytes that are then used.
type signedContent struct {
	manifest    *Manifest
	manifestSum string // lowercase hex SHA-256 of manifest.json as read
	execPath    string
	execSum     string // lowercase hex SHA-256 of the executable
}

// signingInput is the exact byte string a plugin publisher signs.
//
// It is line-oriented, like the update manifest's, so a value containing a
// line break is refused rather than encoded: a newline inside the name would
// let it pose as the line that follows, which is how one signed message comes
// to mean two things.
func (c *signedContent) signingInput() ([]byte, error) {
	fields := [][2]string{
		{"name", c.manifest.Name},
		{"version", c.manifest.Version},
		{"manifest_sha256", c.manifestSum},
		{"executable", filepath.Base(c.execPath)},
		{"executable_sha256", c.execSum},
	}
	var b strings.Builder
	b.WriteString(signingDomain)
	b.WriteByte('\n')
	for _, f := range fields {
		if strings.ContainsAny(f[1], "\n\r") {
			return nil, fmt.Errorf("plugin field %q contains a line break; refusing to sign or verify an ambiguous message", f[0])
		}
		b.WriteString(f[0])
		b.WriteByte('=')
		b.WriteString(f[1])
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// SigningInput returns the bytes a publisher signs to produce plugin.sig for
// the plugin folder dir. It finds the executable the same way Discover does, so
// it must be run on the platform the plugin is for: the executable's file name
// is part of what is signed, and the candidate names differ by platform.
//
// It does not check permissions or signatures; it only reports what a
// signature would have to cover.
func SigningInput(dir string) ([]byte, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", dir, err)
	}
	data, err := os.ReadFile(filepath.Join(abs, manifestFileName))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	manifest, err := parseManifest(data)
	if err != nil {
		return nil, err
	}
	execPath := findExecutable(abs, filepath.Base(abs), manifest.Name)
	if execPath == "" {
		return nil, fmt.Errorf("no executable found in %s for this platform", abs)
	}
	execSum, err := sha256File(execPath)
	if err != nil {
		return nil, err
	}
	c := &signedContent{manifest: manifest, manifestSum: sha256Hex(data), execPath: execPath, execSum: execSum}
	return c.signingInput()
}

// checkSignature reports why the plugin in dir must not be loaded on the
// strength of its signature, or nil when the policy's publisher signed c.
func (l *Loader) checkSignature(dir string, c *signedContent) error {
	if l.policy.AllowUnsigned {
		return nil
	}
	if l.policy.Verifier == nil {
		return errors.New("no trusted publisher is configured to verify plugin signatures")
	}
	sig, err := os.ReadFile(filepath.Join(dir, signatureFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("the plugin carries no %s. A plugin runs with this agent's privileges "+
				"on every check interval, so it must be signed by the publisher this agent trusts for "+
				"updates (see `openidx-agent plugin digest`), or allow_unsigned_plugins must be set in "+
				"agent.json for a lab", signatureFileName)
		}
		return fmt.Errorf("read %s: %w", signatureFileName, err)
	}
	input, err := c.signingInput()
	if err != nil {
		return err
	}
	if err := l.policy.Verifier.VerifySignature(input, string(sig)); err != nil {
		return fmt.Errorf("%s does not verify for this manifest and executable: %w", signatureFileName, err)
	}
	return nil
}

// reservedCheckType returns the first of types the policy reserves, or "".
func (l *Loader) reservedCheckType(types []string) string {
	for _, t := range types {
		for _, r := range l.policy.ReservedCheckTypes {
			if t == r {
				return t
			}
		}
	}
	return ""
}

// sha256File returns the lowercase hex SHA-256 of the file at path, read as a
// stream so that a large executable is not held in memory.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s to hash it: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
