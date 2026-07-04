package credentials

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// safeUsername constrains a POSIX username to a shell-safe charset. sshConfigFromMap
// only checks that username is non-empty, and authorizedKeysScript interpolates the
// username directly into a shell command — so we validate here before building it.
var safeUsername = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func validateUsername(user string) error {
	if !safeUsername.MatchString(user) {
		return fmt.Errorf("ssh_key: unsafe username %q (must match %s)", user, safeUsername.String())
	}
	return nil
}

// sshKeyRotator rotates a POSIX account's SSH key-pair. The stored secret value is a
// freshly-generated ed25519 OpenSSH private key; Apply installs the derived public key
// into the target's authorized_keys and Verify SSHes in as the target with the new key.
type sshKeyRotator struct{ vault vaultUser }

// NewSSHKeyRotator returns a Rotator (and ValueGenerator) that rotates a POSIX account's
// SSH key-pair over SSH, authenticating with a sudo-capable admin credential resolved
// from the vault. vaultUser is satisfied by *vault.Service.
func NewSSHKeyRotator(v vaultUser) Rotator { return &sshKeyRotator{vault: v} }

func (r *sshKeyRotator) Type() string { return "ssh_key" }

// Generate produces a fresh ed25519 OpenSSH private key (PEM). The GenerationPolicy is
// ignored because the key type is fixed.
func (r *sshKeyRotator) Generate(_ GenerationPolicy) ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ssh_key: generate: %w", err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "openidx-rotated")
	if err != nil {
		return nil, fmt.Errorf("ssh_key: marshal: %w", err)
	}
	return pem.EncodeToMemory(blk), nil
}

// authorizedLine derives the public key from the private key PEM and formats the
// authorized_keys line, tagged "openidx-rotated:<user>" so prior rotations can be replaced.
func (r *sshKeyRotator) authorizedLine(privPEM []byte, user string) (string, error) {
	signer, err := ssh.ParsePrivateKey(privPEM)
	if err != nil {
		return "", fmt.Errorf("ssh_key: parse: %w", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return line + " openidx-rotated:" + user, nil
}

// Apply installs the derived public key into the target's authorized_keys, replacing any
// prior openidx-rotated line for the same user, using the sudo-capable admin credential.
func (r *sshKeyRotator) Apply(ctx context.Context, cfg map[string]any, newValue []byte) error {
	conf, err := sshConfigFromMap(cfg)
	if err != nil {
		return err
	}
	if err := validateUsername(conf.username); err != nil {
		return err
	}
	line, err := r.authorizedLine(newValue, conf.username)
	if err != nil {
		return err
	}
	admin, err := r.vault.Use(orgctx.WithBypassRLS(ctx), conf.adminSecretID)
	if err != nil {
		return fmt.Errorf("ssh_key: resolve admin secret: %w", err)
	}
	defer zero(admin)

	client, err := sshDialAdmin(ctx, conf, admin)
	if err != nil {
		return fmt.Errorf("ssh_key: dial: %w", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh_key: session: %w", err)
	}
	defer sess.Close()

	sess.Stdin = strings.NewReader(line + "\n")
	prefix := ""
	if conf.adminUsername != "root" {
		prefix = "sudo "
	}
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	if err := sess.Run(prefix + "sh -c '" + authorizedKeysScript(conf.username) + "'"); err != nil {
		return fmt.Errorf("ssh_key: install failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Verify dials the target host authenticating AS the rotated user with the new private
// key. A successful connection proves the public key was installed.
func (r *sshKeyRotator) Verify(ctx context.Context, cfg map[string]any, newValue []byte) error {
	conf, err := sshConfigFromMap(cfg)
	if err != nil {
		return err
	}
	signer, err := ssh.ParsePrivateKey(newValue)
	if err != nil {
		return fmt.Errorf("ssh_key: verify parse: %w", err)
	}
	client, err := sshDialAs(ctx, conf, conf.username, ssh.PublicKeys(signer))
	if err != nil {
		return fmt.Errorf("ssh_key: verify auth failed: %w", err)
	}
	_ = client.Close()
	return nil
}

// authorizedKeysScript returns a POSIX sh script (run via `sh -c '<script>'`) that installs
// the authorized_keys line piped on stdin, replacing any prior "openidx-rotated:<user>"
// line, atomically. The caller MUST have validated user via validateUsername first.
func authorizedKeysScript(user string) string {
	// chown the .ssh dir (not just the file) to the target user: it may be created here
	// by the admin (root), and sshd StrictModes rejects a ~/.ssh not owned by the user.
	return `set -e; u=` + user + `; h=$(getent passwd "$u" | cut -d: -f6); ` +
		`test -n "$h"; mkdir -p "$h/.ssh"; chmod 700 "$h/.ssh"; chown "$u" "$h/.ssh"; ak="$h/.ssh/authorized_keys"; ` +
		`touch "$ak"; new=$(cat); tmp="$ak.oidx.$$"; ` +
		`grep -v "openidx-rotated:$u" "$ak" > "$tmp" || true; printf '%s\n' "$new" >> "$tmp"; ` +
		`chmod 600 "$tmp"; chown "$u" "$tmp"; mv "$tmp" "$ak"`
}

// ValidateConfig satisfies ConfigValidator: the config is valid if it parses.
func (r *sshKeyRotator) ValidateConfig(cfg map[string]any) error {
	_, err := sshConfigFromMap(cfg)
	return err
}
