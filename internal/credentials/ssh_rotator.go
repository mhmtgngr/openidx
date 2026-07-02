package credentials

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// vaultUser is the subset of *vault.Service the SSH (and postgres) rotator needs:
// it fetches a secret's current value under a bypass-RLS context.
// *vault.Service satisfies this interface via its Use method.
type vaultUser interface {
	Use(ctx context.Context, secretID string) ([]byte, error)
}

// sshConf holds the parsed, validated fields from a connector_config map.
type sshConf struct {
	host          string
	port          int
	username      string
	adminSecretID string
	adminUsername string
	adminAuth     string // "password" or "private_key"
	hostKey       string // authorized_keys-format public key for FixedHostKey
}

// sshConfigFromMap parses and validates an SSH connector_config map.
// Defaults: port=22, admin_auth="password".
// Required: host, username, admin_secret_id, admin_username, host_key.
func sshConfigFromMap(cfg map[string]any) (sshConf, error) {
	str := func(key string) string {
		v, _ := cfg[key].(string)
		return v
	}

	host := str("host")
	username := str("username")
	adminSecretID := str("admin_secret_id")
	adminUsername := str("admin_username")
	hostKey := str("host_key")

	switch {
	case host == "":
		return sshConf{}, fmt.Errorf("ssh connector: missing required field %q", "host")
	case username == "":
		return sshConf{}, fmt.Errorf("ssh connector: missing required field %q", "username")
	case adminSecretID == "":
		return sshConf{}, fmt.Errorf("ssh connector: missing required field %q", "admin_secret_id")
	case adminUsername == "":
		return sshConf{}, fmt.Errorf("ssh connector: missing required field %q", "admin_username")
	case hostKey == "":
		return sshConf{}, fmt.Errorf("ssh connector: missing required field %q", "host_key")
	}

	// port: accept int, float64 (JSON), or string representations.
	port := 22
	if raw, ok := cfg["port"]; ok {
		switch v := raw.(type) {
		case int:
			port = v
		case float64:
			port = int(v)
		case string:
			n, err := strconv.Atoi(v)
			if err != nil {
				return sshConf{}, fmt.Errorf("ssh connector: invalid port %q: %w", v, err)
			}
			port = n
		}
	}

	adminAuth := str("admin_auth")
	if adminAuth == "" {
		adminAuth = "password"
	}

	return sshConf{
		host:          host,
		port:          port,
		username:      username,
		adminSecretID: adminSecretID,
		adminUsername: adminUsername,
		adminAuth:     adminAuth,
		hostKey:       hostKey,
	}, nil
}

// chpasswdStdin returns the stdin payload for chpasswd: "username:newValue".
// The password is delivered over stdin — never placed on the command line
// (which would appear in process listings).
func chpasswdStdin(username string, newValue []byte) string {
	return username + ":" + string(newValue)
}

// chpasswdCommand returns the shell command to invoke: bare "chpasswd" when
// the admin is root, "sudo chpasswd" otherwise.
func chpasswdCommand(isRoot bool) string {
	if isRoot {
		return "chpasswd"
	}
	return "sudo chpasswd"
}

// sshRotator applies POSIX password rotation over SSH using chpasswd.
type sshRotator struct{ vault vaultUser }

// NewSSHRotator returns a Rotator that rotates a POSIX account's password over
// SSH, authenticating with a sudo-capable bootstrap credential resolved from
// the vault. vaultUser is satisfied by *vault.Service.
func NewSSHRotator(v vaultUser) Rotator { return &sshRotator{vault: v} }

func (r *sshRotator) Type() string { return "ssh" }

// Apply resolves the admin credential from the vault, dials the target host as
// the admin, and pipes the new password to chpasswd over stdin.
func (r *sshRotator) Apply(ctx context.Context, cfg map[string]any, newValue []byte) error {
	conf, err := sshConfigFromMap(cfg)
	if err != nil {
		return err
	}
	admin, err := r.vault.Use(orgctx.WithBypassRLS(ctx), conf.adminSecretID)
	if err != nil {
		return fmt.Errorf("ssh: resolve admin secret: %w", err)
	}
	defer zero(admin)

	client, err := r.dial(ctx, conf, admin)
	if err != nil {
		return fmt.Errorf("ssh: dial: %w", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh: new session: %w", err)
	}
	defer sess.Close()

	// Feed the new password to chpasswd via stdin — never on the command line.
	sess.Stdin = bytes.NewReader([]byte(chpasswdStdin(conf.username, newValue)))
	var stderr bytes.Buffer
	sess.Stderr = &stderr

	if err := sess.Run(chpasswdCommand(conf.adminUsername == "root")); err != nil {
		return fmt.Errorf("ssh: chpasswd failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Verify dials the target host authenticating AS the rotated user with the new
// password. A successful connection proves the rotation was applied.
func (r *sshRotator) Verify(ctx context.Context, cfg map[string]any, newValue []byte) error {
	conf, err := sshConfigFromMap(cfg)
	if err != nil {
		return err
	}
	client, err := r.dialAs(ctx, conf, conf.username, ssh.Password(string(newValue)))
	if err != nil {
		return fmt.Errorf("ssh: verify auth failed: %w", err)
	}
	_ = client.Close()
	return nil
}

// fixedHostKey parses an authorized_keys-format public key and returns a
// ssh.FixedHostKey callback. Returns an error if the key cannot be parsed —
// InsecureIgnoreHostKey is never used.
func fixedHostKey(rawKey string) (ssh.HostKeyCallback, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rawKey))
	if err != nil {
		return nil, fmt.Errorf("ssh: parse host_key: %w", err)
	}
	return ssh.FixedHostKey(pub), nil
}

const sshDialTimeout = 15 * time.Second

// dial connects as the admin user, choosing password or private-key auth
// based on conf.adminAuth, then delegates to dialAs.
func (r *sshRotator) dial(ctx context.Context, conf sshConf, admin []byte) (*ssh.Client, error) {
	var authMethod ssh.AuthMethod
	if conf.adminAuth == "private_key" {
		signer, err := ssh.ParsePrivateKey(admin)
		if err != nil {
			return nil, fmt.Errorf("ssh: parse private key: %w", err)
		}
		authMethod = ssh.PublicKeys(signer)
	} else {
		authMethod = ssh.Password(string(admin))
	}
	return r.dialAs(ctx, conf, conf.adminUsername, authMethod)
}

// dialAs opens an SSH connection to conf.host:conf.port as the given user with
// the provided auth method. It enforces conf.hostKey via ssh.FixedHostKey and
// applies a bounded dial timeout.
func (r *sshRotator) dialAs(ctx context.Context, conf sshConf, user string, authMethod ssh.AuthMethod) (*ssh.Client, error) {
	hkCallback, err := fixedHostKey(conf.hostKey)
	if err != nil {
		return nil, err
	}

	clientCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: hkCallback,
		Timeout:         sshDialTimeout,
	}

	addr := net.JoinHostPort(conf.host, strconv.Itoa(conf.port))
	client, err := ssh.Dial("tcp", addr, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh: connect to %s: %w", addr, err)
	}
	return client, nil
}
