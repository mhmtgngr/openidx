# PAM M5 — Rotation Connectors (SSH + PostgreSQL) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use `- [ ]`.

**Goal:** Add SSH and PostgreSQL `Rotator` connectors so the M1b rotation engine can rotate credentials on Linux hosts and PostgreSQL, each resolving its bootstrap/admin credential from the vault.

**Tech Stack:** Go 1.25, `golang.org/x/crypto/ssh` (present), `pgx v5` (present). No new deps, no migration. Branch `pam/rotation-connectors` (off main). **Spec:** `docs/superpowers/specs/2026-07-02-pam-m5-rotation-connectors-design.md`

**Reused interface** (`internal/credentials/rotator.go`): `Rotator{ Type() string; Apply(ctx, cfg map[string]any, newValue []byte) error; Verify(ctx, cfg, newValue []byte) error }`, `ErrVerifyUnsupported`. `vault.Service.Use(bypassCtx, secretID) ([]byte, error)` (requires `orgctx.WithBypassRLS`). Registration: `cmd/admin-api/main.go` `rotators := []credentials.Rotator{...}` (~line 274) with `vaultSvc` in scope.

**Execution order:** T1 → T2 → T3.

---

## Task 1: SSH connector

**Files:** Create `internal/credentials/ssh_rotator.go`, `internal/credentials/ssh_rotator_test.go`.

- [ ] **Step 1: Pure helpers first (TDD).** Write `ssh_rotator_test.go` for the pure pieces, then implement so they pass:
  - `sshConfigFromMap(cfg map[string]any) (sshConf, error)` — parse/validate `{host, port, username, admin_secret_id, admin_username, admin_auth, host_key}`; defaults port=22, admin_auth="password"; **error** if host/username/admin_secret_id/admin_username/host_key missing (host_key required — no blind-accept).
  - `chpasswdStdin(username string, newValue []byte) string` → `"<username>:<newValue>"` (used as the stdin fed to `chpasswd`; the value is NEVER placed on the command line). Test: contains the username + value + a single colon; empty username → still `":val"` but config validation prevents empty.
  - `chpasswdCommand(isRoot bool) string` → `"chpasswd"` when root else `"sudo chpasswd"`.
  Tests: valid map → conf; missing each required field → error; stdin builder shape.

- [ ] **Step 2: Implement `ssh_rotator.go`:**
```go
package credentials

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openidx/openidx/internal/common/orgctx"
)

type sshRotator struct{ vault vaultUser } // vaultUser = interface{ Use(ctx, id) ([]byte,error) }

// NewSSHRotator returns a Rotator that rotates a POSIX account's password over SSH,
// authenticating with a sudo-capable bootstrap credential resolved from the vault.
func NewSSHRotator(v vaultUser) Rotator { return &sshRotator{vault: v} }

func (r *sshRotator) Type() string { return "ssh" }

func (r *sshRotator) Apply(ctx context.Context, cfg map[string]any, newValue []byte) error {
	conf, err := sshConfigFromMap(cfg)
	if err != nil { return err }
	admin, err := r.vault.Use(orgctx.WithBypassRLS(ctx), conf.adminSecretID)
	if err != nil { return fmt.Errorf("ssh: resolve admin secret: %w", err) }
	defer zero(admin)
	client, err := r.dial(ctx, conf, admin)
	if err != nil { return fmt.Errorf("ssh: dial: %w", err) }
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil { return err }
	defer sess.Close()
	sess.Stdin = bytes.NewReader([]byte(chpasswdStdin(conf.username, newValue)))
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	if err := sess.Run(chpasswdCommand(conf.adminUsername == "root")); err != nil {
		return fmt.Errorf("ssh: chpasswd failed: %w (%s)", err, stderr.String())
	}
	return nil
}

func (r *sshRotator) Verify(ctx context.Context, cfg map[string]any, newValue []byte) error {
	conf, err := sshConfigFromMap(cfg)
	if err != nil { return err }
	// Authenticate AS the rotated user with the new password → proves the rotation worked.
	client, err := r.dialAs(ctx, conf, conf.username, ssh.Password(string(newValue)))
	if err != nil { return fmt.Errorf("ssh: verify auth failed: %w", err) }
	_ = client.Close()
	return nil
}

// dial connects as the admin/bootstrap account (password or private-key from `admin`).
// dialAs is the shared dialer given a username + auth method. Both use a bounded timeout,
// conf.hostKey via ssh.FixedHostKey (parse the configured host key), and reject on mismatch.
```
Implement `dial`/`dialAs` with `ssh.Dial("tcp", host:port, &ssh.ClientConfig{User, Auth, HostKeyCallback: fixedFromConfig(conf.hostKey), Timeout})`. For admin_auth="private_key", parse `admin` as a PEM key via `ssh.ParsePrivateKey`; else `ssh.Password(string(admin))`. Parse `host_key` with `ssh.ParseAuthorizedKey` → `ssh.FixedHostKey`. Define the local `vaultUser` interface (`Use(context.Context, string) ([]byte, error)`) so the test can inject a fake and so it matches `*vault.Service`.

- [ ] **Step 3:** `go test ./internal/credentials/ -run 'TestSSH' -v` (pure tests pass); `go build ./...`; `go vet`; `gofmt -l`.
- [ ] **Step 4:** Commit `feat(credentials): SSH rotation connector (chpasswd over ssh, vault-bootstrapped)`.

---

## Task 2: PostgreSQL connector

**Files:** Create `internal/credentials/postgres_rotator.go`, `internal/credentials/postgres_rotator_test.go`.

- [ ] **Step 1: TDD the pure pieces.** `postgres_rotator_test.go`:
  - `pgConfigFromMap(cfg) (pgConf, error)` — `{host, port(=5432), dbname, sslmode(=require), admin_secret_id, admin_username, target_role}`; error on missing host/dbname/admin_secret_id/admin_username/target_role.
  - `buildAdminDSN(conf, adminPassword) string` — a pgx-parseable conninfo/URL with the admin creds + sslmode; assert it contains host/port/dbname/user/sslmode and the password is present (this DSN is used internally, never logged).
  Tests: valid map → conf; missing required → error; DSN shape.

- [ ] **Step 2: Implement `postgres_rotator.go`:**
```go
package credentials

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/openidx/openidx/internal/common/orgctx"
)

type postgresRotator struct{ vault vaultUser }

func NewPostgresRotator(v vaultUser) Rotator { return &postgresRotator{vault: v} }

func (r *postgresRotator) Type() string { return "postgres" }

func (r *postgresRotator) Apply(ctx context.Context, cfg map[string]any, newValue []byte) error {
	conf, err := pgConfigFromMap(cfg)
	if err != nil { return err }
	admin, err := r.vault.Use(orgctx.WithBypassRLS(ctx), conf.adminSecretID)
	if err != nil { return fmt.Errorf("postgres: resolve admin secret: %w", err) }
	defer zero(admin)
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := pgx.Connect(cctx, buildAdminDSN(conf, string(admin)))
	if err != nil { return fmt.Errorf("postgres: admin connect: %w", err) }
	defer conn.Close(context.Background())
	// Safely quote identifier (%I) + literal (%L) server-side, then run the DDL.
	var ddl string
	if err := conn.QueryRow(cctx,
		`SELECT format('ALTER ROLE %I WITH PASSWORD %L', $1::text, $2::text)`,
		conf.targetRole, string(newValue)).Scan(&ddl); err != nil {
		return fmt.Errorf("postgres: build ddl: %w", err)
	}
	if _, err := conn.Exec(cctx, ddl); err != nil {
		return fmt.Errorf("postgres: alter role: %w", err)
	}
	return nil
}

func (r *postgresRotator) Verify(ctx context.Context, cfg map[string]any, newValue []byte) error {
	conf, err := pgConfigFromMap(cfg)
	if err != nil { return err }
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(cctx, buildTargetDSN(conf, string(newValue)))
	if err != nil { return fmt.Errorf("postgres: verify connect failed: %w", err) }
	defer conn.Close(context.Background())
	return conn.Ping(cctx)
}
```
Add `buildTargetDSN(conf, targetPassword)` (same host/port/db/sslmode, user=target_role). Reuse the `vaultUser` interface + `zero` from Task 1 (don't redeclare). The `format('ALTER ROLE %I WITH PASSWORD %L', ...)` pattern is the safe-quoting requirement — the new password is passed as a bound `$2` to `format`, never string-concatenated.

- [ ] **Step 3:** `go test ./internal/credentials/ -run 'TestPostgres' -v`; `go build ./...`; `go vet`; `gofmt -l`; `go run ./tools/orgscope -fail ./internal/credentials`.
- [ ] **Step 4:** Commit `feat(credentials): PostgreSQL rotation connector (ALTER ROLE, vault-bootstrapped)`.

---

## Task 3: Register connectors

**Files:** `cmd/admin-api/main.go`.

- [ ] **Step 1:** Extend the `rotators` slice (~line 274) where `vaultSvc` is in scope:
```go
rotators := []credentials.Rotator{
	credentials.NewDirectoryRotator(dirService),
	credentials.NewGenerateOnlyRotator(),
	credentials.NewSSHRotator(vaultSvc),
	credentials.NewPostgresRotator(vaultSvc),
}
```
Confirm `vaultSvc` (the `*vault.Service`) satisfies the `vaultUser` interface (it has `Use(context.Context, string) ([]byte, error)`) — it does. Confirm `dirService` var name matches (read the file). Only admin-api runs the scheduler; no other main needs these.
- [ ] **Step 2:** `go build ./... && go build ./cmd/admin-api/ && go vet ./... && gofmt -l && go run ./tools/orgscope -fail ./internal`.
- [ ] **Step 3:** Commit `feat(credentials): register SSH + PostgreSQL rotators in admin-api`.

---

## Final verification
```bash
go build ./... && go vet ./... && gofmt -l internal/credentials cmd/admin-api/main.go
go run ./tools/orgscope -fail ./internal
golangci-lint run && govulncheck ./...
go test ./internal/credentials/...
```

## Self-review notes
- **No secret leak:** admin + new credentials are `[]byte`, `defer zero`'d; the SSH password is fed via **stdin** (never argv → not in `ps`); the Postgres password is quoted server-side via `format('… %L', $2)` (never concatenated) and the DSN is never logged; connector errors wrap the driver error, not the secret.
- **Host security:** SSH requires a configured `host_key` (FixedHostKey; no `InsecureIgnoreHostKey`); Postgres honors `sslmode`.
- **Fail-closed:** any Apply error → the engine leaves `current_version` unchanged; `Verify` authenticating with the new credential is the strong success signal.
- **No new deps, no migration** (x/crypto/ssh + pgx present; connector_config JSONB from v57).
- **Verifiability:** pure builders (config parse, chpasswd stdin, ALTER ROLE via format, DSN) are unit-tested; live apply/verify against a real host/DB is a box/manual check (fail-closed makes a misconfig safe).
