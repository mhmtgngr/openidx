# Rotation connectors (MySQL + SSH key-pair) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (or
> executing-plans). Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add `mysql` and `ssh_key` `Rotator` connectors to the PAM rotation engine.
**Spec:** `docs/superpowers/specs/2026-07-04-rotation-connectors-mysql-sshkey-design.md`
**Module:** `github.com/openidx/openidx`. **Branch per PR from `main`.** cloud-IAM deferred.

Key facts (verified): `Rotator` = `Type()/Apply(ctx,cfg,newValue)/Verify(ctx,cfg,newValue)`;
`vaultUser.Use(ctx,secretID)` resolves admin creds (call under `orgctx.WithBypassRLS`);
`runRotation` (engine.go:84) does `newValue=generateSecret(gp)`; rotators registered in
`cmd/admin-api/main.go:296`; `cmd/admin-api/main_test.go` has NO rotator assertions;
`golang.org/x/crypto/ssh` has `MarshalPrivateKey`/`ParsePrivateKey`/`MarshalAuthorizedKey`/`NewPublicKey`;
SSH `dial`/`dialAs` (ssh_rotator.go) use only `conf`+`admin` (no receiver state) → extractable.

---

# PR 1 — engine ValueGenerator seam + ssh_key connector  (branch `feat/rotation-ssh-key`)

## Task 1 — `ValueGenerator` seam
**Files:** `internal/credentials/rotator.go`, `internal/credentials/engine.go`, `internal/credentials/engine_test.go`

- [ ] **Step 1:** In `rotator.go`, add after the `Rotator` interface:
```go
// ValueGenerator lets a connector produce the secret value itself (e.g. an SSH private key)
// instead of the engine's default random-password generateSecret. Optional: connectors that
// don't implement it keep using generateSecret.
type ValueGenerator interface {
	Generate(gp GenerationPolicy) ([]byte, error)
}
```
- [ ] **Step 2:** In `engine.go` `runRotation`, replace:
```go
	newValue, err := generateSecret(gp)
	if err != nil {
		return "failed", false, 0
	}
```
with:
```go
	var newValue []byte
	var err error
	if g, ok := r.(ValueGenerator); ok {
		newValue, err = g.Generate(gp)
	} else {
		newValue, err = generateSecret(gp)
	}
	if err != nil {
		return "failed", false, 0
	}
```
- [ ] **Step 3:** Test `TestRunRotation_ValueGenerator` in `engine_test.go` (mirror existing runRotation
  tests — find one for the fake Rotator/candidateVault): a fake Rotator implementing `ValueGenerator`
  returns a sentinel value; assert `AddCandidateVersion`/`Apply`/`Verify` all receive that sentinel
  (not a generated password). Also assert a non-ValueGenerator Rotator still gets a `generateSecret`
  value (non-empty, length gp).
- [ ] **Step 4:** `go test ./internal/credentials/ -run RunRotation -v` PASS; `go build ./...`.
- [ ] **Step 5:** Commit `feat(credentials): optional ValueGenerator seam for connector-produced values`.

## Task 2 — extract SSH dial helpers to shared funcs
**Files:** `internal/credentials/ssh_rotator.go`

- [ ] **Step 1:** Convert the `(*sshRotator) dial` and `(*sshRotator) dialAs` methods into package
  functions `sshDialAdmin(ctx context.Context, conf sshConf, admin []byte) (*ssh.Client, error)` and
  `sshDialAs(ctx context.Context, conf sshConf, user string, authMethod ssh.AuthMethod) (*ssh.Client, error)`
  (bodies unchanged — they use only `conf`/`admin`). Update the two call sites in `sshRotator.Apply`/`Verify`
  to call the package funcs. `fixedHostKey` is already a package func.
- [ ] **Step 2:** `go build ./... && go test ./internal/credentials/ -run SSH` — existing ssh tests still pass.
- [ ] **Step 3:** Commit `refactor(credentials): extract sshDialAdmin/sshDialAs as shared package funcs`.

## Task 3 — `ssh_key_rotator.go`
**Files:** `internal/credentials/ssh_key_rotator.go`, `internal/credentials/ssh_key_rotator_test.go`

- [ ] **Step 1:** Implement the connector (reuse `sshConfigFromMap`, `sshDialAdmin`, `sshDialAs`, `fixedHostKey`):
```go
type sshKeyRotator struct{ vault vaultUser }

// NewSSHKeyRotator rotates a POSIX account's SSH key-pair: the stored secret value IS an
// ed25519 OpenSSH private key; Apply installs the derived public key into the target's
// authorized_keys (a single line tagged "openidx-rotated:<user>", replaced each rotation).
func NewSSHKeyRotator(v vaultUser) Rotator { return &sshKeyRotator{vault: v} }

func (r *sshKeyRotator) Type() string { return "ssh_key" }

// Generate produces the value: a fresh ed25519 OpenSSH private key (PEM). gp is ignored
// (key type is fixed ed25519).
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

func (r *sshKeyRotator) authorizedLine(privPEM []byte, user string) (string, error) {
	signer, err := ssh.ParsePrivateKey(privPEM)
	if err != nil {
		return "", fmt.Errorf("ssh_key: parse: %w", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return line + " openidx-rotated:" + user, nil
}

func (r *sshKeyRotator) Apply(ctx context.Context, cfg map[string]any, newValue []byte) error {
	conf, err := sshConfigFromMap(cfg)
	if err != nil {
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
	// Feed the public-key line via stdin; the script rewrites the target's authorized_keys
	// replacing the single tagged line (idempotent, other keys preserved). Runs sudo when the
	// admin isn't root. The public key is not secret; the private key never leaves the engine.
	sess.Stdin = strings.NewReader(line + "\n")
	prefix := ""
	if conf.adminUsername != "root" {
		prefix = "sudo "
	}
	script := prefix + `sh -c '` + authorizedKeysScript(conf.username) + `'`
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	if err := sess.Run(script); err != nil {
		return fmt.Errorf("ssh_key: install failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

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
```
- [ ] **Step 2:** Add `authorizedKeysScript(user string) string` — reads the target's home via `getent`,
  ensures `~/.ssh` (0700) + `authorized_keys` (0600) owned by the user, strips the tagged line, appends
  the new one from stdin, atomically `mv`s. Draft (validate/iterate against the smoke in Task 4):
```go
// authorizedKeysScript returns a POSIX sh script (run via `sh -c '<script>'`) that installs the
// authorized_keys line piped on stdin, replacing any prior "openidx-rotated:<user>" line. user is
// validated by sshConfigFromMap upstream; still keep it shell-safe (alnum/._-).
func authorizedKeysScript(user string) string {
	return `set -e; u=` + user + `; h=$(getent passwd "$u" | cut -d: -f6); ` +
		`test -n "$h"; mkdir -p "$h/.ssh"; chmod 700 "$h/.ssh"; ak="$h/.ssh/authorized_keys"; ` +
		`touch "$ak"; new=$(cat); tmp="$ak.oidx.$$"; ` +
		`grep -v "openidx-rotated:$u" "$ak" > "$tmp" || true; printf '%s\n' "$new" >> "$tmp"; ` +
		`chmod 600 "$tmp"; chown "$u" "$tmp"; mv "$tmp" "$ak"`
}
```
  **Validate `user` is shell-safe before interpolating** — add a guard in `sshConfigFromMap` (or here)
  rejecting `username` outside `[A-Za-z0-9._-]`. Report if `sshConfigFromMap` already constrains it.
- [ ] **Step 3:** Imports: `bytes`, `crypto/ed25519`, `crypto/rand`, `encoding/pem`, `fmt`, `strings`,
  `golang.org/x/crypto/ssh`, `.../orgctx`. `go build ./...`.
- [ ] **Step 4:** Unit tests `ssh_key_rotator_test.go`: `Generate` output parses via `ssh.ParsePrivateKey`
  and is ed25519; `authorizedLine` produces a valid `ssh-ed25519 … openidx-rotated:<user>` line that
  `ssh.ParseAuthorizedKey` accepts; `authorizedKeysScript` contains the tag + no unescaped user; cfg
  validation rejects a bad username. `go test ./internal/credentials/ -run SSHKey -v` PASS.
- [ ] **Step 5:** Commit `feat(credentials): ssh_key rotator (ed25519 key-pair rotation)`.

## Task 4 — register + live sshd smoke
- [ ] **Step 1:** `cmd/admin-api/main.go:296` rotators slice: add `credentials.NewSSHKeyRotator(vaultSvc)`.
  `go build ./...`.
- [ ] **Step 2: Live smoke (throwaway sshd; docker/podman + dangerouslyDisableSandbox).** Because
  `docker compose`/full engine wiring is heavy, smoke the connector directly with a tiny throwaway that
  constructs `NewSSHKeyRotator` with a fake `vaultUser` returning the admin key, runs `Generate`→`Apply`
  →`Verify` against a container running sshd:
  - Start e.g. `docker run -d -p 2222:2222 ... lscr.io/linuxserver/openssh-server` (or build a minimal
    `ubuntu` + openssh-server + a target user + a root/sudo admin with a known key). Capture the host key
    (`ssh-keyscan -p 2222 localhost`) for `host_key`.
  - Throwaway `cmd/ssh-key-smoke`: fake vault returns the admin private key; cfg points at the container;
    `Generate` → `Apply` → `Verify` must succeed; run Apply twice and assert `authorized_keys` has exactly
    one `openidx-rotated:<user>` line (exec into the container to check). Print SMOKE: PASS.
  - Tear down container + remove throwaway. Report the result. If a working sshd image can't be obtained
    here, fall back to asserting `Generate`/`authorizedLine`/script correctness (unit-level) and clearly
    say the remote Apply/Verify wasn't exercised live.
- [ ] **Step 3:** Commit `feat(credentials): register ssh_key rotator in admin-api`.

## Task 5 — PR 1
- [ ] Push `feat/rotation-ssh-key`; `gh pr create` (engine seam + ssh_key + registration; note the smoke
  result); adversarial review; CI green; **stop for per-PR merge go-ahead**.

---

# PR 2 — mysql connector  (branch `feat/rotation-mysql`, from `main` after PR 1)

## Task 6 — `mysql_rotator.go` (mirror postgres_rotator.go)
**Files:** `internal/credentials/mysql_rotator.go`, `internal/credentials/mysql_rotator_test.go`, `go.mod`/`go.sum`

- [ ] **Step 1:** `mysqlConfigFromMap(cfg)` mirroring `pgConfigFromMap`: required `host`,
  `admin_secret_id`, `admin_username`, `target_user`; optional `port`(3306), `target_host`(`%`),
  `dbname`, `tls`(bool). **Validate `target_user` and `target_host` against `^[A-Za-z0-9_.%-]+$`** and
  reject otherwise (identifiers are interpolated into DDL — no binding possible).
- [ ] **Step 2:** Password escaper + DDL:
```go
// mysqlQuoteLiteral escapes s for a MySQL single-quoted string literal (valid when
// NO_BACKSLASH_ESCAPES is OFF, which Apply enforces). Rejects NUL.
func mysqlQuoteLiteral(s string) (string, error) {
	if strings.ContainsRune(s, 0) {
		return "", fmt.Errorf("mysql: password contains NUL")
	}
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(s) + "'", nil
}
```
  `Apply`: resolve admin (`vault.Use` under bypass, `defer zero`), open `sql.Open("mysql", dsn)` as admin
  (DSN via `github.com/go-sql-driver/mysql`'s `mysql.Config`; never logged), `PingContext`, then in one
  session: `SET SESSION sql_mode=REPLACE(@@SESSION.sql_mode,'NO_BACKSLASH_ESCAPES','')` (so `\`-escaping
  holds), then `ALTER USER '<target_user>'@'<target_host>' IDENTIFIED BY <quoted>` where `<quoted>` comes
  from `mysqlQuoteLiteral(string(newValue))` and the identifiers are the validated fields. 15s ctx.
- [ ] **Step 3:** `Verify`: open a second `sql.Open("mysql", …)` as `target_user`@host with `newValue`,
  `PingContext` (10s). Success ⇒ rotation applied.
- [ ] **Step 4:** `NewMySQLRotator(v vaultUser) Rotator`; `Type() == "mysql"`. `go get github.com/go-sql-driver/mysql`
  + `go mod tidy`. `go build ./...`.
- [ ] **Step 5:** Unit tests `mysql_rotator_test.go`: `mysqlQuoteLiteral` (`'`→`\'`, `\`→`\\`, combined,
  NUL-reject); identifier validation rejects `` `; DROP `` / spaces / quotes; `mysqlConfigFromMap`
  required-field + port parsing. `go test ./internal/credentials/ -run MySQL -v` PASS.
- [ ] **Step 6:** Commit `feat(credentials): mysql rotator (ALTER USER password rotation)`.

## Task 7 — register + live mysql smoke + PR
- [ ] **Step 1:** `cmd/admin-api/main.go` rotators slice: add `credentials.NewMySQLRotator(vaultSvc)`. `go build ./...`.
- [ ] **Step 2: Live smoke (throwaway `mysql:8`; dangerouslyDisableSandbox).** `docker run -d -e
  MYSQL_ROOT_PASSWORD=… -p 13306:3306 mysql:8`; wait ready; create a target user
  (`CREATE USER 'tgt'@'%' IDENTIFIED BY 'old'; GRANT USAGE …`). Throwaway `cmd/mysql-rot-smoke`: fake
  vault returns root creds; `Apply` a new password; then assert a `mysql` connection as `tgt` with the
  NEW password succeeds and the OLD one fails; also run a password containing `'` and `\` to exercise the
  escaper end-to-end. Print SMOKE: PASS. Tear down + remove throwaway. Report the escaper result explicitly.
- [ ] **Step 3:** `go build ./...`, `go vet`, `gofmt`; push `feat/rotation-mysql`; `gh pr create`
  (mysql connector + dep; call out the escaping/`sql_mode` handling for review); adversarial review
  (the escaper + identifier validation get the hard look); CI green; **stop for per-PR merge go-ahead**.

---

## Self-review notes
- Spec coverage: ValueGenerator seam (T1), ssh_key (T2-T4), mysql (T6-T7), registration (T4/T7),
  live smokes (T4/T7). cloud-IAM out of scope.
- Security review items: MySQL password escaping + `sql_mode` guard + identifier validation (T6);
  ssh_key username shell-safety + authorized_keys atomic single-line rewrite + FixedHostKey reuse (T3).
- `cmd/admin-api/main_test.go` has no rotator assertions → registration adds no fixture churn (confirm build).
- New dep only in PR2 (`go-sql-driver/mysql`); PR1 uses `x/crypto` (already present).
- Open questions (resolve at impl): `sql_mode` set-vs-fail; authorized_keys atomicity; missing `~/.ssh`
  (the script `mkdir -p`s it).
