# CodeQL critical + high remediation

**Goal:** Resolve the 6 serious open CodeQL alerts on `main` (3 critical `go/request-forgery`, 2 high
`go/incorrect-integer-conversion`, 1 high `go/sql-injection`) — each with a real code fix where there's
genuine risk, or a **documented false-positive dismissal** where the pattern is safe by construction.
(The ~94 medium `go/log-injection` alerts are a separate, lower-priority sweep — out of scope here.)

**Verified current state (2026-07-07):**
- CodeQL is **not** a required check, but these are real security-review signal. `main` carries 3
  critical + 3 high + ~94 medium open CodeQL alerts.

## Per-alert analysis + decision

### A. `internal/common/database/database.go:45,48` — `go/incorrect-integer-conversion` (high ×2) → REAL FIX
`envInt32` does `n, err := strconv.Atoi(s)` then `int32(n)`. `Atoi` returns `int` (64-bit); `int32(n)`
silently truncates/wraps a value > 2^31−1 (e.g. `DB_MAX_CONNS=3000000000` → a negative pool size). This
is a genuine (if minor) overflow bug. **Fix:** use `strconv.ParseInt(s, 10, 32)`, which bounds to int32
and returns an error on overflow; keep the default-on-error + `< min` behavior:
```go
func envInt32(name string, def, min int32) int32 {
	s := os.Getenv(name)
	if s == "" {
		return def
	}
	n, err := strconv.ParseInt(s, 10, 32) // bitSize 32 → errors on overflow, no silent truncation
	if err != nil || int32(n) < min {
		return def
	}
	return int32(n)
}
```
Clears both alerts (the flagged `int32(n)` conversions are now provably in-range) and fixes the bug.
**Test:** a `TestEnvInt32` covering default/valid/below-min/**overflow** (`"3000000000"` → default).

### B. `internal/access/ziti.go` — `go/request-forgery` (critical ×3) → REAL FIX (validate base + escape segment)
All three are Ziti **management-API** calls whose URL derives from `zm.cfg.ZitiCtrlURL` (trusted
operator config) and, for one, `zitiIdentityID` parsed from a **prior API response** (a remote-flow
source — the genuinely tainted input). Fixes:
1. **Escape the response-derived path segment** (line ~586, the real vector):
   `url.PathEscape(zitiIdentityID)` before interpolating it into the identities path.
2. **Validate the controller base once, reuse it** — add a small helper so every mgmt request is built
   from a parsed, scheme/host-checked base (a sanitizer barrier for the config-derived URL):
   ```go
   // mgmtURL joins a path onto the validated Ziti controller base URL. It parses ZitiCtrlURL and
   // requires an http/https scheme with a host, so a malformed/hostile controller URL can't redirect
   // management calls elsewhere. Callers must url.PathEscape any dynamic path segment.
   func (zm *ZitiManager) mgmtURL(pathAndQuery string) (string, error) {
   	base, err := url.Parse(zm.cfg.ZitiCtrlURL)
   	if err != nil || (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" {
   		return "", fmt.Errorf("ziti: invalid controller URL")
   	}
   	return base.Scheme + "://" + base.Host + pathAndQuery, nil
   }
   ```
   Rebuild the 3 request URLs via `mgmtURL(...)`: sessions (`/edge/management/v1/sessions?filter=…&limit=1`),
   identities (`/edge/management/v1/identities/` + `url.PathEscape(zitiIdentityID)`), authenticate
   (`/edge/management/v1/authenticate?method=password`). Handle the returned error (log + return "" / wrap).
**Rationale:** the base rebuilt from a validated `Scheme+Host` (no path/userinfo passthrough) + escaped
segment removes the taint flow CodeQL tracks. If CodeQL still flags the config-derived base after this
(ZitiCtrlURL is trusted operator config, not attacker input), the residual is a documented FP →
dismiss via the code-scanning API with that justification (decided per the PR's CodeQL result).
No live smoke needed (control-plane URL construction; box Ziti health already covered by deploy smokes),
but `go build`/`vet`/existing ziti tests must stay green.

### C. `internal/credentials/mysql_rotator.go:202` — `go/sql-injection` (high) → DOCUMENTED FP DISMISSAL
`ALTER USER '%s'@'%s' IDENTIFIED BY %s` is built with `fmt.Sprintf` because **MySQL DDL cannot bind
identifiers or the password**. It is already mitigated (and was security-reviewed + injection-smoke-tested
in v1.14.0): `targetUser`/`targetHost` are validated against `mysqlIdentRE` (safe charset); the password
is escaped via `mysqlQuoteLiteral` on a pinned connection with `sql_mode` `NO_BACKSLASH_ESCAPES` stripped
and a utf8mb4 charset (defeats the GBK backslash-swallow attack). There is no parameterized form CodeQL
would accept for DDL. **Decision:** dismiss as a false positive via the code-scanning API with a
justification referencing the validation + escaping + the v1.14.0 injection smoke. Add a one-line code
comment at the DDL noting "CodeQL go/sql-injection: FP — DDL can't bind; identifiers charset-validated,
password escaped (mysqlQuoteLiteral + sql_mode guard)". No behavior change.

## Approach / sequencing
- **PR (code fixes):** A (database.go + test) + B (ziti.go helper + PathEscape) in one PR. Verify CI
  CodeQL result: the int-conversion alerts should clear; the ziti request-forgery should clear or reduce.
- **Dismissals (after the PR's CodeQL runs):** for the mysql sql-injection (definite FP) and any residual
  ziti request-forgery on the trusted-config base, dismiss via
  `gh api repos/mhmtgngr/openidx/code-scanning/alerts/<n> -X PATCH -f state=dismissed -f dismissed_reason="false positive" -f dismissed_comment="<justification>"`. **Dismissing critical alerts is surfaced on the security dashboard — do it only for genuinely-safe patterns, with a clear justification, and only after the code fixes land.**

## Testing / verification
- `go build ./... && go vet ./internal/... && gofmt -l && go run ./tools/orgscope -fail ./internal/access && go test ./internal/common/database/ ./internal/access/ ./internal/credentials/`.
- `golangci-lint run` clean (Lint is a Required Check).
- New `TestEnvInt32` (incl. overflow). Existing ziti tests stay green.
- On the PR: confirm via the code-scanning API that the merge-ref shows the int-conversion + (ideally)
  request-forgery alerts cleared; document any that remain as dismissed-FP.

## Scope / risk
- Backend-only, low behavior risk: database.go pool-sizing parse (bugfix), ziti.go control-plane URL
  construction (hardening — same endpoints, validated), mysql comment + dismissal (no code change).
- No migration, no runtime behavior change beyond stricter env parsing + controller-URL validation.
- Out of scope: the ~94 medium log-injection sweep; other pre-existing alerts beyond the 6 critical/high.
