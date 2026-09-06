# §5.1 — release-gate controls

Nine controls run at every release. **Six of them CI runs on every push**, so
their evidence is the run link; three need a human on a real deployment,
because what they check cannot be checked from a repository.

The job names below are the check names as they appear on a pull request.

## Automated — evidence is the CI run

| Control | Runs as | Fails how |
|---|---|---|
| `make build` + full test suite, including integration | `Build (Go 1.26)`, `Unit Tests (…)` (25 packages), `Race Detector`, `The stack answers end to end` | any red job blocks `Required Checks` |
| `tools/orgscope` clean (the tenant boundary) | `Org-scope lint` | a table the migrations declare but no query scopes, or a query with no org predicate |
| Security scans gating, zero unwaivered criticals | `Analyze Go` + `Analyze JavaScript/TypeScript` (CodeQL), `Go Dependency Scan` + `Vulnerability Check` (govulncheck), `Trivy`, `Secret Scanning (Gitleaks)`, `SAST Scan (Semgrep)` | CRITICAL/HIGH with no reasoned allowlist entry |
| `ValidateProduction()` still bites | `Unit Tests (internal/common)` — `TestValidateProduction`, `TestValidateProductionRejectsDevBypassAndMockSMS`, `TestProductionWarnings`, `TestValidateDarkModeBind` | a deliberately-insecure config that starts anyway |
| Migration up **and** down on a real Postgres | `Unit Tests (internal/migrations)` — `migration_test.go` applies every migration and rolls back; `v138_test.go` applies, rolls back and re-applies the tenant-isolation migration | a migration that cannot be undone |
| Version/changelog currency | `GitHub config is runnable` — `check-version-sync.sh` holds the console, the chart's `appVersion`, the Flutter client and all ten OpenAPI specs to `VERSION` | any artifact disagreeing with `VERSION` |

Two more automated checks are not in §5.1 but are worth the same treatment,
because they were added precisely to stop a class of release-time surprise:
`Docs build clean under --strict`, and `No prose running as shell` (which now
also runs `check-docs-drift.sh` — no document may cite a path that is not
there).

## Operator-run — evidence is a dated row below

These three cannot be run by CI: two need a live overlay with real identities,
one needs real backup media.

### `make dr-game-day` — restore actually restores

```sh
make dr-game-day                    # scripts/dr-game-day.sh --self-test

# Or, at minimum, verify the newest backup is restorable:
go run ./cmd/backup list
go run ./cmd/backup verify <filename>
```

A false-green DR drill is worse than no drill. Record what was restored, from
which artifact, and how long it took.

| Date | Who | Result | Output |
|---|---|---|---|
| | | | |

### `tools/darkprobe` — dark services are dark

```sh
# darkprobe <identity.json> <service-name> [http-path]
go run ./tools/darkprobe authorized.json <dark-service>      # expect: reached
go run ./tools/darkprobe unauthorized.json <dark-service>    # expect: refused
```

Proves a dark service is reachable by an **authorized** identity and not by an
unauthorized one. Both halves matter: only the negative half detects an
overlay that has quietly stopped enforcing.

| Date | Who | Authorized reached | Unauthorized denied | Output |
|---|---|---|---|---|
| | | | | |

### Assignment report clean

Console → **Governance → Assignment Report**, or
`GET /api/v1/access/assignment-report`. No `would_deny` entries you did not
intend, and a `display == enforcement` spot-check per
[display-equals-enforcement.md](display-equals-enforcement.md).

| Date | Who | would_deny count | Intended? | Output |
|---|---|---|---|---|
| | | | | |

## Release log

One row per tag. The CI link covers every automated control above, because
they all ran on that commit.

| Version | Date | CI run for the tagged commit | Signed | Notes |
|---|---|---|---|---|
| v1.34.0 | _(not cut)_ | | will be the first signed release | |
