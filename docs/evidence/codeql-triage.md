# CodeQL high-severity triage

CodeQL's `security-and-quality` suite raises 41 results at security severity
**7.0 or higher** across this tree — 28 Go, 13 JavaScript/TypeScript. GitHub's
code-scanning results check fails a pull request on exactly these (mediums,
warnings and notes cannot fail it), and it names only a count:

> 224 new alerts including 1 high severity security vulnerability

That is the whole of what the check tells you. This file is the rest: every
result at or above the floor, with a verdict and the evidence for it.

**How the list is produced.** `scripts/codeql-alert-summary.sh` runs after each
analysis (both jobs in `.github/workflows/codeql.yml`) and prints the results
from the SARIF the analysis already writes. It is a diagnostic and cannot fail
the build. Re-read it from the job log after any run; this file is a snapshot,
and a snapshot goes stale.

**Snapshot:** commit `7ebdcdd0`, CodeQL 2.26.4, `security-and-quality`.

**What is not here.** The 757 `go/log-injection` results (6.1, medium) and the
80 quality-only JS results are below the floor and out of scope for this file.
`go/log-injection` at that volume is worth its own pass; it is not what fails
the check.

---

## Verdicts

| Verdict | Meaning |
|---|---|
| **fixed** | changed on this branch; the alert is gone |
| **not a defect** | the flagged code is correct, and why |
| **vendored** | third-party code this project does not maintain |
| **needs the maintainer** | a real decision, recorded, owner named |

---

## Go — 28 results ≥ 7.0

### `go/request-forgery` — 9.1 (critical) × 5 — **not a defect**

`internal/access/ziti.go:732, 768, 885, 2201, 2230`

Every one is `zm.mgmtClient` calling the **Ziti controller** whose URL the
operator configured. The taint CodeQL follows is real — the URL reaches the
client from a request body — but the body is `PUT /ziti/settings` and
`POST /ziti/settings/test`, both registered `adminOnly`
(`internal/access/service.go:431-433`). An administrator naming the address of
their own overlay controller is the feature, not a forgery: the product cannot
manage a Ziti network without being told where it is.

Worth stating plainly, because it is the limit of this verdict: an
administrator can therefore point the management client at an internal
address. That is inherent to an operator-run controller, which normally *is*
internal. It is a privileged-configuration surface, not a path from an
unauthenticated or ordinary-user request to an arbitrary host.

### `go/sql-injection` — 8.8 × 1 — **not a defect**

`internal/credentials/mysql_rotator.go:204`

```go
ddl := fmt.Sprintf("ALTER USER '%s'@'%s' IDENTIFIED BY %s", conf.targetUser, conf.targetHost, quoted)
```

MySQL cannot bind identifiers, and `ALTER USER` is DDL, so a placeholder is not
available for the user, the host, or the password. Both identifiers are
validated at parse time against an **anchored** allow-list —
`mysqlIdentRE = ^[A-Za-z0-9_.%-]+$` (`mysql_rotator.go:18`), checked at `:81`
and `:84`, and the config is rejected outright if either fails. The password
goes through `mysqlQuoteLiteral` (`:104`), which refuses a NUL byte and escapes
`\` and `'`, on a connection pinned with `NO_BACKSLASH_ESCAPES` stripped and
`utf8mb4`.

This alert was assessed and dismissed once before — the code says so in a
comment on the statement. **The dismissal did not survive**: an unrelated
refactor on this branch (routing the rotator's bootstrap credential through
`useAdminSecret`) moved the statement by one line, and a code-scanning
dismissal is keyed to the alert's fingerprint. That is the argument for this
file: a verdict recorded in a review UI evaporates on a line move, and a
verdict recorded in the repository does not.

### `go/insecure-hostkeycallback` — 8.2 × 1 — **needs the maintainer**

`internal/access/ws_connect.go:238`

```go
HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // overlay-scoped; per-entry pinning is a follow-up
```

The connection is dialled inside the Ziti overlay, so the transport is already
authenticated and encrypted end to end and the host key adds little against a
network attacker. It still adds something against a compromised or
misconfigured overlay endpoint, and the comment already calls per-entry host-key
pinning a follow-up. **Owner: maintainer.** Unchanged by this branch — this is
the pre-existing posture, recorded here so it is not mistaken for an oversight.

### `go/incorrect-integer-conversion` — 8.1 × 9 — **vendored**

`agent/third_party/gopsutil/cpu/cpu_linux.go:204, 278, 289`,
`agent/third_party/gopsutil/load/load_linux.go:97, 99, 101, 103`,
`agent/third_party/gopsutil/net/net_linux.go:583, 886`

A vendored copy of gopsutil, parsing `/proc`. This project does not maintain
that source, and patching a vendored tree in place is how a vendored tree stops
being updatable. `.github/codeql/codeql-config.yml` excludes
`agent/third_party/**` from analysis for exactly this reason: nine findings
nobody can act on are nine findings between a reader and the ones they can.

### `go/path-injection` — 7.5 × 4 — **not a defect**

`internal/access/remote_support_recording.go:102, 105, 161, 165`

All four resolve through `filesystemRecordingStore.path` (`:82`), which maps
**every** rune outside `[A-Za-z0-9_-]` to `_` before joining:

```go
safe := strings.Map(func(r rune) rune { ... return '_' }, sessionID)
return filepath.Join(s.root, safe, "recording.webm")
```

`../` becomes `___`. There is no traversal to construct. CodeQL does not
recognise `strings.Map` with a default-replace closure as a sanitiser; the
comment above it already says the sanitising is deliberate and defensive, since
session IDs are UUIDs to begin with.

### `go/weak-sensitive-data-hashing` — 7.5 × 3 — **not a defect**

- `internal/identity/passwords.go:141` — SHA-1 of the candidate password, for
  the **HaveIBeenPwned k-anonymity API**, which specifies SHA-1 and receives
  only the first five hex characters. Using anything else would not be a
  stronger check; it would be no check.
- `internal/access/dbproxy/upstream.go:100` — MD5 as required by the
  **PostgreSQL `md5` authentication message**. A wire protocol, not a choice.
- `internal/backup/backup.go:622` — the explicitly labelled **pre-scrypt legacy
  decryption path**. New backups derive their key with scrypt (`:615`); this
  branch exists to still open an old file.

### `go/disabled-certificate-check` — 7.5 × 5 — **not a defect (dev tooling)**

`agent/cmd/e2e-screenshare/main.go:66, 88`, `cmd/profiler/main.go:221`,
`internal/access/my_resources.go:307`, `tools/darkprobe/main.go:76`

Four are developer tools and probes that talk to a local self-signed edge;
`my_resources.go:307` is a liveness probe whose response body is never read.
Each carries its reason at the line.

**A sixth was here and is fixed.** `tools/contractcheck/main.go` hard-coded
`InsecureSkipVerify: true` with `-insecure` defaulting to **on**, so the tool
that exists to prove what a deployment really answers would accept any
certificate from anything that answered. Verification is now on unless asked
for, the transport takes the flag's value, and
`TestProbeVerifiesCertificatesUnlessAsked` pins it. That one was a real
finding — see the `[Unreleased]` entry in `CHANGELOG.md`.

---

## JavaScript/TypeScript — 13 results ≥ 7.0

Every one is in a **test or end-to-end spec**, none in shipped console code:

| Rule | Sev | Location |
|---|---|---|
| `js/incomplete-url-substring-sanitization` | 7.8 | `e2e/production.spec.ts:13, 14` |
| `js/incomplete-hostname-regexp` | 7.8 | `e2e/production-deployment.spec.ts:20`, `src/pages/identity-providers.test.tsx:117` |
| `js/insecure-randomness` | 7.8 | `e2e/client-registration.spec.ts:30, 45`, `e2e/test-helpers.ts:136` |
| `js/regex/missing-regexp-anchor` | 7.8 | `e2e/identity-provider-templates.spec.ts:59, 75`, `e2e/production-deployment.spec.ts:20, 257`, `src/pages/identity-providers.test.tsx:117`, `src/pages/webhooks.test.tsx:107` |

(paths relative to `web/admin-console/`)

**Verdict: not a defect.** The URL and hostname checks are a test suite asking
"am I pointed at production?" before it refuses to run destructive steps — a
guard on the test runner, not an authorisation decision, and a false negative
there fails safe by skipping. The randomness generates unique client names for
fixtures. The unanchored regexes are `getByText` matchers.

**Worth noticing anyway:** `e2e/production.spec.ts:13` decides whether a suite
is allowed to mutate by `PLAYWRIGHT_BASE_URL?.includes('openidx.tdv.org')`. A
substring test is the wrong shape for that question, and the cost of getting it
wrong is a destructive suite running against a live deployment. Recorded for
the e2e work, not a product defect.

---

## What the maintainer needs to do

The verdicts above are recorded; the alerts are still open in code scanning,
and closing them is a UI action this branch cannot take.

1. Dismiss as **"used in tests"**: the 13 JS results.
2. Dismiss as **"false positive"**, citing this file: `go/sql-injection`,
   the four `go/path-injection`, the three `go/weak-sensitive-data-hashing`,
   the five `go/request-forgery`, and the five `go/disabled-certificate-check`.
3. Leave open, as real work: `go/insecure-hostkeycallback`
   (`ws_connect.go:238`) — per-entry host-key pinning.

The nine vendored results disappear on the next run with the `paths-ignore`
config; nothing to dismiss.
