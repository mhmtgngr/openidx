# CodeQL high-severity triage

CodeQL's `security-and-quality` suite raises 40 results at security severity
**7.0 or higher** across this tree — 27 Go, 13 JavaScript/TypeScript. GitHub's
code-scanning results check fails a pull request on exactly these (mediums,
warnings and notes cannot fail it), and it names only a count:

> 224 new alerts including 1 high severity security vulnerability

That is the whole of what the check told you while it was red. This file is
the rest: every result at or above the floor, with a verdict and the evidence
for it.

**The check is green now**, and the title says why:

> 225 new alerts including 213 medium severity security vulnerabilities

One high became none. The one was `go/insecure-hostkeycallback`, and the fix
below removed it — see the caution in that entry, because an alert
disappearing and a behaviour disappearing are not the same claim.

**How the list is produced.** `scripts/codeql-alert-summary.sh` runs after each
analysis (both jobs in `.github/workflows/codeql.yml`) and prints the results
from the SARIF the analysis already writes. It is a diagnostic and cannot fail
the build. Re-read it from the job log after any run; this file is a snapshot,
and a snapshot goes stale.

**Snapshot:** commit `dec5b493`, `security-and-quality` — the run in which the
results check first passed.

**Below the floor.** The 80 quality-only JS results are not security findings
and are out of scope here. `go/log-injection` is 759 results at 6.1 — not what
fails the check, but the volume that buried the 27 Go results that do, so
it gets a
verdict of its own at the end.

---

## Verdicts

| Verdict | Meaning |
|---|---|
| **fixed** | changed on this branch; the alert is gone |
| **not a defect** | the flagged code is correct, and why |
| **vendored** | third-party code this project does not maintain |
| **needs the maintainer** | a real decision, recorded, owner named |

Nothing is left under "needs the maintainer": the one finding that carried real
work is fixed.

---

## Go — 27 results ≥ 7.0

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

### `go/insecure-hostkeycallback` — 8.2 × 1 — **fixed**

`internal/access/ws_connect.go`

```go
HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // overlay-scoped; per-entry pinning is a follow-up
```

This was the one entry in this file with real work behind it, and the comment
had been promising the work for a while. The connection is dialled inside the
Ziti overlay, so the transport is already authenticated end to end and the host
key adds little against a network attacker — but it adds something against a
compromised or misconfigured overlay endpoint, and "a follow-up" is not a
control.

Now: a PAM entry's `settings.ssh_host_key` (one `authorized_keys` line, the
shape the SSH rotator's connector config already uses — so no migration, the
settings column is free-form JSONB) is **enforced** through `ssh.FixedHostKey`.
A different host key fails the connection; a stored key that will not parse
fails it too, rather than falling back to accepting anything — a pin that is
displayed and not enforced is worse than no pin, because someone believes in
it. An entry with no pin connects as before, and says so: a Warn log naming the
entry, and `host_key_pinned: false` on the `pam.ws_connect` audit event, so
"which of my entries accept any host key" is answerable.
`PAM_SSH_REQUIRE_HOST_KEY=true` refuses unpinned entries outright, for
operators who want pinning mandatory; making that the default would break every
existing entry, which is the operator's call and not this function's.

Four tests pin it (`ws_connect_test.go`), the first behavioural: the callback
is invoked with the pinned key and with a different one, and has to accept the
first and reject the second. Red-proved by dropping the `FixedHostKey`
assignment.

**The alert is gone from the SARIF, and that is the weaker of the two claims.**
`go/insecure-hostkeycallback` follows an `InsecureIgnoreHostKey()` that reaches
`HostKeyCallback`; once the callback is a variable a branch may overwrite, the
query stops flagging it. So the count went to zero the moment the pin existed,
whether or not any entry sets one. What the tests prove is the other claim: a
pinned entry is enforced. An entry that pins nothing still accepts any host
key — deliberately, loudly (Warn log, `host_key_pinned: false`), and
refusably (`PAM_SSH_REQUIRE_HOST_KEY=true`). Do not read the green check as
"no entry connects unpinned"; read `host_key_pinned` on the audit events.

Semgrep sees the same line and says so — `go.lang.security.audit.crypto.`
`insecure_ssh.avoid-ssh-insecure-ignore-host-key`, raised on the review of the
commit that added the pin. It is a true finding about the unpinned path, and
it carries this verdict: not a `// nosemgrep`, because this repository silences
a scanner only for a false positive, and this one is not.

### `go/incorrect-integer-conversion` — 8.1 × 9 — **vendored**

`agent/third_party/gopsutil/cpu/cpu_linux.go:204, 278, 289`,
`agent/third_party/gopsutil/load/load_linux.go:97, 99, 101, 103`,
`agent/third_party/gopsutil/net/net_linux.go:583, 886`

A vendored copy of gopsutil, parsing `/proc`. This project does not maintain
that source, and patching a vendored tree in place is how a vendored tree stops
being updatable.

**A correction, because this file was wrong here.** It said these nine would
"disappear on the next run" under a `paths-ignore: agent/third_party` in
`.github/codeql/codeql-config.yml`. The next run produced all nine. A Go
database is whatever the build compiled, the agent compiles gopsutil, and the
config's path filter is honoured for interpreted languages only — so the
config excluded nothing while its own comment said it narrowed what was
scanned. That is this programme's defect class wearing a YAML hat, found by
the final audit reading the SARIF instead of trusting the file. The config is
deleted (`.github/workflows/codeql.yml` carries the reason where the next
person would reach for one), and these nine go back on the maintainer's
dismissal list below, where they were always going to have to live.

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

## `go/log-injection` — 6.1 × 759 — **not a defect**, and pinned

Below the failing threshold, but it is 759 of the 794 Go results: the reason
nobody could see the 27 that matter. It deserves a verdict rather than a
shrug.

Log injection is **forging a record** — a user-supplied value carrying CR/LF so
that what reads as a second log line was in fact typed by the attacker. What
prevents it here is the encoder, not a sanitiser at each of 759 call sites:

- production (`APP_ENV=production`) builds `zap.NewProductionConfig()`
  (`internal/common/logger/logger.go:24`), whose encoding is JSON;
- development builds `zap.NewDevelopmentConfig()`, and zap's console encoder
  still writes the structured **fields** through the JSON encoder.

Either way a `zap.String("username", userInput)` value is JSON-escaped and a
newline inside it comes out as the two characters `\` and `n`. That is not an
assertion: `TestUserValuesInFieldsCannotForgeALogRecord`
(`internal/common/logger/log_injection_test.go`) encodes a forged value through
both encoders and fails if a raw line break survives.

**The shape that would be a real defect** is a user value interpolated into the
log *message*, which the console encoder writes verbatim. The same test pins
that difference, so the distinction cannot quietly stop being true. A sweep for
it — `logger.Info(fmt.Sprintf(...))` and message concatenation across
`internal/` and `cmd/` — finds **four** sites, and all four interpolate
configuration (`server.Addr`) or join constant strings. None carries user
input.

So: triage a future `go/log-injection` alert by asking which argument the
tainted value reaches. A field is safe by construction; the message is not.

### Update — eleven alerts on lines that ARE sanitised

Alerts **2477–2486**, raised on `5921ce10`, sit on:

`internal/common/middleware/csrf.go:81, 97, 107` ·
`opa.go:71, 88` · `ratelimit.go:172, 210, 211` ·
`tenant_resolver.go:208`

Alerts **2488–2489**, raised on `41d70b07`, are the same thing one commit later:
`internal/gateway/middleware/logging.go:87` logs a body that went through
`logsafe.JSONBody`, and `:261` a query string that went through
`logsafe.QueryString`. Both lines were *added* by the commit that introduced the
redaction, which is the tell: the count goes up when the sanitiser is applied to
a site the query already reached.

Every one of those lines reads `logsafe.String(...)` or another `logsafe` call. They are the sites that
commit *added* the sanitiser to, and the count did not go down, because
**CodeQL cannot see this sanitiser**. From the query's own customizations
(`go/ql/lib/semmle/go/security/LogInjectionCustomizations.qll`) it recognises
exactly two:

- `ReplaceSanitizer` — a `strings.ReplaceAll` whose replaced string is `"\r"`
  or `"\n"`;
- `SafeFormatArgumentSanitizer` — an argument formatted with `%q`.

`logsafe.Clean` uses `strings.Map`, which is neither, so taint flows through
it. No config file can change that (and see the note in
`.github/workflows/codeql.yml` about why a Go `paths-ignore` cannot either).

**Do not rewrite `Clean` as a CR/LF `ReplaceAll` to make the scanner quiet.**
That is the one change that would clear the alerts, and it would make this
function the weaker of the two implementations the package was created to
unify — its own comment records that four of the five copies it replaced
"stripped only CR and LF". A tab still ends a field in a TSV-shaped line, an
ANSI escape still reprograms the terminal reading `docker logs`, and a NUL
still truncates in some consumers. `TestCleanIsNotReplaceAllOfCRLF`
(`internal/common/logsafe/logsafe_test.go`) fails if somebody makes the
scanner happy at the control's expense, and its comment says why.

So the triage rule gains a second question. Ask which argument the tainted
value reaches — and if the answer is "a field, through `logsafe`", the alert is
closed by this entry.

---

## What the maintainer needs to do

The verdicts above are recorded; the alerts are still open in code scanning,
and closing them is a UI action this branch cannot take. **None of it blocks
the merge** — the results check passes on `dec5b493`. This is hygiene: an
alert list nobody has triaged is an alert list nobody reads.

1. Dismiss as **"used in tests"**: the 13 JS results.
2. Dismiss as **"false positive"**, citing this file: `go/sql-injection`,
   the four `go/path-injection`, the three `go/weak-sensitive-data-hashing`,
   the five `go/request-forgery`, and the five `go/disabled-certificate-check`.
3. Dismiss as **"won't fix"**, citing this file: the nine vendored
   `go/incorrect-integer-conversion` in `agent/third_party/gopsutil`. A path
   filter cannot remove them from a Go analysis — see the entry above — so the
   UI is the only place this verdict can be recorded, and it has to be
   re-recorded whenever a vendor bump moves those lines.
3b. Dismiss as **"false positive"**, citing this file: `go/log-injection`
   alerts 2477–2486 and 2488–2489, which are on lines that call `logsafe`. Read the
   "nine alerts on lines that ARE sanitised" entry first — the reason matters,
   because the change that would clear them is a change that must not be made.
4. Nothing to do for `go/insecure-hostkeycallback`: it is no longer raised.
   Read its entry anyway before concluding the unpinned path went away.

Item 2 is the one worth doing carefully: a dismissal is keyed to an alert
fingerprint, so the next refactor that moves one of those lines brings the
alert back with the dismissal gone. That is why the verdicts live here as
well.
