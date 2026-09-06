# Final audit — 2026-09-06

The readiness programme's last act on this branch. Every phase of the plan
closed with its own verification; this is the pass that re-runs all of it at
once, on one tree, and writes down what came back — including the one thing
that came back wrong.

**Audited tree:** `dec5b493`, branch
`claude/project-readiness-security-controls-c797kg`, 187 commits ahead of
`main`, 1,135 files changed (+106,217 / −61,495).

An audit that only confirms is not an audit. This one found a defect in its
own programme's work — see [What it found](#what-it-found) — and the fix is in
the commit that carries this file.

## What was run

Everything below ran locally against the audited tree, in one sitting. CI runs
the same things on the pull request; the point of running them here is that a
local run cannot be explained away by a runner.

| Check | Result |
|---|---|
| `go build ./...` | exit 0 |
| `go vet ./...` | exit 0 |
| `go test ./internal/... ./tools/... ./cmd/... ./pkg/...` | **77 packages ok**, 17 with no test files, 0 failures |
| `go run ./tools/orgscope -fail ./internal` | **0 blocking findings**; 5 tables on the `needsScoping` register (each a recorded product decision, below) |
| `gofmt -l` over first-party Go | clean |
| Console `npm run type-check` | exit 0 |
| Console `npx vitest run` | **160 files, 1,181 tests, all passing** |
| Console `npm run lint` | **0 errors**, 185 warnings (the standing `no-explicit-any` baseline) |
| Console `npm run build` | built |
| 29 repo and CI guard runs (`check-*.sh` and their `.test.sh` self-tests) | all green |
| 14 UI-safety guard runs (7 guards, each self-tested and run `--enforce`) | all green |
| 12 self-heal loop self-tests | all green |
| CodeQL results check on `dec5b493` | **passing** — 0 results ≥ 7.0 in changed code |

The guards are the load-bearing half of that list. A test proves a behaviour
once; a guard proves nobody can quietly take it away. `ci.yml`'s aggregate
requires 21 jobs, so none of them is optional.

## What it found

`.github/codeql/codeql-config.yml` — added by this branch three commits before
this audit — declared `paths-ignore: agent/third_party`, to keep nine
`go/incorrect-integer-conversion` results in a vendored library out of a
reader's way. Its own comment said it narrowed what was scanned and changed
nothing about how a finding is treated.

The next analysis produced all nine.

A CodeQL database for a compiled language is whatever the build compiled. The
agent compiles gopsutil, so gopsutil is in the database; the config's path
filter is honoured for interpreted languages only. The file excluded nothing
and said it did — a control that displays without enforcing, which is the exact
defect class this whole programme was written to remove, produced by the
programme, under a comment claiming the opposite. It survived three commits,
which is how long it took for something to read the output instead of the file.

It surfaced because the audit read the SARIF rather than the config. That is
the same move that broke the original CodeQL chase open: the check reports a
count, so `scripts/codeql-alert-summary.sh` prints the list the check will not.
Reading the artefact instead of the intention is what both findings have in
common, and it is the transferable lesson here.

**Fixed in the same commit as this file:** the config is deleted, the reason is
recorded in `.github/workflows/codeql.yml` at the step where the next person
would reach for one, and the nine vendored findings are back on the maintainer
dismissal list in [codeql-triage.md](codeql-triage.md) — which is where a
finding nobody can act on always had to end up.

## What is open

Nothing here is a surprise and nothing here is engineering on this branch.
Each item names its owner.

### The maintainer

1. **Dismiss the triaged CodeQL alerts** ([codeql-triage.md](codeql-triage.md)
   lists which and why). Hygiene, not a blocker — the results check passes.
2. **Merge this pull request.**
3. **Tag v1.34.0** — the first signed release. `RELEASING.md` has the recipe;
   `release.yml` does the signing.
4. **Supply the CI secrets nobody else can:** the Android release keystore, and
   Apple signing material for the iOS upload path. Until they exist the Flutter
   client ships an artifact named for the debug key that signed it, which is
   the honest state rather than a hidden one.
5. **Branch protection** should require the checks `ci.yml` does not own.
6. **A VPAT pass** needs a human with a screen reader. The automatable subset
   is gated in CI; the rest is not automatable, by definition.

### The operator, on a live deployment

The rollout order, each step in report mode first:
`ACCESS_ASSIGNMENT_ENFORCE` → `ABAC_ENFORCE` → `ENABLE_OPA_AUTHZ` →
`PAM_SESSION_RISK_GATE` / `POSTURE_DEVICE_TRUST_GATE`. Then the §5.2 and §5.3
controls, filed in [operational.md](operational.md) and
[display-equals-enforcement.md](display-equals-enforcement.md) with dates.

Those files are empty of dates on purpose. A control's evidence is somebody
having run it, and nobody has.

### Product decisions, deliberately not made here

- **Five tables on the `needsScoping` register.** Each needs an answer, not a
  migration: may one external account link to a user in two tenants; is the
  agent fleet per-tenant or per-install. Guessing would be a schema change
  built on a guess.
- **Delegation scope enforcement.** Group, Role and Application scopes are
  recorded and shown but narrow nothing; only Organization is enforced.
  Enforcing the others needs the identity of the resource each request acts
  on, which the permission middleware does not have, and narrowing an existing
  delegation would silently revoke access somebody is relying on. The console
  now says so on every affected row, the middleware comment says where the
  truth is told, and `docs/docs/guide/governance.md` says it in prose — an open gap that
  announces itself, rather than a badge that implies a control.
- **The roadmap-epic consoles** (outbound SCIM targets, HR-driven joiner/mover/
  leaver, SSF/CAEP streams) ship as documented API-only surfaces. Post-GA, by
  the decision recorded in the guide.

## Two things this audit did not do

**Fix the vendored tree's formatting.** `gofmt -l` names two files under
`agent/` that are not formatted. Both are identical to `main`, neither is
touched by this branch, and no CI job gates them. Fixing them here would widen
a 1,135-file pull request for cosmetics; recording them is the useful half.

**Re-audit what earlier phases already proved.** Each phase closed against its
own red proof — the guard shown failing before it was made to pass. Re-deriving
those would produce confidence, not evidence. The evidence is the guard, still
in CI, still green above.
