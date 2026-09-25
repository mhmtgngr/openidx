# Working agreement for AI coding agents

This document tells AI coding agents (Claude Code and others) how to work in
this repository. It adds to [CONTRIBUTING.md](../CONTRIBUTING.md) and does not
replace it. Humans should read CONTRIBUTING.md first.

The repository's `.gitignore` keeps `CLAUDE.md` and `AGENTS.md` local. An
agent loads this agreement when that local file imports it, with the line
`@docs/AI-WORKING-AGREEMENT.md`.

OpenIDX is a self-hosted access platform (IAM + IGA + PAM + ZTNA over OpenZiti).
The Go services live under `cmd/` and `internal/`, and the React console under
`web/admin-console/`. The Flutter client is in `client/`, the endpoint agent in
`agent/`, and deployment files in `deployments/`. Priorities are in
[ROADMAP.md](../ROADMAP.md).

## 1. Product decisions belong to the human maintainer

- A product decision is anything that changes scope, priorities, defaults,
  user-visible behaviour, the data model's meaning, naming, licensing, or what
  is deprecated. The human maintainer (@mhmtgngr) makes these decisions. When a
  task needs one, stop and ask. Give two or three options, a recommendation,
  and the trade-off. Do not decide "under delegation", and do not record a
  decision as taken until the maintainer has confirmed it in writing.
- Record each confirmed decision as a short ADR in `docs/adr/`, named
  `NNNN-title.md`, with context, options, decision and consequences. The ADR
  names the person who approved it.
- [ROADMAP.md](../ROADMAP.md) is the only source of priorities. Work outside the
  current milestone needs the maintainer's go-ahead. The current milestone is
  **M1 "Trusted Core"**, which means **no new features**: only hardening,
  verification, secure defaults and fixes.
- **Frozen:** the global-scale / cell-architecture programme, whose plans are
  archived under `docs/archive/`. Do not extend it until the maintainer lifts
  the freeze.

## 2. Security-critical code needs human approval

The human maintainer must review and approve a change before it merges if it
touches any of these areas. Say so at the top of the PR description, and never
self-merge or enable auto-merge on such a PR:

- **Authentication and tokens:** `internal/oauth/`, `internal/identity/`,
  `internal/auth/`, `internal/stepup/`, `internal/signingkeys/`,
  `internal/revocation/`, `internal/apikeys/`.
- **Tenant isolation and schema:** `internal/common/database/` (RLS and
  pooling), `internal/migrations/`, `tools/orgscope/`.
- **Secrets and privileged access:** `internal/vault/`, `internal/credentials/`,
  and any key, KEK, signing or encryption code.
- **Authorization decisions:** `internal/access/` (PAM broker and Ziti policy),
  `internal/abac/`, `internal/jitgrant/`.
- **Supply chain:** the agent's enrollment and update code under `agent/`, and
  `.github/workflows/release.yml`, including signing.

## 3. Definition of done

A change is done only when all of the following hold:

1. **Two-sided tests.** There is a positive test, showing the allowed case
   works, and a negative test, showing the disallowed case is refused (the
   unassigned user, the other tenant, the revoked token, the wrong scope). A
   control with only a positive test is not done.
2. **Display equals enforcement.** Anything shown in a UI or advertised in a
   discovery document, the API docs or the README is actually enforced. For an
   access grant, that means a row in
   `docs/evidence/display-equals-enforcement.md`. If it is not enforced,
   remove it. Never ship a switch, badge, field or endpoint that decides
   nothing.
3. **Database tests run in CI.** Tests that need Postgres are selected by a CI
   job, not only by a local run.
4. **You ran the checks.** These are the checks for the areas you touched:
   - **Go:** `go build ./...`, `go vet ./...`, `go test -short ./...`, and
     `make test-db` for database code.
   - **Web:** in `web/admin-console`, `npm run type-check`, `npm run lint`,
     `npm test -- --run`, `npm run build`.
   - **CI guards:** `make guards`.
5. **The PR says what was verified.** It states what was verified and how, and
   also what was *not* verified. A "done" claim without evidence is not
   accepted.

## 4. Keep the repository clean

- **No session logs in the repository.** Do not append progress narratives,
  "windows" or "lessons" to `CHANGELOG.md`, plan documents or anything under
  `docs/archive/`, which holds dated records only. Progress belongs in the
  PR description and the GitHub issue. A CHANGELOG entry is one or two
  user-facing lines.
- **One topic per PR,** small enough for one human review.
- **No site-specific values in product code.** Real hostnames, IP addresses,
  home directories and organisation names belong in an operator's environment
  or overlay. They never go in defaults, examples, fixtures or tests. Use
  `example.com`, `localhost` or same-origin instead.
- **Update the document that owns a topic** rather than writing a new one.
  Keep documents short and current.
- **Prefer tests that check outcomes** (a running stack, an upgrade, a
  restore, a conformance run) over scripts that check the text of files. Add a
  new CI guard script only when it closes a defect class that has actually
  happened.

## 5. Commits and pull requests

- Follow [CONTRIBUTING.md](../CONTRIBUTING.md) for commit messages and the DCO
  sign-off. CI checks every commit for a `Signed-off-by` line.
- Never push to `main`, never force-push a shared branch, and never merge your
  own PR.
- Link the GitHub issue the PR works on, and say which roadmap milestone it
  belongs to.
