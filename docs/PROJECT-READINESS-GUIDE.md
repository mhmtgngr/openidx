# OpenIDX Project Readiness — the User-Perspective Guide

**Date:** 2026-09-01 (commit `c98082a`, branch `main`)
**Question this document answers:** *Is OpenIDX fully functional and well defined end to end, as experienced by the people who use it — and what are the next steps and controls to get it there?*

This is the product-and-user-side companion to
[PRODUCTION-READINESS.md](./PRODUCTION-READINESS.md) (the deploy-side view,
last refreshed 2026-06-08). It was produced by a fresh full-repo audit:
backend (all `cmd/` + `internal/`), frontend (all apps), deployment assets,
and all 122 docs, with the headline findings re-verified against the code.
`go build ./...` passes clean on the audited commit.

Read §1 if you are confused about how IAM, IGA, PAM and ZTNA fit together.
Read §2–§3 for the honest state of the product. Read §4 for what to do next,
in order. Read §5 for the recurring controls that keep the project ready.

---

## 1. The mental model (this resolves the IAM/PAM/ZTNA confusion)

OpenIDX is **one product with four pillars**, not four products. Each pillar
answers a different question about the same person:

| Pillar | The question it answers | What the person actually experiences |
|---|---|---|
| **IAM** (identity) | *Who are you, and is it really you?* | The login page, MFA prompts, passkeys, SSO into apps, "My Security", sessions |
| **IGA** (governance) | *Who approved that you have this, and for how long?* | Access requests, approvals, access reviews / certifications, SoD blocks, JIT expiry |
| **PAM** (privileged access) | *How do you borrow powerful credentials safely?* | Credential vault checkout, brokered SSH/RDP in the browser, recorded sessions |
| **ZTNA** (network, via OpenZiti) | *How do you reach things that have no public door?* | The endpoint agent / BrowZer, "My Apps & Network", dark services with no inbound port |

What makes them **one product** is the spine they share:

```
one identity  →  one grant (application assignment)  →  one policy plane
       →  one audit trail (unified_audit_events)  →  one kill switch
```

A decision made anywhere propagates everywhere: disable a user and IAM
sessions, vault checkouts, live privileged sessions **and** Ziti network
circuits are severed (three enforcement layers, ≤30 s worst case — see
[IAM_PAM_ZITI_INTERRELATION.md](./IAM_PAM_ZITI_INTERRELATION.md), the best
conceptual doc in this repo).

### 1.1 Why it still *feels* confusing — the four parallel access systems

The confusion is real and structural, and the project has already diagnosed
it ([access-model-redesign.md](./access-model-redesign.md)): historically,
**four independent mechanisms decided what a user can reach, and they did
not talk to each other**:

1. Application assignments (`user_application_assignments`) — what the
   launcher and governance *display*, enforced by **nothing**;
2. Proxy route roles/groups (`proxy_routes.allowed_roles`) — what the web
   proxy enforces;
3. Ziti dial policies — what the network overlay enforces (by default, for
   *every* enrolled identity, regardless of assignment);
4. PAM entry grants — what privileged connect/reveal enforces.

So an admin could "assign an app" and grant nothing, and a user could reach
an app that never appeared in their portal. **The fix is designed, planned
([access-and-login-convergence-design.md](./access-and-login-convergence-design.md),
[plans/2026-08-30-access-and-login-convergence.md](./plans/2026-08-30-access-and-login-convergence.md))
and — as of #878/#880 — fully landed in code**: one predicate package
(`internal/appaccess`) consumed by the portal, the Ziti reconciler, the
proxy and `/oauth/authorize`, plus one SPA login and a real MFA policy.

**But it is all still behind flags that default to the old behaviour:**
`ACCESS_ASSIGNMENT_ENFORCE=false` and `OAUTH_LOGIN_UI=server`
(`internal/common/config/config.go:282,293,771`). Until the staged rollout
(Task 16 of the plan) is executed, *assignment is still a catalogue, not a
grant*. Executing that rollout is the single highest-leverage step this
project can take — see §4, P1.

### 1.2 The missing glossary (use these words consistently)

| Term | Means | Does **not** mean |
|---|---|---|
| **Application** | A thing users launch (OIDC/SAML client and/or a published route) | A Ziti service (that's the transport underneath) |
| **Route** (`proxy_routes`) | The published web path to an application, optionally Ziti-overlaid | An access grant |
| **Service** (Ziti) | A dark network endpoint dialable over the overlay | Something users see by name |
| **Assignment** | The admin act of granting an application to a user/group — *the* grant once convergence is enforced | (today, pre-rollout) an enforcement |
| **Entitlement / grant** | What governance reviews and certifies (assignments, roles, vault grants, JIT) | — |
| **Policy** | A rule evaluated at decision time (MFA policy, ABAC/OPA, dial policy, approval policy) | A grant |

A user-facing version of §1 belongs in the published docs — nothing there
explains the four pillars together today (see §3.3).

---

## 2. Verdict snapshot

**The platform is genuinely built.** ~190k lines of non-test Go across 36
domains, 1,463 HTTP routes, 137 migrations, 514 test files (~118k test
lines), 8 services with a fail-closed production startup gate. The admin
console's ~107 pages are **all wired to real APIs — zero mocked pages**
(verified by sweep; there is even a CI contract test that fails on
endpoint drift). Core crypto is right: Argon2id passwords with
rehash-on-verify (`internal/common/pwhash/pwhash.go`), RS256 pinned with
type assertions everywhere, AES-256-GCM envelope encryption with KEK
rotation and a `cmd/rekey` tool, FORCE row-level security with a
merge-blocking tenant linter (`tools/orgscope`).

**Where it is not ready, the pattern is consistent:** a control or a story
*displays* without being *true* —

| Symptom | Examples |
|---|---|
| Controls that display but don't enforce | Admin "revoke session" is inert (§3.1-A1); assignment isn't a grant until rollout (§1.1); IP threat list ignored by login risk scoring; voice MFA UI over a no-op backend |
| First contact fails | The canonical getting-started doc leaves a new user unable to log in; README quick start references files that don't exist; `helm install` cannot bootstrap its own schema |
| The trust story contradicts itself | `SECURITY.md` still says "multi-tenant SaaS isolation is not implemented" while README and SECURITY-TENANCY.md (correctly) say the opposite; the published docs site describes a Keycloak-based product with **no PAM or ZTNA sections at all** |
| Shipped but unreleased | Last release v1.27.0 (2026-07-13); ~7 weeks of major work — including security fixes — sits in `[Unreleased]` |

None of this is scaffolding rot. It is a codebase maturing faster than its
enforcement wiring, docs, and release process. That gap is closable with
focused work, and §4 sequences it.

---

## 3. End-to-end readiness, journey by journey

The user's definition of "fully functional" is: every journey below
completes without a workaround. Status: ✅ works · ⚠️ works with material
caveats · ❌ broken/missing.

| # | Journey (persona) | Status | The caveat that matters |
|---|---|---|---|
| J1 | **First run** — deploy → log in → rotate admin → create org (operator) | ⚠️ | Works via `scripts/generate-secrets.sh` + `deployments/docker/docker-compose.yml` (+ `.prod.yml`). Broken as documented: README quick start cites a root compose file and a Helm repo that don't exist; `docs/GETTING-STARTED.md` never states a working credential (three docs give three different admin credentials); `helm install` runs no migrations and references an OPA service the chart never creates. No minimum hardware stated for a ~39-container stack. |
| J2 | **Joiner** — create/sync user → enroll MFA → first login → sees their apps (end user) | ✅⚠️ | Real: user CRUD/SCIM/directory sync, MFA wizard (TOTP/WebAuthn/push/recovery), portal. Caveats: WebAuthn challenges are in-memory (`internal/identity/service.go:206`) → passkeys break with >1 replica; a typo'd `SMS_PROVIDER` silently falls back to a mock that delivers nothing (`internal/sms/service.go:115`); phone-call MFA is enrollable but can never verify (dead provider, fails closed — `internal/identity/phone_call_mfa.go:278`). |
| J3 | **App access** — publish app → assign → user launches with SSO → reach matches (admin + user) | ⚠️ | SSO itself is solid (OIDC/PKCE, SAML, consent). But assignment drives real reach **only after the convergence rollout** (§1.1). Today the report-only machinery observes the gap; `#874` already made "My Apps & Network" show enforced truth. Execute rollout Task 16. |
| J4 | **Network access** — enroll agent/BrowZer → posture check → reach a dark service (end user) | ✅ | Real: Windows/Android agents, BrowZer clientless, posture checks, reconciler, `tools/darkprobe` proves dark services are reachable only by authorized identities, and a "going dark" runbook exists. Per-app scoping of dial policies arrives with the same rollout as J3. |
| J5 | **Privileged access** — request → approve → checkout/brokered session → recording → review (engineer + auditor) | ✅❌ | Functionally the strongest pillar: vault with rotation, Guacamole + in-browser wasm-SSH, recordings with encryption/retention/legal hold, break-glass. But **zero user-facing PAM documentation and zero OpenAPI coverage** of `/pam/*` — a headline pillar that is invisible to evaluators and undocumented for users. |
| J6 | **Governance loop** — access request → approval → certification campaign → revoke propagates (manager/auditor) | ✅ | Requests, multi-step approvals, campaigns, SoD (fail-closed), JIT expiry all wired; application fulfillment gap was closed (`internal/governance/workflows.go`). |
| J7 | **Leaver / incident** — disable or kill-switch a user → everything severed (admin) | ✅⚠️ | The strong path: deprovision + lifecycle sweep + Ziti sweep sever IAM/PAM/network in ≤30 s; kill switch is synchronous and honest about partial failures. The broken path: **the admin console's per-session "Revoke" is cosmetic** — see A1 below. |
| J8 | **Operate** — monitor → audit → back up → restore → upgrade (operator) | ⚠️ | Compose-prod path, backup CLI with *automated restore verification*, DR/HA drills (`make dr-game-day`, `ha-drill`) are genuinely good. Caveats: Helm chart can't stand alone; security CI scans gate nothing (every step `continue-on-error`, including the final gate — `.github/workflows/security-scan.yml:440`); release binaries unsigned; release cadence stalled. |

### 3.1 The specific defects behind the ⚠️s (verified, with fixes)

**A. Controls that display but don't enforce** — worst class for a security
product; either wire them or remove them from the UI.

- **A1 — Admin session revocation is inert (P0).**
  `internal/admin/sessions.go` (`DELETE /sessions/:id` and
  `DELETE /users/:id/sessions`) only sets `sessions.revoked=true` in
  Postgres. Enforcement reads **Redis**: the refresh grant checks
  `revoked_session:<id>` (`internal/oauth/service.go:3532`), and the DB
  column is read by `IsSessionValid` — which has zero production callers.
  Result: the UI shows "revoked", and the user's refresh token keeps
  minting access tokens indefinitely. Four other paths do this correctly
  (deprovision `internal/identity/service.go:835`, kill switch, SCIM,
  session policy) — the admin path was simply missed. Fix: publish the
  same Redis markers from both admin handlers (the `redis` client is
  already on the admin `Service`). Note even when fixed, already-minted
  access tokens live up to their TTL (default 1 h) because request-path
  middleware checks signature+expiry only; the kill switch remains the
  incident-response path.
- **A2 — IP threat list doesn't feed login risk.**
  `internal/risk/scorer.go:476` `isIPBlocked` is a placeholder returning
  `false`. Admins populate the list, IBDR auto-writes it, and the access
  proxy honors it — but it contributes zero to the login risk score that
  drives step-up MFA.
- **A3 — Voice-call MFA is a dead feature** (enrollable, never verifiable;
  provider never instantiated). Hide the four routes or wire Twilio.
- **A4 — SAML Single Logout never sends the LogoutRequest**
  (`internal/oauth/saml_slo.go:480` builds and logs it). SP sessions
  survive logout.
- **A5 — Assignment isn't a grant until the rollout flips** (§1.1) — the
  systemic instance of this class.
- Minor same-class: DB-backed feature flags silently fall back to memory
  (`internal/feature/flag.go:295`); gateway `logInfo`/`logError` are empty
  bodies (`internal/gateway/service.go:235`).

**B. First-contact failures** — what a new operator/evaluator hits in hour one.

- **B1 — Default admin `admin@openidx.local` / `Admin@123` seeds every
  install including production** (`internal/migrations/sql.go:517`,
  migration v10), is *not* checked by `ValidateProduction()` (which does
  guard the Ziti and Guacamole defaults), is absent from the deployment
  checklist, and there is no forced first-login rotation. For an IAM/PAM
  product this is the headline install-time risk.
- **B2 — You cannot log in by following the docs.** `GETTING-STARTED.md`
  gives no credential; `USER_GUIDE.md` says `Admin123!`;
  `PRODUCTION-READINESS.md` says `Admin@123`. One authoritative first-login
  section, plus forced rotation, fixes B1+B2 together.
- **B3 — README quick start is wrong three ways** (no root
  `docker-compose.yml`; `make dev-infra`+`make dev` overlap and still
  reference Keycloak — `Makefile:231`; `charts.openidx.io` is unpublished),
  and all 7 links in README's Documentation section are dead. `install.cmd`
  at the repo root is an unrelated file committed by accident.
- **B4 — `helm install` yields a non-working deployment**: no migration
  Job/hook (docs claim `AUTO_MIGRATE=true`, which exists nowhere), inert
  `apisix.enabled`/`opa.enabled` values with `opaUrl` pointing at a Service
  the chart never creates (governance is fail-closed → breaks), no
  `securityContext`, `Chart.yaml` still declaring a Keycloak dependency.
- **B5 — Grafana ships admin/admin** (compose fallback
  `GF_SECURITY_ADMIN_PASSWORD:-admin`, port 3001 published, prod overlay
  doesn't override); dev-kube applies its `changeme-*` secrets template
  directly (`dev-kube/kustomization.yaml:18`).

**C. Trust-story contradictions** — what a client's security reviewer reads.

- **C1 — `SECURITY.md` §Trust Model still says single-tenant / "multi-tenant
  SaaS isolation is not implemented"**, contradicting README and
  `SECURITY-TENANCY.md` (which documents the FORCE-RLS boundary correctly
  and marks the single-tenant claim as historical). Same stale claim in
  `GETTING-STARTED.md:10`. A reviewer reading the file literally named
  SECURITY.md concludes your flagship isolation feature doesn't exist.
- **C2 — The published docs site (mkdocs) is a different, older product**:
  only 31 of 122 docs published, no PAM or ZTNA sections in the nav,
  `docs/docs/guide/architecture.md` names "Keycloak 23" as the IdP. The
  excellent conceptual docs (§1's reading list) are all unpublished.
- **C3 — No threat model, no compliance control mappings** (SOC 2 / ISO
  27001 exist only as report *types* the audit service emits), OpenAPI
  specs pinned at 0.1.0 with ~7–42% route coverage and phantom services;
  dangling references to docs that never existed
  (`MARKET_GAP_ANALYSIS_2026.md`, `ULTIMATE_PRODUCT_PLAN.md`).
- **C4 — Stale entry-point docs actively mislead**: `PROJECT-STATUS.md`
  (May) drops PAM/IGA from the product definition and calls Helm/Terraform
  incomplete; `FEATURE_PRIORITY_PLAN.md` lists long-shipped features as
  "must implement"; `TESTING.md` instructs authenticating against Keycloak.

**D. Surface sprawl** — decide, then delete.

- Two overlapping mobile apps: `mobile/` (Expo — real, active) vs
  `client/` (Flutter — never compiled in-repo by its own README; FCM stub
  throws; iOS deep links unconfigured). Pick the shipping one; say so.
- Dead/vestigial: `frontend/` (committed pre-built JS bundle + duplicate
  Playwright suite), `web/admin-console/keycloak-theme/` (250-line
  skeleton, no Go references), orphaned `pages/branding.tsx`, 13 legacy
  `.sql` files no runner loads — two containing credentials
  (`migrations/011_add_admin_users.sql:106`).
- `landing.tsx` hardcodes unsubstantiated marketing claims (99.99% SLA,
  <50 ms, 70% savings) into the product UI.

**E. Enterprise gates** (not blockers today, but the next "no" from a buyer):
no i18n at all (~107 pages of hardcoded English), accessibility far below
VPAT/WCAG expectations (~40 aria attributes console-wide), end users share
the admin bundle behind role gates only, release binaries unsigned/no
checksums, WebAuthn single-replica limit (J2).

---

## 4. Next steps — the program, in priority order

Each phase has an exit test. Don't start the next phase's *announcements*
before the previous phase's exit test passes — code can proceed in parallel.

### P0 — Make displayed controls true, and first contact survivable (~1–2 weeks)

1. **Wire admin session revocation to Redis markers** (A1). *This branch
   ships the fix — see the commit accompanying this guide.*
2. **Close the default-admin hole** (B1/B2): add a `ValidateProduction()`
   critical check for an unrotated `admin@openidx.local` password, force
   password change on first login, write the one authoritative first-login
   doc section, and rotate the two docs that state credentials.
3. **Fix the trust contradiction** (C1): correct `SECURITY.md`'s trust
   model to the FORCE-RLS multi-tenant reality (link SECURITY-TENANCY.md),
   fix `GETTING-STARTED.md:10`.
4. **Fix README first-run** (B3): correct compose paths, remove Keycloak
   remnants from Makefile output, delete `install.cmd`, fix or remove the
   7 dead doc links, state a hardware floor (≥8–10 GB RAM for the full
   compose stack).
5. **Make security CI gate** (J8): remove `continue-on-error` from the
   final "fail on critical findings" step (keep individual scanners
   non-blocking if needed, but the gate must gate).
6. **Kill the admin/admin Grafana fallback and dev-kube secrets template
   in `resources:`** (B5).

*Exit test:* a new operator with only the README reaches a logged-in,
rotated-admin console; `security-scan.yml` goes red on a seeded critical;
revoking a session in the console kills the refresh token (integration
test).

### P1 — One access model: execute the convergence rollout (~2–4 weeks, the anti-confusion fix)

Follow Task 16 of
[plans/2026-08-30-access-and-login-convergence.md](./plans/2026-08-30-access-and-login-convergence.md)
exactly — it is already written:

1. Deploy phases A+C (no behaviour change), verify `openidx-appdial-*`
   policies appear beside blanket ones.
2. Drive the **assignment report** (`/assignment-report`) to clean —
   create the assignments you actually intend; only trust it when
   `reachability_source=controller` and `incomplete_users=0`.
3. Flip `OAUTH_LOGIN_UI=spa`; verify console, mobile, BrowZer logins.
4. Delete the server-rendered login (plan Task 15).
5. Flip `ACCESS_ASSIGNMENT_ENFORCE=true`; verify an unassigned user can no
   longer dial, and the denial is audited.
6. Create the first MFA policy (`{"factor_enrolled": true}`) and chase
   enrollment via MFA Management stats.

Then finish the story: fold A2 (threat list → risk score) and decide
A3/A4 (wire or remove voice MFA and SAML SLO).

*Exit test:* for any user, **My Apps & Network, the assignment report, the
proxy, `/oauth/authorize` and the Ziti controller all give the same
answer** — display equals enforcement, one grant model, one login, one MFA
policy. This is the moment the IAM/PAM/ZTNA confusion structurally ends.

### P2 — Tell one product story (parallel with P1)

1. **Publish the real docs site**: restructure `mkdocs.yml` around the
   four pillars + the §1 mental model; publish the strong tier
   (IAM_PAM_ZITI_INTERRELATION, zero-trust-architecture,
   how-network-access-works, SECURITY-TENANCY, SECURITY-HARDENING,
   remote-access-lifecycle-scenarios); purge Keycloak from
   `docs/docs/guide/architecture.md`.
2. **One quickstart** (deploy → login → org → user → app → dark service →
   PAM session), replacing the three divergent ones; retire or banner the
   stale entry docs (PROJECT-STATUS, FEATURE_PRIORITY_PLAN, TESTING.md).
3. **Write the missing PAM docs** (admin setup + end-user checkout/session
   walkthrough) and spec `/pam/*` in OpenAPI; regenerate specs against
   live routers (the `contractcheck`/route-enumeration tooling exists).
4. **Add the auditor artifacts**: a real threat model (overlay, broker,
   recordings, vault included) and a control-mapping table
   (SOC 2 / ISO 27001 → OpenIDX capability → evidence).
5. Separate engineering artifacts (`docs/plans`, `docs/ux-audit`,
   audits/reviews) from product docs; label the Turkish-language docs.

*Exit test:* an evaluator who reads only the published site can describe
all four pillars, deploy, log in, and find PAM.

### P3 — Operability & release hygiene

1. **Cut v1.28.0 now** — 7 weeks of work including security fixes is
   sitting unreleased; `docs/RELEASING.md` already defines the process.
2. **Finish the Helm chart**: migration Job/hook, real or removed
   OPA/APISIX toggles, `securityContext`, ServiceMonitor, backup CronJob,
   chart publishing (or delete the README's Helm section until true).
3. **Move WebAuthn challenges to Redis with TTL** (unblocks >1 replica).
4. **Sign release artifacts** (SHA256SUMS + cosign; images already get
   provenance/SBOM — extend to binaries).
5. Deduplicate Dependabot/Renovate; prune dead surfaces (D).

### P4 — Enterprise reach (sequence by sales pressure)

i18n framework then string extraction; accessibility pass to a VPAT;
separate/hardened end-user portal bundle; mobile app decision (Expo vs
Flutter) executed; then the existing roadmap epics (outbound SCIM,
HR-driven JML, per-org overlay scoping, SSF/CAEP, agent-identity
substrate).

---

## 5. The controls — recurring checks that keep the project ready

These are *controls* in the audit sense: run them on a cadence, keep the
evidence. §5.1 gates every release; §5.2 verifies a running install; §5.3
is the invariant that prevents the four-systems problem from returning.

### 5.1 Release-gate controls (every release)

- [ ] `make build` + full test suite green, including `test-integration`
      (Required Checks already enforce this — keep it that way).
- [ ] `tools/orgscope` clean (tenant boundary) — merge-blocking, do not
      waiver.
- [ ] Security scans **gating** (post-P0.5): CodeQL, govulncheck, Trivy,
      Gitleaks, Semgrep — zero unwaivered criticals.
- [ ] Migration drill: `cmd/migrate up` from the previous release's schema,
      then `down` one step, on a copy.
- [ ] `ValidateProduction()` smoke: a deliberately-insecure config refuses
      to start (this is the security floor — prove the gate still bites).
- [ ] `make dr-game-day` (or at minimum `cmd/backup` restore-verify) —
      a false-green DR drill is worse than none.
- [ ] `tools/darkprobe`: dark services reachable by an authorized identity
      and **not** by an unauthorized one.
- [ ] Assignment report clean (post-P1): no would-deny entries you didn't
      intend; `display == enforcement` spot-check per §5.3.
- [ ] CHANGELOG updated, version tagged, artifacts signed (post-P3),
      README/status docs match the release ("docs currency" — grep the
      release notes for anything that invalidates an entry-point doc).

### 5.2 Operational controls (running install — monthly, and after incidents)

Identity & session:

- [ ] Default admin rotated; ≥2 admin accounts; MFA enrolled on all admins
      (TOTP + hardware backup).
- [ ] Revoke a test session from the admin console → refresh token dies
      (validates A1 stays fixed); kill-switch drill on a test user → IAM,
      PAM, Ziti all report severed.
- [ ] MFA factors that are *offered* are *deliverable*: send a real SMS and
      email OTP (a typo'd provider silently mocks — A-class defect);
      confirm push approval end to end.
- [ ] JWT signing key age ≤ 90 days (nothing in code reminds you).

Access model (the §1 spine):

- [ ] Pick 3 users; compare My Apps & Network ↔ Access 360 ↔ assignment
      report ↔ actual dial/launch. All four agree.
- [ ] Access review revoke on a test grant propagates (portal, proxy,
      overlay) within the sweep interval.

Platform (see [SECURITY-HARDENING.md](./SECURITY-HARDENING.md) for the
full config-gate list — it is the enforced source of truth):

- [ ] All services green on `/health` + `/ready`; Prometheus scraping all
      8; alert routes paged to a human.
- [ ] Audit pipeline: a test admin action appears in `unified_audit_events`
      and in the SIEM forwarder; hash-chain verification passes.
- [ ] Backup CronJob/timer ran in the last 24 h **and** the latest
      restore-verify passed.
- [ ] No `latest` image tags in production; image digests pinned.
- [ ] Grafana/observability endpoints are not exposed with default creds.

### 5.3 The display==enforcement invariant (verify whenever access machinery changes)

For each grant type, the place a person *sees* it and the place the system
*enforces* it must use the same predicate:

| Grant | Displayed at | Enforced at | Verify by |
|---|---|---|---|
| App assignment | My Apps & Network, Access 360 | `internal/appaccess` via proxy, `/oauth/authorize`, Ziti dial policy (post-P1) | assignment report empty; dial test |
| Role/group | Users/Groups pages | JWT `roles` claim, route checks | route probe as member vs non-member |
| Vault/PAM grant | My Privileged Access, PAM pages | `pamEntryAllowed` at connect/reveal | connect as granted vs ungranted user |
| Session | Sessions pages | Redis `revoked_session:*` at refresh/userinfo | revoke → refresh fails |
| MFA policy | MFA Management | `IsMFARequired` in the OAuth login path | policy user is challenged; exempt user isn't |
| Device trust | My Devices, Access 360 | Ziti posture + `#device-trusted` attribute | untrusted device denied dial |

Anything that appears in an admin UI without a row in this table is a
defect: either wire it or remove it.

### 5.4 Zero-trust tenets (NIST SP 800-207) — where OpenIDX stands

| Tenet | Mechanism | Status |
|---|---|---|
| All resources dark; access per-session | Ziti overlay, no inbound ports, per-session circuits | ✅ (per-app scoping post-P1) |
| Dynamic policy: identity + device + context | Posture checks, risk engine, step-up, MFA policy | ⚠️ threat list not in login score (A2); MFA policy live post-P1 |
| Monitor & measure integrity | Posture, EDR integration, audit hash-chain | ✅ |
| Authenticate/authorize strictly before access | OIDC/SAML + MFA + fail-closed RLS/OPA | ✅ (revocation latency caveat, A1/TTL) |
| Least privilege per request | Assignment-as-grant, JIT, SoD, vault checkout | ⚠️ becomes true when `ACCESS_ASSIGNMENT_ENFORCE=true` |
| Collect & improve | Unified audit, SIEM, risk analytics, self-heal | ✅ |

---

## 6. Definition of Done — "fully functional, well defined, end to end"

Call the project ready from the user's perspective when all of these hold:

1. Every journey J1–J8 in §3 is ✅ with no manual workaround, and each has
   an automated or scripted verification.
2. `ACCESS_ASSIGNMENT_ENFORCE=true` and `OAUTH_LOGIN_UI=spa` in the
   reference deployment; the legacy login is deleted; §5.3's table holds
   for every row.
3. Every control visible in the admin console enforces something (no
   A-class defects open).
4. A new operator completes first run from the README alone; a new end
   user completes login→MFA→launch from the published docs alone; an
   evaluator can find all four pillars on the docs site.
5. `SECURITY.md`, the README, and the docs site tell one story, and a
   threat model + control mapping exist for the auditor.
6. Releases are current (no >2-week unreleased security fixes), signed,
   and the Helm path installs working or is not advertised.
7. The §5 controls have run at least once on cadence with evidence.

---

## 7. When this file is wrong

This document follows the repo's convention: it cites the file that settles
each claim, so it can be re-verified. If you fix something listed here,
update or strike the entry in the same PR — a gap list that is not
re-checked becomes a rumour (see the §6 preamble of
[PRODUCTION-READINESS.md](./PRODUCTION-READINESS.md), which learned this
the hard way). If this document and the code disagree, the code is right
and this file has rotted: fix the file.
