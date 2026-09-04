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
3. Flip `OAUTH_LOGIN_UI=spa`; verify console, mobile, BrowZer logins.
4. Delete the server-rendered login (plan Task 15).
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
4. ☐ **OPA `deny` enforced** — `internal/common/middleware/opa.go`: abort
   unless `Allow && len(Deny)==0`; `authz.rego:15-19`'s "any authenticated
   user may GET anything" removed; `policies/access_control.rego`
   (unreachable package, phantom inputs) deleted; allow+deny → 403 test.
5. ☐ **No-op buttons made honest** — `ai_recommendations.go` "Apply"
   performs each action through the primitive that exists or returns 501
   with the reason (and the console shows it); `ispm.go` "Remediate"
   sends the reminder / opens the review item and marks
   `remediation_pending` / `flagged` — the score moves only when the next
   scan passes.
6. ☐ **ABAC enforcement (D4)** — new `internal/abac` (the `internal/appaccess`
   shape: small, DB-direct, importable by both enforcement points) holds
   the evaluator moved out of `internal/governance/service.go`; governance
   keeps thin wrappers so the page's test button runs the production
   evaluator. `ABAC_ENFORCE` tri-state validated like
   `PAM_SESSION_RISK_GATE`; wired inside `assignmentGateAllows`
   (`internal/oauth/service.go`) and the proxy's assignment decision
   (`internal/access/service.go`), subject = the user row's attributes +
   roles + groups, resource = the application; `abac.would_deny` /
   `abac.denied` written through the same durable audit path as
   assignment decisions; a mode badge on the ABAC page.
7. ☐ **SMS `mock` is not a provider** outside development
   (`internal/sms/service.go`); "Send test SMS" answers 501 on mock;
   `ValidateProduction` rejects `SMS_ENABLED=true` + `SMS_PROVIDER=mock`.
8. ☐ **Multi-IdP SSO** — `sso_state` carries `idp_id`; the callback loads
   that IdP, not `idps[0]`.
9. ☐ **Assignment gate fails closed under enforcement** — a lookup error
   with `ACCESS_ASSIGNMENT_ENFORCE=true` denies (audited) instead of
   issuing; report mode keeps logging and allowing.
10. ☐ **`ValidateProduction()` sees the enforcement flags** — errors for
    `DEV_ADMIN_BYPASS=true` and mock SMS; warnings surfaced on the ops
    cockpit / first-run gate for every gate still in report mode
    (`ACCESS_ASSIGNMENT_ENFORCE`, `ABAC_ENFORCE`, `ENABLE_OPA_AUTHZ`,
    `PAM_SESSION_RISK_GATE`, `POSTURE_DEVICE_TRUST_GATE`).
11. ☐ **Constants dressed as measurements** — real uptime; the dashboard
    metrics/refresh endpoints removed; predictive growth computed or
    removed; SAML transient NameID random per assertion; continuous-auth
    geo uses `GEOIP_SERVICE_URL` or reports the factor unavailable;
    role-assignment review campaigns populate from role assignments.

*Exit test:* the two-org isolation tests and the orgscope inversion are
green; the integration harness with `ABAC_ENFORCE=enforce` and a deny
policy answers 403 + audit on `/oauth/authorize`.

### P6 — A Definition of Done that CI proves

1. ☐ **Convergence Task 15 is code, not ops** — the server-rendered login
   is deleted: `GET /oauth/login`, `POST /oauth/authorize/callback`, the
   five `/oauth/authorize/mfa*` routes, `hosted_mfa.go`,
   `renderLoginPage`/`handleLoginPage`/`handleAuthorizeCallback`, the
   `OAuthLoginUI` branch and flag. `POST /oauth/login` (the SPA's JSON
   API) and `POST /oauth/mfa-verify` stay. `OAUTH_LOGIN_URL` (default
   `<issuer>/login`) is set in the compose stack, whose console is on
   another origin. Proof: a route-table test asserting the routes are
   absent (with `POST /oauth/login` as the positive control) and an
   integration case under `ACCESS_ASSIGNMENT_ENFORCE=true` proving an
   unassigned user of an opted-in application is denied + audited and
   `GET /oauth/login` is 404.
2. ☐ **Smoke test in CI** — `docker compose up` (a CI override with
   `ZITI_ENABLED=false` and an explicit service list) → `make smoke-test`.
   The DoD §6.1 exit test, run on every PR.
3. ☐ **Playwright in CI** — the mocked specs against `vite preview`, the
   backend-dependent ones inside the smoke job; port/README drift fixed;
   stale specs fixed or deleted, never skipped.
4. ☐ **Helm install proof** — a `kind` job runs `make helm-install --wait`
   and asserts the migration Job completed, OPA is ready, the backup
   CronJob and NetworkPolicies exist.
5. ☐ **Gates that gate (D2)** — `docs.yml` validates on PRs with
   `--strict`; `security-scan.yml` blocks (Trivy exit 1 on CRITICAL/HIGH
   with `ignore-unfixed`, Gitleaks/Semgrep/npm-audit without
   `continue-on-error`, allowlists carry a reason); `status-check`
   aggregates every guard job and `test-frontend`; `ci-android.yml` loses
   its `|| true`; `tools/contractcheck` armed in `ci-web.yml` and
   `api-contract.test.ts` compares console paths against the route tables.
6. ☐ **CODEOWNERS** rewritten to the real owner; unsupported `!` lines and
   dependabot references removed.
7. ☐ **Agent downloads derived, not written** — the agent release builds
   Linux deb/rpm with the existing `agent/Makefile` nfpm target and
   publishes `agent-manifest.json`; `pages/add-device.tsx` renders only
   what the manifest lists.

*Exit test:* every new job green on the PR; DoD items 1, 2, 4 and 6 point
at a job.

### P7 — One console, one client

1. ☐ **Bilingual for real** — the remaining English in
   `components/` (`my-privileged-access-section`, the remote viewers, the
   self-heal panel, the audit stream/dashboard, `manage-app-access-dialog`,
   `relay-renderer`), `App.tsx`'s two loading strings, `api/mfa.ts`'s
   thrown errors; the completeness test extended to `src/components/**`;
   both page globs recursive so `pages/audit/` is gated.
2. ☐ **Console controls that were not true** — idle timeout wired into the
   layout from the session policy; device-trust sync awaited with a
   warning on failure; all five topology queries gated and the
   query-coverage guard counting per `useQuery`; `AdminRoute` on
   `hasMinRole` with a route/role matrix test.
3. ☐ **Dead console code out** (~1,300 LOC incl. `mfa-setup-wizard.tsx`),
   duplicate proxy-route toggles collapsed, tests for the untested
   security pages (`add-device`, `remote-support-popout`, `lib/webauthn`,
   `api/mfa`), the `tr` catalog lazy-loaded.
4. ☐ **Backend hygiene** — `internal/feature/`, `internal/oauth/store.go`,
   the empty gateway loggers, the env reader that reads no env, the two
   unbound config flags deleted; tests that name the security core
   (`handleToken`, refresh, revoke, the MFA step-up handlers, backup/bypass
   codes, vault reveal/checkout, `RunSoDSweep`, `handleApproveRequest`,
   kill switch, the Guac session handlers); OpenAPI specs cover the routed
   groups and carry the release version.
5. ☐ **Mobile (D1)** — `mobile/` and its workflow deleted with every
   reference; Flutter: release keystore from CI secrets, ntfy push (the
   throwing Firebase stub removed), backup-codes / passkeys / TOTP screens
   ported, iOS built as an artifact until Apple credentials exist.

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
3. ☐ **Versions aligned** to 1.34.0 (`package.json`, `Chart.yaml
   appVersion`, `pubspec.yaml`, `PRODUCTION-READINESS.md`, the OpenAPI
   `version:` fields) with a version-sync guard.
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
2. `ACCESS_ASSIGNMENT_ENFORCE=true` in the reference deployment; the
   server-rendered login is deleted from the code (one login UI, at
   `OAUTH_LOGIN_URL`); §5.3's table holds for every row.
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
