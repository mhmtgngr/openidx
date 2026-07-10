# OpenIDX — Parallel Implementation Plan

> **What this is.** The execution plan that turns the ~130 gaps in
> [`MARKET_GAP_ANALYSIS_2026.md`](./MARKET_GAP_ANALYSIS_2026.md) into
> **workstreams that can be picked up in parallel** — grouped by package
> ownership to avoid merge collisions, ordered into dependency **waves** so
> nothing is built before the thing it needs, each with concrete startable
> tasks, the existing code to wire, acceptance criteria, and effort.
>
> Strategy and sequencing rationale live in
> [`ULTIMATE_PRODUCT_PLAN.md`](./ULTIMATE_PRODUCT_PLAN.md). This document is the
> board you assign from.
>
> **Coverage:** every gap in the register maps to exactly one workstream below.
> Nothing is dropped; deferred items are marked and parked in a workstream's
> backlog. Last refreshed 2026-07-10.

---

## How to run this in parallel

**Three rules keep concurrent work safe:**

1. **Own a package, not a feature.** Each workstream is assigned a primary set
   of packages/paths (the *ownership map* below). Two workstreams almost never
   edit the same file. Where a **hot file** is unavoidably shared
   (`internal/oauth/service.go`, `internal/identity/service.go`,
   `internal/access/service.go`, `cmd/*/main.go`), the plan lists the *specific
   functions* each workstream touches, and those workstreams rebase daily.
2. **Respect the waves.** A workstream may start only when its `depends-on`
   workstreams have merged the interface it needs. Wave 0 has no deps (start all
   eight now). Wave 1 builds the four shared foundations. Waves 2–3 consume them.
3. **No new parallel implementations; delete the loser.** Every task that wires
   an existing-but-dead subsystem also *removes or quarantines the duplicate* in
   the same PR. This is the project's #1 debt source (two OAuth stacks, five risk
   engines, a hardened MFA lib beside a plaintext one) and the cause of the
   "hollow layer." Ending the drift is part of "done."

**Definition of done (every PR):** builds green; new/changed logic has a test;
the `orgscope` CI linter passes (tenant scoping); no endpoint returns a
fabricated success or 500; if the PR wired dead code, the duplicate is gone; docs
touched by the change are updated in the same PR.

---

## Ownership map (collision matrix)

| Workstream | Primary packages / paths owned | Shared hot files (functions) |
|---|---|---|
| **WS-01** OAuth hardening | `internal/oauth/**`, `cmd/oauth-service/main.go` | `oauth/service.go` (handleLogin MFA-gate, handleAuthorize) |
| **WS-02** Identity MFA & delivery | `internal/identity/{webauthn,pushmfa,passwordless,otp,passwords}.go` + MFA funcs in `service.go`, `internal/mfa/**`, `internal/email/**` | `identity/service.go` (TOTP enroll/verify, forgot-password) |
| **WS-03** Platform auth & tenancy | `internal/common/middleware/**`, `internal/apikeys/**`, `internal/organization/**`, `web/.../organizations.tsx`,`tenant-management.tsx`, all `cmd/*/main.go` (validator wiring) | `cmd/*/main.go` (validator construction) |
| **WS-04** Risk & policy correctness | `internal/identity/adaptive_mfa.go`, `internal/risk/**`, `internal/middleware/**` (OPA) | `identity/service.go` (login risk call site) |
| **WS-05** Governance enforcement | `internal/governance/**`, `internal/admin/{attestation,ai_policy_recommendations}.go` | — |
| **WS-06** PAM step-up & temp-access | `internal/vault/**`, `internal/access/temp_access.go` | `access/service.go` (route registration) |
| **WS-07** ZTNA honesty | `internal/access/{ziti,unified_audit,posture,context_evaluator}.go` | `access/service.go` (route registration) |
| **WS-08** Repo hygiene & console UX | `docs/**`, `web/admin-console/src/{layout,store,components}`, root cleanup | — |
| **WS-F1** Event bus | `internal/events/**` (new), publishers in identity/provisioning/directory | publisher call-sites (append-only) |
| **WS-F2** Outbound SCIM + connector SDK | `internal/provisioning/outbound/**` (new), `pkg/connector/**` (new) | — |
| **WS-F3** SSF/CAEP | `cmd/ssf-service` + `internal/ssf/**` (new) | — |
| **WS-F4** Token exchange + OPA-everywhere | `internal/oauth/token_flow.go`, OPA middleware in every `cmd/*/main.go` | `oauth/service.go` (token endpoint), `cmd/*/main.go` |
| **WS-F5** Agent-identity substrate | `internal/oauth/{registration,mcp}.go` (new), `oauth_clients` schema | `oauth/service.go` (token/discovery) |
| **Wave 2 P-*** | inherit their pillar's packages | rebase on Wave 1 interfaces |
| **Wave 3 D-*** | new packages per theme | — |
| **XC-*** | cross-cutting (CI, `.github`, `pkg/`, mobile repo, docs) | — |

---

## Dependency waves (the spine)

```
WAVE 0  ── credibility sprint (8 workstreams, all start NOW, no cross-deps) ──┐
  WS-01 WS-02 WS-03 WS-04 WS-05 WS-07 WS-08   [WS-06 waits on WS-01 step-up]  │
                                                                              ▼
WAVE 1  ── shared foundations (4+1, start in parallel; each gates Wave 2) ────┤
  WS-F1 event bus     WS-F2 outbound SCIM     WS-F3 SSF/CAEP                   │
  WS-F4 token-exch+OPA     WS-F5 agent substrate                              │
                                                                              ▼
WAVE 2  ── market parity (6 pillar workstreams; consume Wave 1) ──────────────┤
  P-IAM   P-IGA   P-PAM   P-ZT   P-RISK   P-PLAT                              │
                                                                              ▼
WAVE 3  ── differentiators (6 theme workstreams; the seams) ──────────────────┘
  D-CAE   D-CONV   D-INFRA   D-NHI   D-AGENT   D-ZCON

XC (cross-cutting programs) run continuously alongside every wave:
  XC-COMPLIANCE  XC-CONNECTORS  XC-MIGRATION  XC-MOBILE  XC-LICENSE  XC-DOCS
```

Foundation → consumer edges to remember: **F1** unlocks JML, birthright roles,
dynamic groups, micro-certs, NHI lifecycle, HR provisioning, ITDR loop. **F2**
unlocks lifecycle management + IGA fulfillment + the connector marketplace.
**F3** unlocks token-to-packet CAE, ZTNA mid-session revoke, universal logout,
agent session revoke. **F4** unlocks per-app CA, ABAC enforcement, workload
federation, agent on-behalf-of, MCP tool authZ. **F5** unlocks every AI-agent
gap across all four pillars.

---

# WAVE 0 — Credibility sprint (start all now)

> Goal: no silent security holes; every advertised feature works or is honestly
> labeled. Mostly *wiring existing tested code*, not building. This is the gate
> to any external demo/POC/security review.

### WS-01 — OAuth service hardening
**Owns:** `internal/oauth/**`, `cmd/oauth-service/main.go` · **Depends:** none ·
**Effort:** S · **Unblocks:** WS-06

| # | Task | File anchor | Done when |
|---|---|---|---|
| 1 | Step-up MFA must **verify the code** before completing the challenge / issuing the `step_up` JWT. Call the existing TOTP (`identity.VerifyTOTP`) / WebAuthn verifier per `method`. | `internal/oauth/stepup.go:149` `handleStepUpVerify` | Test: wrong code → 401, no token; correct code → token |
| 2 | Challenge MFA on **any enrolled factor**, not TOTP-only. Query the `user_mfa_methods` view (already used by stepup) and offer the enrolled set. | `internal/oauth/service.go:1882` `mfaEnabled := totpStatus…` | WebAuthn/push/SMS-only user is challenged (test) |
| 3 | `/oauth/authorize`: derive the subject **only** from the `flowAuth` session; reject client-supplied `user_id`; remove the unauthenticated dev bypass. | `oauth/service.go` `handleAuthorize`, `cmd/oauth-service/main.go:196` | Body `user_id` ignored; dev path gone (test) |

### WS-02 — Identity MFA correctness & delivery
**Owns:** `internal/identity/{webauthn,pushmfa,passwordless,otp,passwords}.go` +
TOTP funcs in `identity/service.go`, `internal/mfa/**`, `internal/email/**` ·
**Depends:** none · **Effort:** M

| # | Task | Anchor | Done when |
|---|---|---|---|
| 1 | **Encrypt TOTP secrets at rest** — wire the AES-GCM encrypter from `internal/mfa` into enroll/verify; lazy-migrate plaintext on next verify; **delete the plaintext path**. | `identity/service.go:2033`, `internal/mfa` | New secrets ciphertext; old ones upgrade on use |
| 2 | **HA-safe WebAuthn** — replace the in-memory `sync.Map` challenge store with the built `internal/mfa/webauthn_store.go` (Redis); consolidate on `mfa_webauthn`; fix the wrong-table count. | `identity/webauthn.go:633`, `passwordless.go:449` | Passkey login survives a replica restart (test) |
| 3 | **Magic-link email delivery** — add a template to `internal/email`, call `SendAsync` from `CreateMagicLink`; base URL from settings; remove the token-in-response test endpoint. | `identity/passwordless.go:64`, `handlers_advanced_mfa.go:597` | Link arrives by email; no token in logs/response |
| 4 | **Working push** — FCM HTTP v1 (`x/oauth2/google`) + APNS provider-token (ES256 JWT); creds via `secretcrypt` w/ hot-reload. (Needs the companion app — coordinate w/ XC-MOBILE.) | `identity/pushmfa.go:547,603` | Push reaches a real device (integration) |
| 5 | **Password-reset hardening** — gate the raw-token log behind `APP_ENV=development`; read reset base URL from settings; call the existing HIBP + password-history checks. | `identity/service.go:4687`, `passwords.go` | No token logged in prod; breach check fires (test) |

### WS-03 — Platform auth & tenancy
**Owns:** `internal/common/middleware/**`, `internal/apikeys/**`,
`internal/organization/**`, org console pages, `cmd/*/main.go` validator wiring ·
**Depends:** none · **Effort:** M

| # | Task | Anchor | Done when |
|---|---|---|---|
| 1 | **API keys authenticate** — construct `apikeys.Service` in all 7 service mains; pass the real validator to `AuthWithAPIKey` instead of `Auth()`'s nil. | `middleware.go:304-309`, `cmd/*/main.go` | A minted key authenticates a request (per-service test) |
| 2 | **Org enumeration gate** — put `auth.SuperAdminPredicate` on `GET/POST/DELETE /organizations`; scope the list for non-admins to member orgs. | `internal/organization/service.go` | Non-admin can't enumerate tenants (test) |
| 3 | **Tenant-isolation bypasses** — strip/re-derive `X-Org-Slug` at APISIX+nginx; add `org_id` to the ES audit index mapping + query. | `deployments/docker/apisix`, `internal/audit` ES path | Cross-org spoof + ES leak tests pass |
| 4 | **Org/tenant console renders** — standardize on bare-array + `X-Total-Count`; fix the two React readers; add a Playwright spec mocking the *real* shape. | `web/.../organizations.tsx:56`, `tenant-management.tsx` | Org list populates against the real backend |
| 5 | **Helm production parity** — pre-install migrate Job, backup CronJob, `openidx_app` role in `DATABASE_URL`, delete Keycloak plumbing. | `deployments/kubernetes/helm` | `helm install` migrates + backs up; RLS role correct |

### WS-04 — Risk & policy correctness
**Owns:** `internal/identity/adaptive_mfa.go`, `internal/risk/**`,
`internal/middleware/**` (OPA) · **Depends:** none · **Effort:** M

| # | Task | Anchor | Done when |
|---|---|---|---|
| 1 | **Make admin risk policies apply** — implement the no-op `parseJSON` (unmarshal into the policy struct). | `identity/adaptive_mfa.go:637` | A configured policy changes login risk (test) |
| 2 | **Multi-tenant risk policies** — add `org_id` + RLS to `risk_policies` (match `sql_v37`); scope queries via `orgctx`. | risk migrations, `internal/risk` | No cross-tenant policy bleed (test) |
| 3 | **Wire anomaly detection** — call `RunAnomalyCheck` from a leader-gated worker over `login_history`; auto-lock / auto-IP-block via the IP-threat-list; surface in the alerts UI. | `internal/risk/anomaly.go:468` | Impossible-travel/brute-force alert appears + acts (test) |
| 4 | **Enforce OPA deny-overrides** — Go middleware must enforce `final_allow`, not just `allow`; document the default-on posture. | `internal/middleware` OPA | A rego `deny` actually blocks (test) |

### WS-05 — Governance enforcement
**Owns:** `internal/governance/**`, `internal/admin/{attestation,ai_policy_recommendations}.go` ·
**Depends:** none · **Effort:** M

| # | Task | Anchor | Done when |
|---|---|---|---|
| 1 | **Enforced auto-revocation** — extract the working DELETE from `attestation.go` into a shared revocation executor (role/group/app/vault); call from `SubmitReviewDecision`, `BatchSubmitDecisions`, campaign auto-revoke; write schema-correct audit + Redis session marker. | `governance/service.go:542,1271`, `admin/attestation.go` | A "revoke" removes the grant + kills the session (test) |
| 2 | **Preventive SoD** — fix `pr.condition/pr.effect` → `conditions/actions`; fail **closed**; add the check to access-request fulfillment. | `identity/service.go:2777` `CheckPolicies` | Conflicting-role assignment is blocked (regression test) |
| 3 | **Multi-tenant governance objects** — add `org_id`+RLS to `certification_campaigns`, `campaign_runs`, `abac_policies`; convert the scheduler to iterate orgs. | governance migrations, scheduler | No hardcoded default-org writes (test) |
| 4 | **Real reviewer resolution** — manager (`users.manager_id`) / resource-owner (`entitlement_metadata.owner`) instead of always `admin`; honor `reviewer_strategy`. | `populateReviewItems`, attestation gen | Review routes to the manager (test) |
| 5 | **Stop silent audit loss** — fix mismatched-column INSERTs (`workflows.go:1036`, `jit_expiry.go:96`); check errors; CI test every governance write lands a row. | those files | Governance events persist (CI test) |
| 6 | **Fix or delete broken AI recs** — point `ai_policy_recommendations.go` at real tables or remove it (it 500s today). | `admin/ai_policy_recommendations.go` | No 500ing "AI" route |

### WS-06 — PAM step-up & temp-access hardening
**Owns:** `internal/vault/**`, `internal/access/temp_access.go` ·
**Depends:** **WS-01 task 1** (working step-up) · **Effort:** S–M

| # | Task | Anchor | Done when |
|---|---|---|---|
| 1 | **Enforce step-up at checkout/reveal/session** — `require_step_up` flag on vault secrets + Guacamole routes, checked in vault/guacamole handlers using the now-real step-up. | `internal/vault/handlers.go`, `access/guacamole*.go` | Reveal without fresh step-up → 401 (test) |
| 2 | **Harden temp/vendor access** — route audit through `UnifiedAuditService`; enforce `require_mfa`; implement `notify_on_use` via webhooks; add `org_id`+FORCE-RLS. | `access/temp_access.go:451`, migration | Vendor link is audited, MFA-gated, tenant-scoped (test) |

### WS-07 — ZTNA honesty
**Owns:** `internal/access/{ziti,unified_audit,posture,context_evaluator}.go` ·
**Depends:** none · **Effort:** M

| # | Task | Anchor | Done when |
|---|---|---|---|
| 1 | **Real overlay dial diagnostics** — replace the existence check with a real `zitiCtx.Dial(serviceName)` + timeout + 1-byte probe; surface latency. | `access/ziti.go:1841` `TestServiceDial` | Dial test fails when the overlay is down (test) |
| 2 | **Ziti event ingestion** — subscribe to the controller fabric event stream; normalize circuit/session/posture into unified audit; index to ES. | `access/ziti.go:1869` `GetAuditEvents`, `unified_audit.go:264` | Ziti access events appear in audit search |
| 3 | **Continuous posture revocation on the tunneler path** — worker on `device_posture_results` DELETEs api-sessions on fail transitions; decide via OPA. | `access/posture.go`, `context_evaluator.go` | Degraded posture cuts a live tunneler session (test) |
| 4 | **Runtime-connect + Play Integrity** — pass the swappable `ZitiProvider` into `AgentAPIHandler` (not the boot snapshot); add `require_play_integrity`. | `access/service.go:603`, agent handler | Agent enrolled post-boot gets an identity (test) |

### WS-08 — Repo hygiene & console UX
**Owns:** `docs/**`, `web/admin-console/src/{layout,store,components}`, root cleanup ·
**Depends:** none · **Effort:** S

| # | Task | Done when |
|---|---|---|
| 1 | Reconcile contradictory docs (rewrite `SECURITY-TENANCY.md` around the real RLS belt; fix README SIEM claim). | Docs match shipped behavior |
| 2 | Delete committed cruft: `team.sh.bak.*`, `update_password.sql`, the dead loose `migrations/` numbering scheme, the compiled `frontend/` bundle masquerading as an app. | Repo tree is honest |
| 3 | Console polish: wire the existing `setTheme` into a theme toggle; mount the built idle-timeout dialog; consolidate the two notification API surfaces. | Dark-mode toggle + idle logout work |
| 4 | Fleet profiling: register `pprof` in all mains behind `ENABLE_PPROF` (off in prod, localhost-bound). | Profiling available fleet-wide |

---

# WAVE 1 — Shared foundations (start in parallel; each gates Wave 2)

### WS-F1 — Identity-event bus
**Owns:** `internal/events/**` (new); publisher call-sites in identity/provisioning/directory ·
**Depends:** none (can start alongside Wave 0) · **Effort:** M ·
**Unlocks:** JML, birthright roles, dynamic groups, micro-certs, NHI lifecycle, HR provisioning, ITDR loop

- Define a Redis-stream schema: `user.created/updated/disabled/deleted` + an
  attribute-diff payload (department, manager, status).
- Publish from identity CRUD, the SCIM path, and directory sync (append-only
  call-sites — low collision).
- Provide a leader-gated **consumer framework** (offset tracking, retry, DLQ)
  that Wave-2 workstreams subscribe to.
- **Acceptance:** an integration test asserts a `user.disabled` event is
  produced and a sample consumer observes it exactly once.

### WS-F2 — Outbound SCIM 2.0 client + connector SDK
**Owns:** `internal/provisioning/outbound/**` (new), `pkg/connector/**` (new) ·
**Depends:** none · **Effort:** L · **Unlocks:** workforce lifecycle, IGA fulfillment, the marketplace

- Per-app SCIM target config (base URL, bearer via `secretcrypt`, attribute
  mapping JSON) on the applications registry.
- Redis-queued change worker with retry + circuit breaker (copy
  `internal/webhooks`); reconciliation sweep on the directory-sync leader pattern.
- Publish stable `pkg/connector` interfaces (SCIM target, later HR source / EDR /
  NHI) with the existing per-connector test harness as the template.
- **Acceptance:** disabling a user in OpenIDX deprovisions them in a mock SCIM
  target within one sweep; the SDK ships with a documented example connector.

### WS-F3 — SSF/CAEP service
**Owns:** `cmd/ssf-service` + `internal/ssf/**` (new) · **Depends:** none ·
**Effort:** L · **Unlocks:** token-to-packet CAE, ZTNA mid-session revoke, universal logout, agent revoke

- **Transmitter:** emit CAEP `session-revoked` / `credential-change` SETs from the
  existing Redis revocation pub/sub to registered receivers.
- **Receiver:** accept inbound SETs (JWT parse via `golang-jwt`), map to
  `deprovisionUser` + token revocation + (via WS-07's worker) Ziti termination.
- **Acceptance:** an inbound `session-revoked` event kills the user's OAuth
  tokens and ZTNA session; OpenIDX-originated risk emits an outbound event to a
  test receiver. *Ship as the first OSS SSF/CAEP implementation.*

### WS-F4 — Token Exchange (RFC 8693) + OPA-everywhere
**Owns:** `internal/oauth/token_flow.go` (resurrect), OPA middleware in every
`cmd/*/main.go` · **Depends:** none (coordinate hot-file edits w/ WS-01) ·
**Effort:** M · **Unlocks:** per-app CA, ABAC enforcement, workload federation, agent on-behalf-of, MCP authZ

- Add the `token-exchange` grant, homed in the tested-but-dead `token_flow.go`
  v2 stack (which already enforces grant types/scopes); support `act` delegation
  gated by OPA. **Delete the duplicate live handler once migrated.**
- Add OPA authorization middleware to identity/oauth/audit (they have none);
  standardize the fail-closed `final_allow` contract from WS-04.
- **Acceptance:** an on-behalf-of exchange yields a token carrying the `act`
  claim; an OPA `deny` blocks in every service (test).

### WS-F5 — Agent-identity substrate
**Owns:** `internal/oauth/{registration,mcp}.go` (new), `oauth_clients` schema ·
**Depends:** WS-F4 (token exchange) · **Effort:** M · **Unlocks:** all Wave-3 agent gaps

- RFC 7591 **dynamic client registration** + CIMD, policy-gated approval.
- An `agent` client type with owner / human-sponsor linkage on `oauth_clients`.
- An MCP authorization profile (PKCE, RFC 8707/9728) with APISIX as the data
  plane and OPA per-tool guardrails.
- **Acceptance:** an MCP client self-registers, obtains an agent token bound to a
  human sponsor, and a tool call is authorized/denied by OPA (test).

---

# WAVE 2 — Market parity (consume Wave 1)

> Each pillar workstream inherits its pillar's packages. Tasks are the register's
> P0/P1 *missing* (not-broken) items; per-gap detail + file refs live in the
> register. Order within each is top-to-bottom.

### WS-P-IAM — Federation & provisioning parity
**Depends:** F1 (dynamic groups), F2 (outbound SCIM), F4 (per-app CA)
- Standards-compliant **SAML 2.0 IdP** (`goxmldsig`, real X.509, inbound verify, APISIX route).
- **Generic multi-IdP inbound federation** (well-known discovery; drop Keycloak-hardcoding + the `idps[0]` assumption); inbound SAML SP.
- **SCIM filtering** + honest `ServiceProviderConfig`; gateway route.
- **Signing-key rotation** (wire `keys.go`), **back-channel logout**, **enforced consent** (wire `consent.go`), **custom-claims/federation-rule consumption** — wire-not-build; delete duplicates.
- **Dynamic/rule-based groups** (on F1) and **per-app conditional access** (on F4).
- **Passkey assurance policies** (AAGUID allowlist; synced vs device-bound tiers).
- **Directory-sync incremental correctness** (watermark persistence, `@removed`, disable propagation).
- **HR-driven provisioning** connectors (BambooHR + Workday first, on F1) — shared with P-PLAT.

### WS-P-IGA — Governance parity
**Depends:** F1 (JML/micro-certs/birthright), F2 (fulfillment)
- **Event-driven JML** + **birthright/attribute provisioning** (rule engine on F1; kill the `provisioning_rules` facade).
- **Detective SoD scanning** + violation dashboard + exception workflow.
- **Escalation / delegation / reassignment / reminder workers** (resurrect the dead `RequestService` logic against live rows).
- **Entitlement warehouse** (source-account aggregation, correlation, orphan detection).
- **Certification decision support** (recommendations, dormancy flags, bulk-approve low-risk).
- **Event-triggered micro-certifications**, **non-employee governance**, **identity risk-weighted certs**, **role mining**, **Slack/Teams + actionable-email approvals**, **downstream fulfillment** (outbound SCIM on F2 + ServiceNow tickets), **NHI/service-account governance**, **ABAC fail-closed enforcement**.

### WS-P-PAM — PAM parity
**Depends:** F2 (connector SDK), WS-06 (step-up)
- **Break-glass** workflow; **privileged-account discovery + auto-onboarding**.
- **Checkout exclusivity + dual-control**; **encrypted tamper-evident recordings** (run guacd recordings through `recording_crypto.go`).
- **SIEM/CEF/HEC forwarder**; **rotation-connector breadth** (MSSQL/Oracle/MongoDB/Redis/network-SSH on the F2 SDK) + **Windows rotation + dependency mgmt**.
- **ChatOps approvals + ticketing enforcement**; **Terraform provider (`terraform-provider-openidx`)**; **AAPM SDKs + dynamic per-lease secrets** (shared with P-PLAT).

### WS-P-ZT — ZTNA parity
**Depends:** F1 (JIT grants), WS-07 (posture worker), WS-01 (step-up)
- **UDP / arbitrary-protocol publishing**; **Windows posture-check parity**.
- **EDR/MDM signal ingestion** (CrowdStrike ZTA, Intune/Jamf).
- **Production K8s Ziti fabric + HA control plane** (upstream subchart, 3-node Raft).
- **JIT/time-bound network grants** wired to governance (on F1); **step-up MFA on risk/posture change**.
- **Complete certificate lifecycle** (real rotation, guided CA runbook); **Terraform provider + K8s operator**.

### WS-P-RISK — Risk / ITDR parity
**Depends:** none beyond Wave 0
- **UEBA baselines** (write + use `user_risk_baselines`); **session/token-theft detection**; **MFA-fatigue / push-bombing detection**.
- **Consolidate the five risk engines** onto one canonical path; **delete the rest**.
- **Geo-IP hardening** (bundled MaxMind / TLS; unify caches).
- **Identity deception / honeytokens** (P3).

### WS-P-PLAT — Platform / ops parity
**Depends:** F4 (workload federation)
- **OIDC workload identity federation** (`federated_credentials` table, on F4); **short-lived/JIT dynamic credentials** (Issue() per rotator; shared w/ P-PAM).
- **NHI inventory, ownership & posture scoring** (new `internal/nhi`, directory-sync pattern) — shared w/ D-NHI.
- **Complete DR** (real HA-safe scheduled backups, ES snapshots, restore drills); **Terraform provider + declarative bootstrap** (shared w/ P-PAM/P-ZT — one provider, resource modules per pillar).
- **Internationalization** (`react-i18next`, auth surfaces first); **HA simplification** (etcd SPOF / three proxy layers); **cert lifecycle automation (ACME/inventory)**; **secret scanning w/ liveness**; **conditional access for workloads** (on F4); **N-1 upgrade contract + K8s operator**; **SPIFFE workload identity** (long-horizon, shared w/ D-NHI).

---

# WAVE 3 — Differentiators (the seams)

> The unfair-advantage capabilities. Each is a new theme package that composes
> the finished foundations + parity work. Sequence by market pull.

### WS-D-CAE — Token-to-packet CAE & ITDR loop
**Depends:** F3, WS-07, WS-P-RISK
- **Universal logout / token-to-packet CAE**: one risk event → revoke token + kill session + sever Ziti circuit (on F3). *The headline.*
- **ITDR-to-governance closed loop**: high risk / verify-fail auto-fires a scoped micro-review, expires JIT access, raises step-up.
- **Shadow-SaaS / OAuth-grant discovery** (browser-extension or log-based).

### WS-D-CONV — IGA + PAM + ZTNA convergence
**Depends:** WS-P-IGA, WS-P-PAM
- **Certification-to-network revocation** (revoke decision severs circuits in seconds).
- **One-campaign IGA+PAM** (certify vault access + JIT creds + roles together with recording evidence).
- **PIM-style role eligibility** (eligible vs active); **ZSP for the whole workforce**.
- **Identity attack-path / effective-privilege graph** (recursive CTEs over the unified store).

### WS-D-INFRA — Modern infrastructure access
**Depends:** WS-P-PAM, WS-P-ZT
- **Ephemeral SSH certificates / ZSP** (SSH CA in the vault).
- **Native-client access** (`openidx connect` CLI over the Ziti fabric — ssh/psql/kubectl unmodified).
- **Database session brokering** (Postgres wire-protocol proxy w/ query audit); **Kubernetes access brokering**; **cloud console/CLI JIT elevation**.
- **Moderated sessions**; **AI session summaries**; **privileged-session risk scoring + auto-suspend**; **cloud-vault federation**; **PEDM (Linux-first)**.

### WS-D-NHI — Non-human & workload identity
**Depends:** F4, WS-P-PLAT
- **NHI inventory + governance** (discover external SAs / cloud IAM / OAuth grants / K8s SAs; certify alongside humans).
- **SPIFFE-compatible issuance + federation** (JWT-SVIDs; bridge Ziti↔SPIFFE); **secret scanning w/ liveness** (unique: OpenIDX holds the minted-key hashes); **conditional access for workloads**.

### WS-D-AGENT — AI-agent identity across pillars
**Depends:** F5
- **Agent governance** (agents as catalog principals; certification), **agent privileged access** (vault + JIT), **agent network identity** (Ziti + MCP gateway on the ZTNA plane), **agent risk scoring + CAEP revocation**, **NL admin copilot + platform MCP server**. One substrate (F5), exposed in every pillar.

### WS-D-ZCON — The OSS OpenZiti console
**Depends:** WS-07, WS-P-ZT
- **First-class multi-tenant overlay** (per-org Ziti scoping, delegated admin — remove the hardcoded fallback org UUID).
- **Usage metering / chargeback / consumption analytics**; **AI-assisted app segmentation**; **DEM-lite**; **BrowZer last-mile data controls**; **workload identity federation for CI** (OIDC → ephemeral Ziti identity); **DNS-filtering profile**; **PQ/FIPS crypto posture doc**; **IoT/OT vendor-access pattern**.

---

# Cross-cutting programs (continuous, run alongside every wave)

| Track | Scope | Kick-off deliverable |
|---|---|---|
| **XC-COMPLIANCE** | SOC 2 Type II → ISO 27001 → FIPS 140-3 → FedRAMP; turn the audit service into an evidence generator about OpenIDX itself; pentest + bug bounty | Control-mapping matrix + Type II readiness gap list |
| **XC-CONNECTORS** | Connector SDKs (rotator/SCIM/HR/EDR/NHI) on the F2 base; community marketplace; seed top 20–30 + SSO template gallery | Published `pkg/connector` + 5 reference connectors |
| **XC-MIGRATION** | Importers from Okta / Auth0 / Keycloak / AD / CyberArk (users, groups, apps, policies, passkeys via CXF, vault secrets) | Okta importer (users+groups+apps) MVP |
| **XC-MOBILE** | iOS/Android **authenticator** (push approve, TOTP, passkey, QR — unblocks WS-02 push); signed desktop clients + auto-update; SBOM + cosign/SLSA | Android authenticator MVP wired to WS-02 push |
| **XC-LICENSE** | Decide + publish a permissive, foundation-friendly license posture + explicit open-core boundary | `LICENSING.md` + governance statement |
| **XC-DOCS** | Reconcile/modernize docs; reproducible perf benchmarks (find the single-Postgres ceiling); WCAG pass; air-gap mode (bundled MaxMind/breach-lists/self-hosted push) | Benchmark harness + published RPS/latency numbers |

---

## Ready-to-start summary

- **Start today, in parallel:** WS-01 … WS-05, WS-07, WS-08 (seven independent
  workstreams), plus WS-F1 … WS-F4 (foundations, no deps). WS-06 starts the
  moment WS-01 task 1 merges. That's **~11 workstreams runnable immediately.**
- **Everything downstream** has an explicit `depends-on` and a package owner, so
  Waves 2–3 can be staffed the instant their foundation merges without
  re-planning.
- **Every gap in the register is assigned** to exactly one workstream; deferred
  items (ERP SoD, full IoT/OT, Windows PEDM) are parked in a named backlog, not
  dropped.

First concrete commit of any workstream should reference this plan and the gap
register, and satisfy the Definition of Done above.
