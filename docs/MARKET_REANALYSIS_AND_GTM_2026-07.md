# OpenIDX — Market Re-Analysis, Ziti-First Strategy & Go-To-Market (2026-07-21)

> **What this is.** The commercial follow-on to
> [`MARKET_GAP_ANALYSIS_2026.md`](./MARKET_GAP_ANALYSIS_2026.md) (2026-07-10 gap
> register) and [`ULTIMATE_PRODUCT_PLAN.md`](./ULTIMATE_PRODUCT_PLAN.md) (product
> roadmap). Those answered *"what to build."* This document answers four
> commercial questions as of **2026-07-21**:
>
> 1. **How ready is the project now?** — re-scored against the live code after
>    the 59 commits (v1.25.0 → v1.27.0+, schema v68 → v87) that landed since the
>    July 10 audit.
> 2. **What is the product thesis "over Ziti"?** — which features to set on top
>    of the OpenZiti layer, and why that stack is the moat.
> 3. **How does governance affect IAM, Ziti, and PAM?** — the control-plane
>    model that makes the four pillars one product instead of four modules.
> 4. **How do we sell it?** — segments, packaging, pricing, channels, and a
>    sequenced 12-month commercialization path — plus the refreshed gap list,
>    split into *deal-blockers* and *product gaps*.
>
> Method: code-verified internal audit (sentinel checks against the July 10
> register + a full implementation-maturity sweep) plus fresh July-2026 market
> research (competitive landscape, OpenZiti ecosystem, commercial-OSS GTM
> benchmarks). Sources cited inline where external.

---

## 1. Executive summary

<!-- FILLED AFTER MARKET SECTIONS -->

---

## 2. Readiness re-assessment (2026-07-21)

### 2.1 What actually changed since the 2026-07-10 audit

The July 10 register's headline risk was the **"hollow layer"** — advertised
features that were dead code or silently broken. Eleven days and 59 commits
later, most of the *exploitable* hollow layer is gone. Verified in code, not
changelogs:

**Security wave (v1.25.0, workstreams WS-01…WS-05) — closed:**

| July 10 finding | Status today (verified) |
|---|---|
| Step-up MFA rubber-stamps any code | **Fixed** — `internal/oauth/stepup.go` now calls `verifyStepUpFactor` (TOTP/WebAuthn verified before minting) |
| MFA challenge only checks TOTP (WebAuthn/SMS-only users bypass) | **Fixed** — `mfaEnabled := hasPrimaryFactor` over all enrolled factors (`internal/oauth/service.go:1947`) |
| API keys can't authenticate (nil validator) | **Fixed** — minted keys now authenticate |
| `GET /organizations` enumerates every tenant | **Fixed** — org write paths authorized, list scoped |
| Elasticsearch audit search leaks cross-tenant | **Fixed** — ES queries tenant-scoped |
| Preventive SoD broken by column mismatch, fails open | **Fixed** — SoD enforced fail-closed at role-grant *and* request-fulfillment (`SoDViolationError`, `internal/governance/workflows.go`) |
| Certification "revoke" doesn't revoke | **Fixed** — revocation enforced + sessions killed on access-review revoke |
| Reviewer always "admin" | **Fixed** — manager-based reviewer resolution live |
| Campaigns/ABAC tables not org-scoped | **Fixed** — org_id + FORCE RLS (migrations v69–v80) |
| SCIM `filter` ignored | **Fixed** — 786-line filter parser compiled to SQL (`internal/provisioning/scim_filter.go`) |
| One eternal signing key, hardcoded `kid` | **Fixed** — DB-backed rotatable RS256 keys (`oauth_signing_keys`, v79) |
| Five parallel risk engines / two OAuth stacks | **Purged** — dead-code purge landed in v1.25.0 |
| Anomaly detection never invoked | **Wired** — `RunAnomalyCheck` invoked via the identity-service adapter (`cmd/identity-service/main.go:329`) |
| Approval escalation only in dead code | **Wired** — request escalation checker runs (`internal/governance/request.go:413`) |

**Cross-pillar convergence (new since July 10):**
- **Access 360** — one API/console view correlating a user's IAM roles/groups,
  PAM grants/checkouts/live sessions, and Ziti identity/devices/policies
  (`docs/IAM_PAM_ZITI_INTERRELATION.md`).
- **The kill switch** — `POST /api/v1/access/users/:id/kill-switch` severs
  IAM sessions + API keys, PAM checkouts/JIT/live Guacamole sessions, and Ziti
  edge+API sessions (circuits) in one action (`internal/access/kill_switch.go`,
  408 LOC). Device-scoped variant exists.
- **Lifecycle propagation** — disable a user by *any* path (API, SCIM,
  directory sync, DB) and three reconcile layers sever all pillars in ≤30 s.
- **Device correlation** — IAM device trust and Ziti agent compliance linked
  per physical device (migration v80).

**Client wave:**
- **Windows client** — full agent: SSO/PKCE desktop auth, PAM, tray, embedded
  Ziti, IPC, real posture checks (BitLocker/firewall/AV/patch/domain), MSI,
  **Authenticode-signed** with CI pipeline, winget manifest, self-update.
- **Mobile app (Expo/React-Native)** — usernameless passkey login, TOTP +
  step-up, push-MFA approve UI, approvals inbox, My Access, PAM self-service,
  device enrollment + posture, native Ziti module scaffold (Swift + Kotlin).
- **Android agent** (earlier) — MDM/kiosk/remote-support over Ziti.

**PAM wave (v1.26.0–v1.27.0):**
- RDM-parity connection manager (folders/entries/grants/favorites/session
  ledger, org-scoped RLS, migration v81) with brokered *passwordless* launch.
- **Per-connection reach mode `direct` | `ziti`** (v82): guacd dials the target
  over the OpenZiti overlay — the target has *zero inbound exposure*.
- Dedicated dual Guacamole brokers (compose + Helm), per-user broker
  identities (no admin token in the browser), true read-only live monitoring,
  real client IP recorded.

**Ops wave (the 2026-07-14 system-design-review roadmap, items 1–9 executed):**
- Automated Postgres backups + **tested restore**; reboot-safe boot order;
  secret files owner-only; `orgscope` (RLS linter) now a **merge-blocking CI
  gate**; OPA decision cache + circuit breakers + tight timeouts on the hot
  path; Prometheus/SLO/tracing stack shipped; DB pools right-sized;
  **gateway-service retired — APISIX is the sole edge**; audit→ES reconcile +
  webhook lost-nudge recovery (transactional-outbox phase A); **KEK keyring
  (encv2)** so the master encryption key rotates without a flag-day + `cmd/rekey`
  to retire an exposed KEK.

### 2.2 Scale and maturity snapshot (code-measured)

- **~284,000 lines of Go** across 788 files; **324 test files / 2,673 test
  functions**; race-enabled sharded CI, real integration suite (OAuth, MFA,
  step-up, vault, rotation, Guacamole injection, JIT, cross-org), benchmarks,
  CodeQL + govulncheck, 12 GitHub Actions workflows.
- **194 admin-console pages**, each with a co-located test; end-user portal
  (My Access / My Devices / My Privileged Access / app launcher) included.
- **Ziti integration is application code, not config**: `sdk-golang v1.7.0`
  embedded (live `ziti.Context`, service bind/host), controller management API
  driven across 19 endpoint families, desired-state reconciler, user→identity
  sync, BrowZer clientless path **verified end-to-end in a real browser**.
- **Multi-tenancy enforced twice**: app-layer org context + Postgres **FORCE
  row-level security** stamped at pool checkout, with a custom static analyzer
  (`tools/orgscope`) failing the build on any unscoped tenant-table query.
- **Audit**: HMAC-SHA256 hash-chained events (tamper-evident), ES streaming
  with reconcile, compliance report generators (SOC 2 / ISO / GDPR surfaces),
  ISPM + IBDR (identity breach detection & response) modules.

### 2.3 Pillar scorecard (July 21)

| Pillar | July 10 verdict | July 21 verdict | What moved it |
|---|---|---|---|
| **IAM core (IdP/MFA/SCIM)** | Strongest pillar, delivery + HA failures | **GA-grade with caveats** | Step-up + multi-factor challenge + key rotation + SCIM filter fixed; caveats below |
| **IGA** | Real plumbing, broken enforcement | **Near-GA** | SoD fail-closed, enforced revocation, reviewer resolution, org-scoped campaigns, escalation worker |
| **PAM** | Genuinely mature, modern-PAM frontier missing | **GA-grade** | RDM-parity manager, per-user brokers, Ziti reach mode, live monitoring; frontier gaps remain (§7) |
| **ZTNA / Ziti** | Most mature pillar + biggest strategic opening | **GA-grade orchestration** | Kill switch, device correlation, agent enrollment hardening; event ingestion + per-org overlay still open |
| **Risk / ITDR** | Wired core + five dead engines | **MVP+** | Engines consolidated (purge), anomaly detection wired; SSF/CAEP + token-theft detection still open |
| **Platform / ops** | Ahead of docs; two headline defects | **GA-grade** | API keys fixed, org console fixed, backups/observability/KEK rotation/single-edge landed |
| **Clients** | "No companion app" cross-cutting gap | **Windows GA-ish; mobile MVP** | Signed Windows agent + Expo app phases 1–3; iOS/Android store-grade polish outstanding |

### 2.4 What still isn't true (verified remaining landmines)

These survived the sweep — each is a first-demo or first-POC risk and appears
in the refreshed gap register (§7) with a recommendation:

1. **Push MFA delivery still targets Google's decommissioned legacy FCM
   endpoint** (`internal/identity/pushmfa.go:547`) and unauthenticated APNS —
   the mobile app now renders push approvals, but the server can't deliver
   them. *One of the last "advertised but broken" items.*
2. **Magic-link email is still not sent** — the flow builds the link and rate
   limits, but no call into `internal/email` exists in
   `handlers_passwordless.go`.
3. **SAML IdP signing is still hand-rolled** — no `goxmldsig`/`crewjam`
   dependency; no XML canonicalization; inbound assertion signatures not
   verified. SAML SP schema drift was fixed (v83), but the crypto core is
   not standards-credible yet.
4. **No OAuth consent screen** — `require_consent` is not enforced anywhere in
   the live authorize path.
5. **Token Exchange (RFC 8693), DCR (RFC 7591), SSF/CAEP — absent** — the
   token endpoint serves exactly `authorization_code` / `refresh_token` /
   `client_credentials`. The agent-identity and CAE differentiators have no
   substrate yet.
6. **Outbound SCIM client — absent** — OpenIDX can be provisioned *into*, but
   cannot provision *out to* SaaS apps. The single biggest workforce-IAM
   functional gap vs Okta/Entra.
7. **HR-driven JML — absent** (no Workday/BambooHR/SuccessFactors source).
8. **SIEM forwarder (CEF/syslog/HEC) — absent** despite the unified audit
   store being GA-grade.
9. **EDR/MDM posture ingestion — absent** (CrowdStrike/Intune/Jamf).
10. **Ziti fabric events not ingested** into the unified audit pipeline — the
    network pillar is invisible in the SIEM/compliance story.
11. **A mock session helper ships in `internal/oauth/authorize_flow.go:291`**
    (`user-123` hardcoded) — audit says likely unrouted; delete or gate it
    before any pentest.
12. **Voice-call MFA is a stub** (mock Twilio SID).
13. **README still says "Single-tenant by design"** while the platform enforces
    FORCE-RLS multi-tenancy with a CI linter — the repo's front page
    contradicts one of its best engineering facts.
14. **No importers** from Okta/Auth0/Keycloak/AD (users/apps/policies), no
    published benchmarks, no i18n, no SBOM/signed server artifacts, and no
    third-party security attestation (SOC 2 / pentest) — the commercialization
    blockers, not engineering ones (§7.1).

**Bottom line:** the platform crossed the line from *"impressive demo with
landmines"* to *"design-partner-ready product"* in eleven days of focused
work. The remaining risk is concentrated in (a) four auth-delivery/standards
edges (push, magic link, SAML crypto, consent), (b) the outbound-provisioning
hole, and (c) commercialization scaffolding that has nothing to do with code.

---

## 3. The product thesis: set the features over Ziti

### 3.1 Why Ziti-first is the moat

Every identity vendor is bolting *network* onto *identity* (Okta ⇄ ZTNA
partners, Entra Global Secure Access, Zscaler buying identity signals), and
every network vendor is bolting *identity* onto *network* (Tailscale/NetBird
adding SCIM, ZTNA vendors adding posture). OpenIDX starts from the position
they are all converging toward: **the IdP, the policy engine, the PAM broker,
and the overlay network are one codebase over one database.**

The OpenZiti layer is what makes each pillar's promise *physical*:

| Pillar promise | Without Ziti | Over Ziti (OpenIDX today) |
|---|---|---|
| "Deprovisioned means gone" | Tokens expire eventually; VPN session lingers | Ziti identity deleted → live circuits severed ≤30 s (`ziti_user_sync.go` sweep) |
| "Least privilege" | App-level RBAC only | Per-service dial policies; the app is *dark* — no inbound port exists |
| "Privileged session security" | Jump host with standing creds | `reach_mode=ziti`: guacd dials over the overlay; target has zero inbound exposure; credential injected server-side (v82) |
| "Device trust" | UA sniffing / MDM tax | Enrolled agent posture checks bound to service policies; IAM trust ⇄ Ziti compliance correlated per device (v80) |
| "Kill switch" | Revoke token, hope apps re-check | Token + session + **network circuit** severed in one action (`kill_switch.go`) |
| "Clientless access" | VPN portal / RDP gateway | BrowZer: unmodified browser becomes a Ziti endpoint via injected runtime (verified e2e) |

No OSS competitor has this stack: **Keycloak/Zitadel/Authentik stop at the
IdP** (no network plane, no PAM). **NetBird/Tailscale/Twingate/Firezone have
the network** but a thin identity layer and no governance/PAM.
**OpenZiti itself has the fabric but no identity-governance control plane** —
the multi-tenant console, SCIM lifecycle, JIT, and metering are exactly what
NetFoundry monetizes commercially. OpenIDX is positioned to be **the open
control plane of the OpenZiti ecosystem** — the thing the ecosystem
conspicuously lacks — while ALSO being a standalone IAM/IGA/PAM.

### 3.2 What already sits over Ziti (shipped)

1. **Identity mirror** — every OpenIDX user auto-mirrored to a Ziti identity
   (`externalId` = user UUID → OIDC `sub`), groups → role attributes, device
   trust → `#device-trusted` (30 s poller + reconciler).
2. **One-click publishing** — per-route toggles create the Ziti service, bind
   + dial policies, and hosting; desired-state reconciler converges
   controller state from Postgres.
3. **BrowZer clientless** — OpenIDX is the OIDC issuer BrowZer trusts; login
   once, reach dark web apps from an unmodified browser (WSS last mile
   verified end-to-end).
4. **Agent fleet** — Windows (signed, self-updating), Android (MDM/kiosk),
   mobile scaffold; enrollment minted by OpenIDX, posture checks enforced in
   the proxy path.
5. **PAM over the overlay** — brokered SSH/RDP/VNC sessions whose *broker*
   dials the target through Ziti (`reach_mode=ziti`), so privileged targets
   are dark; recordings encrypted, legal holds honored.
6. **Cross-pillar enforcement** — kill switch and lifecycle sweeps that treat
   the network as an enforcement plane, not a separate product.

### 3.3 The "features over Ziti" build order

Priorities chosen for *sales impact per engineering week*, given §2's state:

**Wave A — make the network pillar auditable and tenant-clean (unblocks GTM):**

| # | Feature over Ziti | Why now | Effort |
|---|---|---|---|
| A1 | **Fabric event ingestion** — subscribe to controller circuit/session/posture events, normalize into `unified_audit_events`, index to ES | Completes "one audit trail" — today the network pillar is invisible to SIEM/compliance; also the substrate for metering (A4) and DEM | M |
| A2 | **Per-org overlay scoping** — remove the hardcoded fallback org, namespace Ziti attributes/service names per org, org-RBAC on Ziti passthrough | THE "OSS NetFoundry console" unlock; prerequisite for MSP channel and any multi-tenant SaaS offer | L |
| A3 | **Continuous posture → mid-session revocation** on the tunneler path (posture degrade → delete API sessions via mgmt API) | Turns posture from gate to guarantee; demo: yank disk-encryption → circuit dies live | M |
| A4 | **Usage metering per org/service/identity** from A1's event stream + consumption dashboard | NetFoundry-parity feature; the MSP billing substrate | M |

**Wave B — governance reaches the network (the demo that closes deals, §4):**

| # | Feature over Ziti | Why | Effort |
|---|---|---|---|
| B1 | **JIT network grants** — access-request approval adds a time-bound role attribute to the target service policy; expiry sweeper removes it and kills sessions | "Approve → network exists for 8 h → vanishes" is the single most differentiated demo vs SailPoint+Zscaler stacks | M |
| B2 | **Certification-revoke → policy detach** — extend the enforced-revocation executor to remove Ziti dial attributes and sever circuits | Completes decision-to-packet within the existing campaign engine | S–M |
| B3 | **Step-up on posture/risk change in the access path** — proxy 302s to OAuth with `acr_values=mfa` | The step-up verifier now actually verifies (WS-01), so this is safe to build | M |

**Wave C — modern-PAM and workload features on the fabric:**

| # | Feature over Ziti | Why | Effort |
|---|---|---|---|
| C1 | **`openidx connect` native-client access** — approved session mints a short-lived scoped Ziti identity; local listener lets unmodified `ssh`/`psql`/`kubectl` reach dark targets | Teleport/StrongDM-class UX at zero marginal license cost; reuses JIT + enrollment machinery | L |
| C2 | **Secretless injection at the edge** — vault secret resolved at connect time and injected at the tunneler; client never sees it | Aembit/Conjur-class with no new agent | L |
| C3 | **Workload identity federation** — CI OIDC token (GitHub/GitLab) → ephemeral scoped Ziti identity, TTL-swept | NHI story on the fabric; pairs with RFC 8693 work | M |
| C4 | **EDR/MDM signal ingestion** (CrowdStrike ZTA / Intune compliance) into posture evaluation | Table stakes in enterprise ZTNA evals | M |

**Wave D — the frontier (agents) once RFC 8693 + DCR land:**

| # | Feature over Ziti | Why | Effort |
|---|---|---|---|
| D1 | **MCP / AI-agent gateway** — each agent a Ziti identity; MCP servers published as dark services; per-tool OPA allowlists; every call audited | The 2026 battleground; OpenIDX can do *network-enforced* agent containment, which pure-IdP rivals cannot | L |
| D2 | **SSF/CAEP transmitter + receiver** with Ziti termination as the receiver's actuator | First OSS SSF/CAEP **with native network termination** — the headline capability (§4.4) | L |
| D3 | **K8s fabric subchart + HA controller (Raft) + Terraform provider** | Production posture for platform buyers | L |

Deliberately **not** on the list: SWG/CASB/DLP inline inspection, IoT/OT
discovery, global PoP networks — that is SSE-vendor territory where OpenIDX
cannot win on breadth; consolidation checkboxes only (DNS filtering profile
later).

---

## 4. Governance is the control plane: how it affects IAM, Ziti, and PAM

The question "how does governance affect IAM / Ziti / PAM" has a precise
architectural answer in OpenIDX, and it is the core of the sales story.

### 4.1 The model

**Governance is the decision layer; IAM, PAM, and Ziti are enforcement
planes.** Because all four share one Postgres and one event/sweep fabric, a
governance decision propagates as *writes and reconciles measured in seconds*,
not as connector tickets measured in days:

```
                       ┌───────────────────────────────┐
                       │         GOVERNANCE            │
                       │  access requests + approvals  │
                       │  SoD policies (fail-closed)   │
                       │  certification campaigns      │
                       │  JIT elevation + expiry       │
                       │  lifecycle policies           │
                       └──────┬────────┬────────┬──────┘
                    decides   │        │        │
              ┌───────────────┘        │        └───────────────┐
              ▼                        ▼                        ▼
        ┌──────────┐             ┌──────────┐             ┌──────────┐
        │   IAM    │             │   PAM    │             │   Ziti   │
        │ roles    │             │ vault    │             │ identity │
        │ groups   │             │ grants   │             │ attrs    │
        │ sessions │             │ checkout │             │ policies │
        │ tokens   │             │ sessions │             │ circuits │
        └────┬─────┘             └────┬─────┘             └────┬─────┘
             │      enforcement:      │                        │
             │  session revocation    │  checkout revoke       │  circuit
             │  API-key revoke        │  Guacamole terminate   │  severance
             │  step-up require       │  JIT expiry            │  policy detach
             └────────────┬───────────┴────────────┬───────────┘
                          ▼                        ▼
                 unified_audit_events      kill switch (all pillars, 1 action)
                 (HMAC hash-chained)
```

### 4.2 Governance → IAM (live today)

- **Access request → approval → grant**: multi-step approval chains (per-step
  approvers, fail-closed auto-approve conditions) fulfill role/group/app
  grants inside the same transaction fabric the IdP reads at token issuance.
- **SoD is preventive and fail-closed** at *both* direct role grant and
  request fulfillment (v1.25.0): a conflicting grant is refused, not logged.
- **Certification revoke now revokes**: the grant is deleted *and* live
  sessions are killed — an access review is an enforcement action, not a
  report.
- **JIT elevation** expires by sweeper: elevated roles *and* application
  access disappear on schedule.
- **Lifecycle**: joiner/mover/leaver events (API, SCIM, directory sync)
  propagate through `deprovisionUser` inline plus ≤30 s reconcile sweeps.
- *Still open:* per-app conditional access at issuance, dynamic groups,
  event-driven JML from an HR source (§7).

### 4.3 Governance → PAM (live today)

- **Vault access rides the same request pipeline**: credential checkout can
  require approval; grants are principal-keyed (user | role) so certifying a
  *role* certifies its vault reach.
- **JIT checkout**: time-bound credential leases with one-shot retrieve,
  early return, and sweeper-enforced expiry — revoking the elevation revokes
  the credential.
- **Session policy flags per connection** (`require_approval`, `record_session`,
  `allow_reveal`) enforced at the broker; single-use approvals for session
  launch; recordings encrypted with rotating keys and legal holds.
- **Deprovision/kill switch terminates live privileged sessions** — the only
  place in the market where an access review and a live RDP session share a
  database.
- *Still open:* break-glass accounts, dual-control/exclusivity on checkout,
  ticketing enforcement, privileged-account discovery (§7).

### 4.4 Governance → Ziti (the differentiator — half live, half next)

Live today:
- **Identity-level**: user disabled/deleted (by decision, sweep, or kill
  switch) → Ziti identity deleted → live circuits die. Device-level revoke
  severs one machine across IAM + Ziti.
- **Group/role attributes flow to dial policies** via the sync poller, so
  role revocation already narrows network reach on the next reconcile.
- **Posture policy** gates the proxied request path fail-closed.

Next (Wave B, §3.3): **JIT network grants** (approval → time-bound dial
attribute → sweeper removes + kills sessions) and **certification-revoke →
policy detach**. With those two wires, the claim becomes literal:

> **"A revoke decision doesn't open a ticket. It deletes the grant, kills the
> session, terminates the privileged connection, and severs the network
> circuit — in under 30 seconds, with one hash-chained audit trail."**

SailPoint + CyberArk + Zscaler need three products, two connectors, and a
services engagement to approximate that sentence. It is OpenIDX's whole
architecture speaking. This — not feature-count parity — is what to sell.

### 4.5 What governance still cannot see (honest limits)

- **Third-party app entitlements** — without outbound SCIM + an entitlement
  warehouse, governance governs *OpenIDX-managed* access (incl. network and
  vault), not entitlements living inside Salesforce/GitHub/AWS. This is the
  most consequential IGA gap for mid-market deals (§7).
- **The network pillar's events** — until fabric event ingestion (Wave A1)
  lands, circuit history can't be attached to campaign evidence.
- **HR truth** — joiner/mover/leaver still originates from directory sync or
  API, not the HR system of record.

---

## 5. Market re-analysis (July 2026)

<!-- MARKET DATA SECTION — research agents -->

---

## 6. Competitive position

<!-- COMPETITIVE SECTION — research agents -->

---

## 7. The refreshed gap register

### 7.1 Deal-blockers (commercial, not code)

<!-- FILLED WITH GTM RESEARCH -->

### 7.2 Product gaps that lose deals (P0/P1 remaining)

<!-- FILLED -->

### 7.3 Closed since 2026-07-10

See §2.1 — fourteen of the July 10 register's P0 rows are verified closed.

---

## 8. Go-to-market: the way to sell

<!-- GTM SECTION — research agent 3 + synthesis -->

---

## 9. 12-month commercialization roadmap

<!-- FILLED -->

---

## 10. Risks

<!-- FILLED -->
