# OpenIDX — The Ultimate Unified Identity Platform: Product Plan

> **What this is.** A re-plan of OpenIDX from first principles against the
> 2025–2026 market, aimed at one goal: make OpenIDX the **ultimate unified
> IAM + IGA + PAM + ZTNA platform** — the open, self-hostable product that does
> what Okta + SailPoint + CyberArk + Zscaler do together, at a fraction of the
> cost, and does things *none of them can* because it's one platform.
>
> This document is the **strategy and sequenced roadmap**. Its companion,
> [`MARKET_GAP_ANALYSIS_2026.md`](./MARKET_GAP_ANALYSIS_2026.md), is the
> **detailed per-pillar gap register** (every gap, market evidence, code status,
> and a codebase-specific recommendation) that this plan draws on. Read the
> executive summary here first; use the register as the backlog.
>
> Produced from a skeptical multi-agent audit of the live code plus market
> research across 12 categories. Last refreshed 2026-07-10.

---

## 1. Executive summary

**The finding that reframes everything:** OpenIDX is *far more built than its
docs claim, and far less finished than its feature list claims.* The core is
genuinely strong — a real OAuth2/OIDC provider, adaptive-risk MFA, directory
sync, an envelope-encrypted PAM vault with session brokering and recording, a
real OpenZiti ZTNA plane with clientless access, and end-to-end multitenancy
with FORCE row-level security. But layered over it is a **"hollow layer"**:
features that look shipped but are dead code, unwired engines, or silently
broken. Examples the audit confirmed in the running code:

- Step-up MFA verification **accepts any code** and mints a signed token.
- Admin-configured **risk policies do nothing** (the JSON parser is a no-op).
- **API keys can't authenticate** anywhere (every service passes a nil validator).
- The Ziti **"dial test" never dials** — it returns true if the record exists.
- Push MFA targets **Google's decommissioned FCM endpoint**; magic links have
  **no email delivery**; TOTP secrets are stored **plaintext** while a superior
  AES-encrypted MFA library sits unwired.
- Certification **"revoke" decisions don't revoke**; preventive SoD **fails open**.
- An "AI recommendations" endpoint queries tables that never existed → **HTTP 500**.

**The strategic consequence:** the fastest, highest-leverage path to "ultimate"
does *not* start with new features. It starts with **making the claims true** —
because OpenIDX has, over and over, already written the *good* version of a
capability and left it unwired next to a weaker one that serves production. The
single biggest risk to the whole ambition is a POC pentester or evaluator
discovering the hollow layer; the single biggest accelerator is that most of
Phase 0 is *wiring, not building*.

**The moat, once the claims are true:** OpenIDX is the only platform that owns
the IdP, the session store, the API gateway, **and** the network layer in one
codebase and one Postgres. That makes a class of capabilities a *JOIN or an
event-wire* here that are *multi-vendor integration projects* for everyone else:
a kill-switch from token to packet, certification-to-network revocation, IGA+PAM
in one campaign, free NHI/agent governance, posture-gated auth with no MDM tax.
The plan is built to cash in exactly those seams.

**The three-line roadmap:**
1. **Phase 0 — Make the claims true** (~1 quarter): fix the security holes and
   wire the dead code. Turn the hollow layer solid. Mostly S-effort wiring.
2. **Phase 1 — Match the market** (~2 quarters): close the *missing* table stakes
   and build the four shared foundations that unlock dozens of downstream gaps.
3. **Phase 2–3 — Win on the seams** (ongoing): ship the unified-architecture
   differentiators (CAE token-to-packet, IGA+PAM+ZTNA convergence, NHI/agent
   governance, the OSS OpenZiti console) that no point product can copy.

Running in parallel the whole way: the **cross-cutting programs** (compliance
attestations, connector SDKs, mobile app, licensing clarity, repo hygiene)
without which features don't convert to signed deals.

---

## 2. North Star and positioning

**North Star.** *One open platform that governs every identity — human, machine,
and AI agent — from authentication through authorization to the network packet,
self-hostable and sovereign, at flat infrastructure cost.*

**Positioning against the field:**

| Against… | The wedge |
|---|---|
| **Okta / Entra / Ping** (workforce IAM) | Same SSO + adaptive MFA + lifecycle + governance, but unbundled from per-user SKU stacking and self-hostable for sovereignty. *No "identity tax."* |
| **Keycloak / Zitadel / Authentik** (OSS IdP) | They stop at the IdP. OpenIDX adds IGA, PAM, and a ZTNA network plane — and ships the CAE/universal-logout that every OSS rival lacks. |
| **SailPoint / Saviynt** (IGA) | Governance that reaches into PAM (certify vault access) and the network (revoke = sever circuits) in one campaign and one audit trail — no connector lag. |
| **CyberArk / Teleport / StrongDM** (PAM) | Vault + rotation + session brokering fused with the IdP, so deprovision-to-revoke is instantaneous, and ZSP for the whole workforce at zero incremental license cost. |
| **Zscaler / Cloudflare / Tailscale / NetFoundry** (ZTNA) | The OSS OpenZiti management plane the ecosystem lacks: multi-tenant, delegated-admin, SCIM-driven identity lifecycle, usage metering — plus PAM and IGA in the same console. |

**The one-sentence pitch:** *"Everything Okta, SailPoint, CyberArk, and Zscaler
do — in one open platform, on your own infrastructure, where a single risk
signal revokes the token, kills the session, and severs the network path at
once."*

---

## 3. Design principle: finish the seams before adding surface

The audit found a recurring pattern — **parallel implementations**: two OAuth
stacks, two WebAuthn schemas, five risk engines, a hardened MFA library beside a
plaintext one, dead escalation/JIT/reviewer-resolution code beside thinner wired
paths, a tamper-evident audit chain with no constructor. This is both the
project's biggest liability (tech debt that slows every change, and the source of
the hollow layer) and its biggest opportunity (the *better* version is often
already written and tested).

**Principle: prefer wiring the good code over writing new code; delete the loser
of every parallel pair.** Concretely:
- Every Phase-0 item names the existing-but-unwired implementation to adopt.
- Each adoption is paired with **deleting or quarantining** the duplicate, so the
  two-subsystem drift ends rather than growing a third variant.
- New features are built on **shared foundations** (§5) so the next feature is a
  wire, not a rebuild.

---

## 4. Phase 0 — Make the claims true (the credibility sprint)

**Goal:** every advertised capability either works end-to-end or is honestly
labeled "beta/roadmap." No silent security holes. This is the gate to *any*
competitive demo, POC, or security review. Most of it is S-effort wiring.

Grouped by theme (full detail + file references in the gap register):

### 4a. Close the security holes (do first — these are exploitable)
- **Step-up MFA actually verifies the code** before minting a step-up token
  (`internal/oauth/stepup.go`). Currently a rubber stamp. *Also unblocks PAM
  checkout gating and ZTNA step-up.*
- **API-key authentication** — construct `apikeys.Service` in all 7 service
  mains and pass the real validator to `middleware.AuthWithAPIKey`
  (`internal/common/middleware/middleware.go`). Today every key is rejected.
- **Tenant-isolation bypasses** — strip/re-derive `X-Org-Slug` at APISIX+nginx;
  add org_id to the Elasticsearch audit index + query (cross-tenant leak today).
- **Org enumeration** — gate `GET /organizations` behind the super-admin
  predicate; scope the list for non-admins.
- **`/oauth/authorize` hardening** — derive identity only from the session, never
  a client-supplied `user_id`; remove the unauthenticated dev path.
- **Password-reset token logging** — stop logging raw reset tokens at Info in all
  environments; read the reset URL from settings.

### 4b. Make advertised features actually deliver
- **MFA challenge on any enrolled factor** (not TOTP-only) — a WebAuthn/push/
  SMS-only user must be challenged.
- **Encrypted MFA secrets at rest** — wire the existing AES-GCM `internal/mfa`
  encrypter; lazy-migrate plaintext seeds.
- **HA-safe WebAuthn** — wire the built-and-tested Redis challenge store;
  consolidate the two passkey schemas.
- **Magic-link email delivery** and **working push (FCM HTTP v1 + APNS token
  auth)** — the challenge lifecycles are done; only delivery is missing (push
  also needs the companion app, §8).
- **Admin risk policies apply** — implement the no-op `parseJSON` so configured
  policies actually change login risk; add org_id to `risk_policies`.
- **Anomaly detection wired** — invoke `RunAnomalyCheck` from a leader-gated
  worker so impossible-travel/brute-force alerts populate and auto-lock/auto-block
  fire (the logic is complete; nothing calls it).

### 4c. Make governance decisions have effect
- **Enforced auto-revocation** — a "revoke" in a review/campaign must remove the
  grant (extract the working DELETE from the attestation module into a shared
  executor; also revoke sessions).
- **Preventive SoD** — fix the column-name mismatch so `CheckPolicies` runs and
  fails closed; add it to access-request fulfillment.
- **Multi-tenant governance objects** — add org_id + RLS to campaigns, runs, and
  ABAC (they run under a hardcoded default org today).
- **Real reviewer resolution** — manager/owner instead of always "admin."
- **Stop silent audit-event loss** — fix the mismatched-column INSERTs that drop
  JIT/continuous-verify/Ziti events; add a CI test that every write lands a row.

### 4d. Make the ZTNA plane honest
- **Real overlay dial diagnostics** — actually `Dial()` the service.
- **Ziti event ingestion** — feed the fabric event stream into the (real) unified
  audit + SIEM pipeline; today it returns an empty slice.
- **Temp/vendor access hardening** — route its audit to the real service, enforce
  `require_mfa`, add org_id.

### 4e. Fix the console contract + clean the repo
- **Org/tenant management pages** render (fix the response-shape mismatch).
- **Repo & docs hygiene** — reconcile the contradictory security/tenancy docs,
  delete `team.sh.bak.*` / `update_password.sql` / dead SQL, quarantine the dead
  parallel implementations. OSS adopters read the repo before the product.

**Exit criteria for Phase 0:** a red-team pass over auth, MFA, step-up, SoD, and
tenant isolation finds no silent bypass; every navigation item in the console is
backed by working data; `grep` for "placeholder"/"not production-ready"/"assume
we have only one" in `internal/` returns only honestly-labeled roadmap stubs.

---

## 5. The four shared foundations (build once, unlock dozens)

Before scattering into per-pillar features, build the four pieces of
infrastructure that a *large fraction* of the remaining gaps all depend on.
Sequencing these first turns each downstream feature into a wire.

1. **The identity-event bus** — publish `user.created/updated/disabled/deleted`
   (+ attribute diffs) to a Redis stream from identity, SCIM, and directory-sync
   paths, with leader-gated consumers.
   *Unlocks:* event-driven JML, provisioning-rule execution (birthright roles),
   dynamic/rule-based groups, event-triggered micro-certifications, NHI lifecycle,
   ITDR-to-governance loop. **(IAM P1, IGA P0/P1 ×4, Risk P2.)**

2. **The outbound SCIM 2.0 client + connector framework** — per-app SCIM targets,
   a Redis-queued change worker with retry/circuit-breaker (copy the webhooks
   engine), reconciliation sweep.
   *Unlocks:* workforce lifecycle management, IGA request fulfillment to real
   apps, deprovisioning automation, and the connector-SDK program. **(IAM P0, IGA P1.)**

3. **The SSF/CAEP service (token-to-packet CAE)** — a transmitter emitting CAEP
   events from the Redis revocation pub/sub, and a receiver mapping inbound events
   to `deprovisionUser` + token revocation + Ziti session termination.
   *Unlocks:* the flagship differentiator (first OSS SSF/CAEP), IAM continuous
   access evaluation, ZTNA mid-session revocation, ITDR universal logout, agent
   session revocation. **One implementation, three pillars.** **(IAM P2, ZTNA P2,
   Risk P2.)**

4. **Token Exchange (RFC 8693) + OPA-everywhere enforcement** — add the exchange
   grant (homed in the tested-but-dead `token_flow.go` v2 stack), and make every
   service enforce OPA's `final_allow` (deny-overrides), not just `allow`.
   *Unlocks:* per-app conditional access, ABAC enforcement, workload identity
   federation, conditional access for workloads, agent on-behalf-of chains, MCP
   tool-level authorization. **(IAM P1/P2, Platform P1/P2, all agent gaps.)**

Two more near-foundations worth front-loading because many features hang off
them: the **revocation executor** (real DELETE for grants — a Phase-0 item that
also underpins ITDR clamp-downs) and the **agent identity type + DCR + MCP
profile** (the substrate for every AI-agent gap across all four pillars).

---

## 6. Phase 1 — Match the market (close the missing table stakes)

With the claims true and the foundations laid, close the table-stakes gaps that
are genuinely *missing* (not broken). Highest-leverage first:

**IAM / provisioning**
- Standards-compliant **SAML 2.0 IdP** (goxmldsig, real cert, inbound verification)
  and **generic multi-IdP inbound federation** (drop the Keycloak-hardcoding).
- **SCIM filtering** + honest `ServiceProviderConfig`; route SCIM through the gateway.
- **Event-driven JML** + **HR-driven provisioning** (BambooHR/Workday first) on the event bus.
- **Signing-key rotation**, **back-channel logout**, **enforced consent**,
  **custom-claims/federation-rule consumption** — all mostly wiring existing code.
- **Dynamic groups** and **per-app conditional access** on the OPA foundation.
- **Passkey assurance policies** (AAGUID allowlist, synced vs device-bound tiers).

**IGA**
- **Detective SoD scanning** + violation dashboard; **escalation/reminder workers**;
  **entitlement warehouse** (source-account aggregation, correlation, orphans);
  **birthright/attribute provisioning** on the event bus.
- **Certification decision support** (recommendations, dormancy flags, bulk-approve
  low-risk) — cheap and hugely demo-visible.
- **Non-employee governance**, **identity risk-weighted certs**, **Slack/Teams +
  actionable-email approvals**.

**PAM**
- **Break-glass**, **privileged-account discovery + auto-onboarding**, **enforced
  step-up at checkout**, **checkout exclusivity + dual-control**, **encrypted
  tamper-evident recordings**, **SIEM/CEF forwarder**, **connector-breadth SDK**
  (seed MSSQL/Oracle/MongoDB/Redis/network-SSH), **ChatOps + ticketing**.

**ZTNA**
- **Continuous posture w/ mid-session revocation** on the tunneler path; **UDP/
  arbitrary-protocol publishing**; **Windows posture parity**; **EDR/MDM signal
  ingestion**; **JIT network grants** wired to governance; **production K8s Ziti
  fabric + HA control plane**.

**Risk / Platform**
- **UEBA baselines** (write and use them); **session/token-theft detection**;
  **MFA-fatigue detection**; **consolidate the five risk engines**; **geo-IP
  hardening**.
- **Helm production parity**; **workload identity federation**; **short-lived/JIT
  dynamic credentials**; **complete DR** (real scheduled backups, ES snapshots,
  restore drills); **Terraform provider + declarative bootstrap**; **i18n**.

**Exit criteria for Phase 1:** OpenIDX passes a feature-by-feature table-stakes
comparison against Okta/Keycloak (IAM), SailPoint/Entra Governance (IGA),
CyberArk/Teleport (PAM), and Zscaler/NetFoundry (ZTNA) with no "missing" in the
table-stakes column — only in the differentiator column.

---

## 7. Phase 2–3 — Win on the seams (the unified-architecture differentiators)

These are the reasons OpenIDX exists as one platform. Each is a JOIN or an
event-wire here and a multi-vendor project for competitors. Sequence by market
pull:

**Phase 2 — the convergence story (12–18 months out)**
- **Token-to-packet CAE / universal logout** (on the SSF/CAEP foundation) — the
  headline nobody else can ship: one risk event revokes token + session + network
  circuit. *Be the first OSS SSF/CAEP implementation.*
- **Certification-to-network revocation** and **ITDR-to-governance closed loop** —
  detections auto-fire scoped reviews and clamp-downs; revoke decisions sever
  circuits in seconds.
- **IGA+PAM in one campaign** — certify vault access, JIT credentials, and
  standing roles together with session-recording evidence attached.
- **Ephemeral SSH certs + native-client access** (`openidx connect`) over the Ziti
  fabric — Teleport/StrongDM ZSP at zero marginal license cost.
- **Secretless credential injection at the Ziti edge** — Aembit/Conjur-class,
  no new agent.
- **The OSS OpenZiti console** — finish per-org Ziti scoping + delegated admin +
  usage metering; become the multi-tenant management plane NetFoundry sells.
- **PIM-style role eligibility** and **ZSP for the whole workforce**.
- **Identity attack-path graph** (recursive CTEs over the unified store) —
  BeyondTrust True Privilege as a query.

**Phase 3 — the frontier (the 2026+ battleground)**
- **AI-agent identity as a first-class principal across all four pillars** — DCR +
  CIMD, MCP authorization server, agent OAuth (on-behalf-of via token exchange),
  agent governance (certification), agent privileged access (vault + JIT), agent
  network identity (Ziti + MCP gateway), agent risk scoring. Built once on the
  agent-identity + token-exchange + OPA foundations, exposed everywhere.
- **NHI inventory + governance** — discover external service accounts / cloud IAM
  / OAuth grants / K8s SAs; certify them alongside humans in one campaign. Give
  away what SailPoint sells as per-identity Machine Identity.
- **SPIFFE-compatible workload identity + federation**; **secret scanning with
  liveness** (uniquely powerful because OpenIDX holds the hashes of keys it minted);
  **cloud-vault federation**; **DB/K8s session brokering**; **AI session
  summaries**; **NL admin copilot + platform MCP server**.
- **Verifiable credentials (eIDAS/EUDI)** and **identity verification at recovery**
  (deepfake defense) — European-tender and Scattered-Spider-response differentiators.

---

## 8. Cross-cutting programs (run in parallel from day one)

Features don't convert to signed deals without these. They are not a phase; they
are continuous tracks.

- **Compliance & certification program.** SOC 2 Type II → ISO 27001 → FIPS 140-3
  → FedRAMP roadmap. Map controls, and turn the audit service into an
  *evidence generator about OpenIDX itself*. This is the real gate to the
  regulated/sovereign deals where the self-host story is strongest. Add a
  pentest + bug-bounty and publish results.
- **Connector ecosystem.** Ship stable SDKs (rotator, SCIM target, HR source, EDR,
  NHI) with the existing test harnesses as templates; build a community
  marketplace; seed the top 20–30 integrations and an SSO template gallery.
  Connector depth is a raw-count RFP row and the IGA technical knockout.
- **Migration tooling.** Importers from Okta, Auth0, Keycloak, AD, and CyberArk
  (users, groups, apps, policies, passkeys via CXF, vault secrets). This is the
  wedge that converts the cost story into displacement deals.
- **Mobile + agent packaging.** An iOS/Android **authenticator app** (push
  approve, TOTP, passkey, QR — this is what unblocks push MFA properly), unified
  signed desktop clients with an auto-update channel, and SBOM + cosign/SLSA
  signed releases (supply-chain trust for a security product).
- **Licensing & open-core clarity.** Pick and *document* a permissive,
  foundation-friendly license posture and an explicit open-core boundary (what, if
  anything, is commercial). The market's AGPL/BUSL turbulence is a tailwind only
  if OpenIDX's posture is unambiguous.
- **Docs, community, benchmarks, a11y, offline mode.** Reconcile and modernize the
  docs (the audit found them the least reliable artifact); publish reproducible
  performance benchmarks (and find the single-Postgres scale ceiling before a
  customer does); a WCAG pass on the console; an "air-gap mode" that swaps in
  bundled MaxMind/breach-lists/self-hosted push.

---

## 9. Sequencing logic (the dependency spine)

The order is not by pillar — it's by dependency. Build the spine, then hang
features off it:

```
Phase 0 (wire the good code, fix the holes)
   └─ revocation executor ─────────────┐
   └─ step-up verify fix ──────────────┤
                                        ▼
Phase 1 foundations                unlocks: PAM checkout gating, ITDR clamp-down,
   ├─ identity-event bus ───────────► JML, birthright roles, dynamic groups,
   │                                  micro-certs, NHI lifecycle
   ├─ outbound SCIM + connector fw ─► lifecycle mgmt, IGA fulfillment, marketplace
   ├─ SSF/CAEP service ────────────► token-to-packet CAE, ZTNA mid-session revoke,
   │                                  universal logout, agent session revoke
   └─ token-exchange + OPA-enforce ► per-app CA, ABAC, workload federation,
                                      agent on-behalf-of, MCP tool authZ
                                        ▼
Phase 2 (the seams: convergence differentiators)
                                        ▼
Phase 3 (frontier: agents, NHI, SPIFFE, VC)
```

Two rules keep this honest: (1) **no new parallel implementations** — every build
adopts or extends an existing subsystem and deletes the loser; (2) **the
cross-cutting programs advance every phase**, because a certified, importable,
well-documented "good-enough everywhere" beats an uncertified,
un-migratable "best-in-class in one pillar."

---

## 10. Success metrics

- **Credibility (Phase 0):** zero silent auth/MFA/SoD/tenant bypasses in a
  red-team pass; 100% of console nav items backed by working data; no "AI"/
  diagnostic endpoint returns 500 or a fabricated success.
- **Parity (Phase 1):** "missing" appears only in the *differentiator* column of
  a head-to-head vs Okta/Keycloak/SailPoint/CyberArk/Zscaler/NetFoundry.
- **Differentiation (Phase 2–3):** demonstrable token→session→network revocation
  from a single event in <1s; one access-review campaign certifying human roles,
  vault access, and agent identities together; the OSS OpenZiti console running a
  multi-tenant, delegated-admin, metered deployment.
- **Adoption (cross-cutting):** SOC 2 Type II achieved; ≥30 seeded connectors + a
  community marketplace; working importers for ≥3 incumbents; signed mobile +
  desktop clients with auto-update; an unambiguous published license posture.
- **Cost proof:** a published TCO comparison showing flat infrastructure cost vs
  per-user/per-identity/per-MAU stacking, with ephemeral agents/CI/pods at zero
  marginal cost.

---

## 11. Risks and mitigations

| Risk | Why it's real | Mitigation |
|---|---|---|
| **The hollow layer detonates in a POC** | A pentester finding rubber-stamp step-up or fail-open SoD destroys trust permanently | Phase 0 is the gate to *any* external evaluation; nothing ships to a prospect until §4 exit criteria are met |
| **Breadth beats depth into mediocrity** | Matching CyberArk *and* SailPoint *and* Zscaler risks being "jack of all trades" | Lead with the *convergence* story and "good-enough + certified" per pillar; be *exceptional only on the seams* no one else can build; defer depth plays (ERP SoD, full IoT/OT, Windows PEDM) explicitly |
| **Parallel-implementation debt compounds** | Five risk engines / two OAuth stacks already slow every change and cause the hollow layer | The "no new parallel impls; delete the loser" rule is enforced per PR; Phase 0 explicitly consolidates |
| **No compliance attestations = locked out of the best deals** | The sovereignty story is strongest in regulated/public-sector, which *require* SOC2/ISO/FedRAMP | Start the compliance program in parallel with Phase 0, not after features are "done" |
| **Single Postgres is both the moat and the ceiling** | The unified store enables the JOINs *and* caps scale / concentrates blast radius | Publish benchmarks early to find the ceiling; design read-replica/sharding escape hatches; keep the RLS belt + backups as the blast-radius control |
| **Open-source monetization stays undefined** | Ambiguity stalls OEM/ISV/procurement adoption and starves the project | Decide and publish the open-core boundary as part of the licensing track; don't let it drift |
| **AI-agent frontier moves faster than we ship** | Every leader shipped agent identity in 2025–26; standards (MCP, XAA/ID-JAG) are settling now | Build the agent substrate (identity type + token exchange + OPA + MCP) as a *foundation* in Phase 1 so agent features across all pillars are wires in Phase 3, not a scramble |

---

## 12. Where to start tomorrow

The first two weeks, in order, all from the gap register with file references:

1. **Fix step-up verification** (security hole, and unblocks PAM/ZTNA step-up).
2. **Wire API-key authentication** (a whole advertised credential type is dead).
3. **Implement the risk-policy `parseJSON` no-op** + add org_id to `risk_policies`
   (admin policies silently do nothing today).
4. **MFA challenge on any enrolled factor** + **encrypted MFA secrets** (wire the
   existing `internal/mfa` library).
5. **Enforced auto-revocation + preventive-SoD column fix** (governance decisions
   that currently have no effect).
6. **Real Ziti dial diagnostics + event ingestion** (remove the demo-killers).
7. **Repo/docs hygiene PR** (reconcile the contradictory security docs, delete the
   committed backups and dead SQL).

Every one of these is small, most are wiring existing tested code, and together
they convert OpenIDX from "impressive-looking demo with landmines" into "a
platform you can safely put in front of a security team" — the prerequisite for
everything else in this plan.
