# OpenIDX Market Gap Analysis 2026 — IAM · IGA · PAM · ZTNA

> **Purpose.** This is the reference register behind
> [`ULTIMATE_PRODUCT_PLAN.md`](./ULTIMATE_PRODUCT_PLAN.md). It records, per
> pillar, what the 2025–2026 market leaders ship, where OpenIDX actually
> stands (from a skeptical read of the live code — **not** the older docs,
> several of which overstate maturity), and a concrete, codebase-specific
> recommendation for each gap.
>
> **Method.** Produced by a multi-agent audit: 10 subsystem code auditors
> reading `internal/`, `cmd/`, `web/`, and `migrations/`; 12 market-research
> agents covering workforce IAM, CIAM/OSS IdPs, IGA, traditional PAM, cloud
> PAM, enterprise ZTNA/SSE, mesh ZTNA, the OpenZiti ecosystem, ITDR/ISPM,
> non-human identity, MFA/passwordless, and AI-agent identity; and 6 pillar
> gap synthesizers. Maturity labels are the auditors' verdicts against the
> running code.
>
> **Priority key.**
> - **P0** — table stakes we lack or that are *silently broken*. Credibility
>   blockers; several are security holes. Fix before any competitive demo.
> - **P1** — needed to win deals against the named leaders.
> - **P2** — differentiator opportunities where the unified architecture lets
>   us leapfrog point products.
> - **P3** — nice to have / long-horizon.
>
> **Effort key.** S ≈ ≤1 wk · M ≈ 1–3 wk · L ≈ 1–2 mo · XL ≈ quarter+.
>
> Last refreshed: 2026-07-10.

---

## Table of Contents

1. [The one-paragraph truth](#the-one-paragraph-truth)
2. [Market landscape at a glance](#market-landscape-at-a-glance)
3. [Pillar 1 — IAM core](#pillar-1--iam-core-authn-mfa-federation-directory--provisioning)
4. [Pillar 2 — Identity Governance (IGA)](#pillar-2--identity-governance-iga)
5. [Pillar 3 — PAM](#pillar-3--pam-vault-rotation-sessions-jit-infrastructure-access)
6. [Pillar 4 — ZTNA / OpenZiti](#pillar-4--ztna--openziti-network-access)
7. [Pillar 5 — Risk, ITDR & AI-era identity](#pillar-5--risk-itdr--ai-era-identity)
8. [Pillar 6 — Platform, NHI & operations](#pillar-6--platform-nhi--operations)
9. [Cross-cutting gaps (the completeness critique)](#cross-cutting-gaps-the-completeness-critique)
10. [Unfair advantages of the unified architecture](#unfair-advantages-of-the-unified-architecture)

---

## The one-paragraph truth

OpenIDX is **far more built than its own docs suggest, and far less finished
than its feature list suggests.** The core is real and often excellent: a
production OAuth2/OIDC provider with PKCE and refresh rotation; TOTP/SMS/email
MFA with a live adaptive-risk engine; LDAP/AD + Azure AD directory sync; an
envelope-encrypted PAM vault with eight rotation connectors (incl. AWS/GCP) and
Guacamole SSH/RDP/VNC brokering with recording and legal holds; a genuine
OpenZiti ZTNA plane with a desired-state reconciler, BrowZer clientless access,
posture enforcement, and desktop + Android agents; and end-to-end multitenancy
with FORCE row-level security policed by a custom CI linter. **But layered over
that core is a large "hollow layer"** — features that look shipped but are dead
code, unwired engines, or silently broken. The gap analysis below separates the
two ruthlessly, because the single biggest threat to the "ultimate product"
ambition is not a missing feature — it is a POC pentester discovering that
step-up MFA rubber-stamps any code, that admin-configured risk policies do
nothing, or that the "AI recommendations" endpoint returns HTTP 500.

---

## Market landscape at a glance

What every serious product in the category now ships (table stakes), and where
the 2026 battle is being fought (differentiators), distilled from the 12
market reports.

| Category | 2026 table stakes you must match | Where the deals are won in 2026 |
|---|---|---|
| **Workforce IAM** | SAML+OIDC SSO, universal directory w/ AD sync, adaptive MFA, passkeys, SCIM in/out, HR-driven JML, conditional access, delegated admin, SIEM streaming | CAE/continuous access eval, AI-agent identity (Entra Agent ID, Okta XAA), converged PAM+IGA+ITDR "identity fabric", posture-as-auth (FastPass), GenAI admin copilots |
| **CIAM / OSS IdP** | Certified OIDC + OAuth 2.1 hygiene, SAML SP+IdP, passkeys, brokering to social/enterprise IdPs, B2B orgs, SCIM, hosted themeable login, token exchange (RFC 8693), i18n | ReBAC/Zanzibar authZ, agent identity (Auth0 Token Vault, MCP auth), event-sourced audit, FAPI 2.0/DPoP, verifiable credentials (eIDAS), permissive-license + sovereignty |
| **IGA** | HR-driven JML, certification campaigns w/ auto-revoke, access-request catalog w/ approvals, SCIM+connectors, entitlement warehouse, role model, **preventive + detective SoD**, risk-scored certs, audit evidence, non-employee governance | Agentic copilots (Harbor Pilot, Savi), NHI/machine-identity governance, AI-agent governance, ML role mining, outlier detection, ISPM, ITDR-to-governance loop, ERP SoD depth |
| **Traditional PAM** | Encrypted vault w/ check-out + dual-control, auto password rotation (300+ connectors), SSH-key vaulting, session brokering w/ credential injection, full session recording, privileged-account discovery, JIT + ticketing, PEDM, break-glass, HA/DR | Ephemeral SSH certs / ZSP, cloud-vault federation (Secrets Hub), machine-identity/CLM (Venafi), attack-path graphing, AI-agent privilege controls, runtime per-action authZ (StrongDM) |
| **Cloud PAM / infra access** | IdP-federated SSO, short-lived auto-expiring creds, JIT + ChatOps, protocol-aware proxy (SSH/K8s/DB), session recording, reverse-tunnel connectors, native-CLI compat, Terraform | Fully secretless SSH-CA (Teleport), SPIFFE workload identity, transparent sessions, query-level DB authZ, device trust w/ TPM attestation, AI-agent/MCP access, moderated sessions |
| **Enterprise ZTNA / SSE** | Inside-out connectors, per-app brokering, SAML/OIDC + SCIM, device posture at connect, EDR-fed risk posture, continuous re-eval, clientless browser access, bundled SWG/CASB/DLP, global PoPs | AI app-segmentation, enterprise browser, ZTNA 2.0 inline inspection, universal ZTNA (NAC replacement), IoT/OT, agentic-AI access security, sovereign/self-hosted SASE |
| **Mesh ZTNA** | WireGuard transport, NAT traversal, outbound connectors, IdP+SCIM, default-deny ACLs, device posture + EDR signals, cross-platform clients, private DNS, ephemeral auth keys, Terraform+operator, free tier | P2P mesh, fully-OSS control plane (NetBird), SSH recording, ephemeral certs, clientless browser terminals, per-request CAE, K8s PAM, agentic-AI (MCP portals), post-quantum, workload identity federation |
| **OpenZiti ecosystem** | Identity-based dark services, mTLS+E2E, OIDC/PKCE, full tunneler matrix, continuous posture, HA control plane (v2.0 Raft), all-protocol, ZAC console + CLI + API, IaC, Prometheus | **The NetFoundry gaps OpenIDX can own:** no-code multi-tenant console w/ delegated RBAC, SCIM→Ziti identity lifecycle, JIT/NHI, usage metering/chargeback, compliance envelope (SOC2/FIPS/PQ), MCP/agent gateway |
| **ITDR / ISPM** | AD attack detections, hybrid AD+cloud correlation, posture scoring, UEBA identity risk score, lateral-movement paths, NHI discovery, MFA-gap analysis, leaked-cred detection, MFA-fatigue detection, AiTM detection, automated response, SIEM/SOAR, MITRE mapping | Inline runtime enforcement (Silverfort), auth firewall, session-token-theft detection, browser-native detection (Push), SSF/CAEP + universal logout, JIT fused into ITDR, AI-agent discovery, deception |
| **Non-human identity** | Agentless NHI discovery, posture/risk scoring, ownership attribution, lifecycle workflows, short-lived issuance, OIDC workload federation, K8s attestation, secret scanning w/ liveness, vault integrations, X.509/mTLS, compliance mapping | Secretless brokering (Aembit), SPIFFE/SPIRE attestation, MCP authZ server, blended identity (agent↔human), AI ownership discovery, NHI ITDR, SaaS-OAuth-grant governance, 47-day cert automation |
| **MFA / passwordless** | FIDO2/WebAuthn passkeys (roaming+platform), synced vs device-bound policy, AAGUID allowlisting, hardened push (number matching), adaptive auth, device posture at auth, protocol breadth, self-service enrollment, AAL2/AAL3 mapping | Session-token-theft protection (Duo Passport), BLE proximity, device-bound "invisible MFA" (Beyond Identity), continuous auth w/ EDR, identity verification at recovery (deepfake defense), passkey portability (CXF), SSF/CAEP, DBSC |
| **AI-agent identity** | OAuth 2.1 AS for MCP (PKCE, RFC 8707/9728), dynamic client registration + CIMD, agents as first-class identity type, delegated authZ preserving human principal (RFC 8693), token vault, short-lived scoped agent creds, HITL approval (CIBA), consent + kill switch, SIEM audit | Cross App Access / ID-JAG (Okta), agent blueprints (Entra), CA + risk for agents, shadow-agent discovery, FGA-for-RAG, NL admin copilots + vendor MCP server, verifiable agent credentials |

**Pricing reality (why the cost story lands).** Every category is priced
per-user/per-identity/per-MAU with heavy SKU stacking, and every category has a
loud buyer revolt: Okta mid-market realistically $18–25/user/mo with governance
SKUs costing nearly as much as the base; Auth0 documented 15× bill growth on
1.67× user growth; CyberArk $1.8k–12k/user/yr quote-only; Teleport per-resource
metering punishes autoscaling and restricts Community Edition; NHI vendors price
per-identity as machine:human ratios hit 50–82:1. A genuinely open,
self-hostable, flat-cost unified platform is aimed straight at this pain — but
only if the features it advertises actually work.

---

## Pillar 1 — IAM core (authn, MFA, federation, directory & provisioning)

**Current maturity:** the strongest pillar. Password/LDAP auth with lockout,
Postgres sessions with policy timeouts and a leader-gated expiry worker,
TOTP/SMS/email OTP MFA, adaptive risk MFA, step-up, trusted browsers, device
trust, hardware tokens, and a real OAuth2/OIDC provider are all genuinely
production. The failures cluster in **delivery** (push/magic-link never reach
the user), **HA-safety** (in-memory WebAuthn store), **SAML correctness**, and
**a shadow hardened `internal/mfa` package that is better than the production
path but wired into nothing.**

| Pri | Effort | Gap | Market evidence | OpenIDX status | Recommendation |
|---|---|---|---|---|---|
| P0 | S | **MFA challenge aware of all enrolled factors** | Every leader challenges on any enrolled factor | `internal/oauth/service.go:1882` sets `mfaEnabled := totpStatus.Enabled` — a WebAuthn/push/SMS-only user bypasses MFA on password login | Query the `user_mfa_methods` view `stepup.go` already uses; challenge if *any* factor enrolled. Offer-plumbing already exists at `service.go:1890` |
| P0 | S | **Encrypted MFA secrets at rest** | Unstated baseline; a SOC2/ISO item | TOTP seed stored **plaintext** (`service.go:2033`) while `internal/mfa` ships AES-256-GCM, replay prevention, constant-time compare — wired into nothing | Wire `internal/mfa`'s encrypter into `EnrollTOTP`/`VerifyTOTP`; lazy-migrate plaintext on next verify; retire the duplicate impl |
| P0 | S | **Magic-link email delivery** | Standard across Auth0/FusionAuth/Zitadel/Authentik; marketed by OpenIDX itself | Token generation solid, but **no email send exists** — token only appears in a dev log or a test endpoint | Add a magic-link template to `internal/email`, call the already-wired `SendAsync`; make base URL an org setting; delete the token-in-response test endpoint |
| P0 | M | **Working push MFA delivery** | Push w/ number matching is table stakes (Okta Verify, MS Authenticator, Duo) | Challenge lifecycle complete, but delivery hits **Google's dead FCM legacy endpoint** (`pushmfa.go:547`) and **unauthenticated APNS** | Migrate to FCM HTTP v1 (`x/oauth2/google`) + APNS provider-token (ES256 JWT); store creds via `secretcrypt` w/ hot reload. **Requires a companion mobile app** (see cross-cutting) |
| P0 | M | **HA-safe WebAuthn + unified passkey schema** | Passkeys are first-class login everywhere; leaders run multi-replica | Challenge sessions in an in-memory `sync.Map` w/ "not production-ready" comments (`webauthn.go:633`); two overlapping schemas; `EnableWebAuthnOnlyLogin` counts the wrong table | Wire the already-built Redis WebAuthn store from `internal/mfa/webauthn_store.go`; consolidate on `mfa_webauthn`; fix `passwordless.go:449` |
| P0 | M | **Standards-compliant SAML 2.0 IdP** | SAML SP+IdP is table stakes for enterprise app onboarding | Signatures hand-rolled with string manipulation, **no XML canonicalization**, no `xmldsig` dep; metadata publishes a bare public key as the cert; **inbound signatures never verified**; `/saml/*` not routed in APISIX | Adopt `github.com/russellhaering/goxmldsig`; generate a real X.509 at first boot; verify inbound against stored SP certs; add the APISIX route |
| P0 | M | **SCIM 2.0 filtering + honest ServiceProviderConfig** | Okta/Entra issue `userName eq` filters to match users on import; ignoring it mis-links identities | `filter` param accepted but **never applied to SQL**; `ServiceProviderConfig` advertises filter/sort/changePassword that don't exist | Minimal filter parser (`eq/co/sw` on userName/externalId/emails) → parameterized WHERE; return `externalId`; set unsupported caps to `false`; route `/scim/v2` in APISIX |
| P0 | S | **Password-reset hardening + wire HIBP/history** | Breached-password checks are CIAM table stakes | Raw reset token **logged at Info in all envs**; reset URL hardcoded `localhost:3000`; HIBP + password-history exist with **zero callers** | Gate/remove the log; read base URL from settings; call the existing HIBP k-anonymity + history checks from reset/change/create |
| P0 | L | **Outbound SCIM 2.0 client** | Core of workforce-IAM lifecycle value (Okta LCM, Entra provisioning) | Provisioning service is **inbound-only**; no SCIM HTTP client exists | New `internal/provisioning/outbound`: per-app SCIM target config on the applications registry, Redis-queued change events w/ retry, reconciliation sweep reusing the directory-sync leader pattern |
| P0 | M | **Generic multi-IdP inbound federation** | IdP brokering for B2B + migration coexistence is table stakes | Upstream endpoints **hardcoded to Keycloak paths**; callback assumes exactly one IdP (`"assume we have only one IdP"`) | Fetch/cache each IdP's `/.well-known/openid-configuration`; carry `idp_id` through OAuth state; add inbound SAML SP reusing the `goxmldsig` work |
| P1 | L | **Event-driven lifecycle engine (JML)** | Rule/event-triggered lifecycle is table stakes (even free Keycloak 26.6 ships Workflows) | Lifecycle workflows run **manual `POST /execute` only**; `RequireApproval`/`Conditions` stored but ignored; `provisioning_rules` have CRUD+UI but **no engine** | Publish `user.*` events to a Redis stream from identity/SCIM/directory paths; leader-gated consumer in provisioning-service (finally justifying its name) evaluates rules via OPA and executes actions |
| P1 | L | **HR-driven provisioning (Workday/BambooHR/…)** | HR-as-source-of-truth JML is table stakes; "where does the joiner record come from" is a first-call qualifier | Docs diagrams only; zero Go code | Model HR sources as a new `internal/directory` connector type (scheduler/watermark/UI generalize cleanly); start BambooHR + Workday RaaS |
| P1 | M | **OAuth authorize hardening + enforced consent** | A consent step is baseline OIDC behavior | `ConsentManager` (561 lines) never constructed; live `/oauth/authorize` has **no consent** and **trusts a client-supplied `user_id`, unauthenticated in dev** | Derive identity only from the `flowAuth` session; wire the existing `ConsentManager` gated by `application_sso_settings.require_consent`; add a consent screen |
| P1 | M | **Signing-key rotation w/ kid-matched JWKS** | Overlapping-key rotation is standard hygiene | `KeyManager` (677 lines, tested) never called; live path serves one eternal key w/ hardcoded `kid` | Wire `KeyManager` w/ a leader-gated schedule; serve multi-key JWKS; fix SCIM middleware to match `kid` instead of first RSA key |
| P1 | M | **OIDC back-channel logout emitter** | Table stakes in the OSS cohort; substrate for universal logout | Discovery advertises `backchannel_logout_supported:true`, column exists, but **zero emitter code** | Enqueue signed logout tokens to registered URIs on session termination; validate `post_logout_redirect_uri`; until shipped, set the flag `false` |
| P1 | M | **OAuth 2.0 Token Exchange (RFC 8693)** | Table stakes in the 2026 OSS cohort; substrate for agent on-behalf-of | Token endpoint supports only `authorization_code`/`refresh_token`/`client_credentials`; no RFC 8693 | Add the grant, homed in the dead-but-tested `token_flow.go` v2 stack (which enforces grant types/scopes the live handler doesn't); support `act` delegation gated by OPA |
| P1 | M | **Per-app conditional access** | CA per app is table stakes (Entra, Okta app policies, Duo) | Risk MFA is real but **org-global**; `application_sso_settings` stored but never read at issuance | App-policy step in `handleAuthorize` composing risk + trusted-browser + device-trust + group via OPA; honor per-app token lifetimes |
| P1 | M | **Passkey assurance policies** | Entra Passkey Profiles, NIST 800-63-4 synced=AAL2 / device-bound=AAL3 | `biometric.go` persists policies but `GetApplicableBiometricPolicy`/`ValidateAuthenticatorForPolicy` are never called | Enforce at registration (AAGUID allowlist, require attestation); record backup-eligible/state to distinguish synced vs device-bound; require device-bound for admins |
| P1 | M | **Dynamic/rule-based groups** | Okta group rules, Entra dynamic groups | Groups are static CRUD; portal even falls back to showing *all* apps when a user has none assigned | Rule expression compiled to SQL (or OPA); re-evaluate on user-change events + nightly sweep; drive app assignment from membership |
| P1 | S | **Consume custom claims + federation rules** | Claim mapping per app is table stakes everywhere | Full CRUD/UI/migrations exist but `custom_claims_mappings`/`federation_rules` are **referenced nowhere at issuance** | Load per-client claim mappings in `GenerateIDToken`/`handleUserInfo`; apply federation rules for home-realm routing. Pure wiring |
| P1 | S | **Directory-sync incremental correctness** | Okta AD Agent/Entra Connect do true incremental + immediate disable | LDAP watermark **read but never written** (every "incremental" run refetches all); Azure `@removed` unhandled; `accountEnabled=false` not applied | Persist max watermark; handle `@removed`; map disable; call the SCIM deprovision path so directory offboarding cuts live sessions |
| P2 | L | **CAE: SSF/CAEP transmitter + receiver + universal logout** | The defining 2026 differentiator; explicitly a gap in every OSS rival | Missing, but foundations exist (Redis revocation markers, SCIM kills sessions, Ziti can sever network) | Small Go service emitting CAEP events from the Redis revocation pub/sub + a receiver mapping inbound events to `deprovisionUser` + Ziti termination. **First OSS SSF/CAEP = headline** |
| P2 | L | **Device posture-gated authentication** | Table stakes in device-trust (Duo Premier 3×, Okta Device Assurance) | No posture as an auth signal, though OpenZiti's native posture checks sit unused for this | Surface OpenZiti posture results into `adaptive_mfa.go` risk + per-app OPA policy; lightweight browser-extension posture for clientless. **Undercuts Duo Premier's main upsell** |
| P2 | L | **AI-agent identity (registry, MCP AS, agent OAuth)** | The 2026 battleground (Entra Agent ID, Okta XAA, Keycloak MCP) | No DCR, no agent type, no MCP | RFC 7591 DCR w/ policy-gated approval, `agent` client type w/ human-sponsor link, token exchange, MCP profile w/ APISIX as data plane + OPA guardrails |
| P2 | XL | **Legacy protocol bridging (LDAP + RADIUS front-ends)** | Table stakes in workforce IAM; why Authentik wins homelab→mid-market | Consumes LDAP but cannot *serve* LDAP/RADIUS | New `cmd/` "outpost" binary speaking LDAP bind/search + RADIUS (PAP/EAP-TTLS) backed by the identity API, distributed as a Ziti-enrolled edge container |

---

## Pillar 2 — Identity Governance (IGA)

**Current maturity:** substantially real — a dedicated governance service with
access reviews, scheduled certification campaigns, a typed policy engine
enforced fail-closed at the ZTNA proxy, access-request/approval/fulfillment, an
entitlement catalog, and an attestation module. **The honesty gaps are in
enforcement, not plumbing:** "revoke" decisions mostly don't revoke, preventive
SoD is broken by a column-name mismatch, and a striking amount of the richest
logic (escalation, reviewer resolution, JIT elevation) lives in **dead parallel
implementations** while the wired path is thinner.

| Pri | Effort | Gap | OpenIDX status | Recommendation |
|---|---|---|---|---|
| P0 | M | **Enforced auto-revocation on certification deny** | `SubmitReviewDecision`/`BatchSubmitDecisions`/campaign auto-revoke only set `decision='revoked'` — **the grant is not removed**; real deletion only lives in the attestation module + dead code | Extract the working DELETE logic into a shared revocation executor (role/group/app/vault), call it from all three paths, write schema-correct audit events, publish a Redis revoked-session marker |
| P0 | S | **Working preventive SoD at assignment/request** | `CheckPolicies` selects `pr.condition/pr.effect` but the schema has `conditions/actions` — query errors and **deliberately fails open**; SoD has never enforced at assignment | Fix column names, fail closed, add the check to `handleCreateAccessRequest`/`fulfillRequest`; regression test asserting a conflicting-role assignment is blocked |
| P0 | M | **Detective SoD scanning + violation dashboard** | Only on-demand `/evaluate`; nothing sweeps standing access; the only standing SoD pairs are hardcoded in rego | Leader-gated sweep (pattern from `jit_expiry.go`) into a new `sod_violations` table (org_id + RLS), `/governance/violations` endpoint, exception via existing access-request flow |
| P0 | S | **Full multi-tenant governance objects** | `certification_campaigns`, `campaign_runs`, `abac_policies` have **no org_id** (scheduler runs everything under a hardcoded default org); attestation list unscoped | One migration adding org_id + RLS; thread `orgctx`; convert the scheduler to iterate orgs with `WithBypassRLS` per-org writes |
| P0 | M | **Real reviewer resolution (manager/owner)** | Wired path always assigns the `admin` user; manager/owner resolution only in dead `CertificationService` | Port reviewer-resolution into live `populateReviewItems` + attestation (manager via `users.manager_id`, owner via `entitlement_metadata.owner`); honor the persisted `reviewer_strategy` |
| P0 | M | **Escalation/delegation/reassignment/reminders** | The only escalation logic is in the **never-constructed** `RequestService`; `request_approval_chains` migrated for dead code | Resurrect the escalation checker as a leader-gated worker against the **live** rows; reminders via `internal/notifications`+`internal/email`; reassign/delegate endpoint on review items |
| P0 | XL | **Event-driven JML w/ HR-authoritative source** | Lifecycle workflows are manual-only; conditions/approval ignored; HR connectors are planned-only | Phase 1: identity-event bus (Redis stream) + governance consumer honoring conditions/approval. Phase 2: HR connectors (shared with IAM Pillar) |
| P0 | M | **Policy-based provisioning (birthright roles)** | `provisioning_rules` is a **facade** — CRUD/UI/migration but no engine | Rule engine as a consumer of the identity-event bus, reusing the ABAC operator evaluator for conditions and `fulfillRequest` primitives for audited grants |
| P0 | XL | **Entitlement warehouse (aggregation, correlation, orphans)** | Catalog is only a UNION of OpenIDX's own objects; no source-account table, no orphan detection | `source_accounts` + `account_entitlements` tables (org_id+RLS) populated by the LDAP/AD/Azure sync engines; correlation rules (mail/UPN/employeeId); unmatched=orphan |
| P0 | S | **Stop silent governance audit-event loss** | `workflows.go:1036`, `jit_expiry.go:96` INSERT into audit columns that don't exist; errors swallowed via `_, _ =` | Fix columns, check/log errors, add a CI test asserting each governance write lands an `audit_events` row; fast-follow: wire the built-but-dead tamper-evident store |
| P1 | M | **Certification decision support** | `review_items` carry no usage/risk context; the signals (`last_login`, activity, MFA, risk_level) exist unused | Enrich items at generation w/ last-login/dormancy/age/risk; compute approve/revoke/inspect recommendation; "bulk-approve low-risk". Cheap, hugely visible in demos |
| P1 | M | **Event-triggered micro-certifications** | Campaign scheduling is calendar-only; nothing fires a review from an event | Consume the identity-event bus: on dept/manager change or high-risk grant, auto-create a scoped single-user review. Reuses 100% of review machinery |
| P1 | L | **Role mining / access modeling** | Planned-only; Okta/Entra *also* lack this — a beatable gap | Batch Jaccard-similarity peer clustering over `user_roles`+`group_memberships`+attributes → `candidate_roles`; review-and-promote flow creating real composite roles |
| P1 | XL | **Downstream fulfillment: outbound SCIM + connectors + ITSM** | `fulfillRequest` grants only internal objects; no SCIM client anywhere | Shared with IAM Pillar's outbound SCIM; invoke from `fulfillRequest` + the revocation executor; ServiceNow ticket fallback for disconnected apps |
| P1 | M | **Non-employee/guest governance** | No `user_type`/sponsor/end_date; nothing expires a contractor | Add `identity_type`/`sponsor_id`/`end_date`; extend the JIT expiry sweep to disable past end_date; sponsor micro-review 14 days pre-expiry. "NERM included free" |
| P1 | M | **Approvals in Slack/Teams + actionable email** | Approvals live only in the React console | Actionable email w/ short-lived signed-JWT approve/deny links; Slack Block Kit cards via the production webhooks engine → same decision endpoints |
| P1 | M | **Identity-level risk scoring → risk-weighted certs** | `entitlement_metadata.risk_level` and `internal/risk` exist but are **never joined** | Nightly job computing identity risk = f(held-entitlement risk, risk scorer, MFA posture, dormancy); store on users; add "risk ≥ X" campaign scoping. Mostly a JOIN across subsystems OpenIDX already owns |
| P1 | L | **Machine identity / NHI governance** | No `identity_type` for service accounts; API keys/OAuth clients aren't in the catalog or any campaign | Classify NHIs; owner+succession in `entitlement_metadata`; a `service_account_certification` attestation type (the module already enforces revocation) |
| P1 | S | **ABAC enforced fail-closed in runtime path** | `EvaluateABACPolicies` is real but nothing calls it from enforcement, and it fails **open** | Call from the access-proxy `evaluatePolicies` with the fail-closed X-Internal-Token contract; flip errors to deny; per-org default-deny for opt-in routes |
| P2 | M | **PIM-style role eligibility** | OpenIDX has the *harder* parts (JIT w/ real expiry, approvals, vault checkout) but no eligible-vs-active model | `user_roles.state='eligible'`; self-service "activate" → pre-approved/approval-gated access-request w/ duration; existing JIT sweep deactivates |
| P2 | L | **AI-agent identity governance** | An `ai_agents` table + admin module exist but agents can't be requested/certified | Promote `ai_agents` to catalog principals (owner=sponsor); agents hold vault checkouts w/ TTL; gate agent-to-app at the proxy |
| P2 | M | **ITDR-to-governance closed loop** | Both ends exist (`internal/risk`, `continuous_verify.go`, reviews) but nothing connects a detection to a review/clamp-down | On high risk / verify-fail: auto-create scoped micro-review, expire JIT access, raise step-up. All actuators exist — event wiring |
| P2 | M | **Governance-as-code (Terraform + YAML import/export)** | REST exists; no declarative config, no provider, no entitlement bundles | Terraform provider + YAML over existing CRUD; entitlement "collections" as requestable bundles; append-only `entitlement_history` |
| P2 | L | **Governance copilot / NL interface** | `ai_policy_recommendations.go` queries tables that never existed → **500s**; args scrambled | First **fix or delete** it (credibility risk to ship 500ing "AI"); then expose governance REST via an MCP server for NL queries |
| P3 | XL | **Fine-grained ERP SoD (SAP/Oracle depth)** | Missing; depends on the connector framework | Defer until the entitlement warehouse + connector framework land; then import community SoD rulesets. Position on cross-app role-level SoD until then |

---

## Pillar 3 — PAM (vault, rotation, sessions, JIT, infrastructure access)

**Current maturity:** genuinely mature — envelope-encrypted vault w/ KEK
rotation, grants, reveal-with-reason, checkout ledger, lease sweeper; a rotation
engine w/ eight connectors incl. AWS IAM and GCP SA minters; JIT checkout
through governance; Guacamole SSH/RDP/VNC brokering w/ server-side credential
injection, single-use approval, recording, transcripts, legal holds, retention.
**The gaps are the modern-PAM frontier** (ephemeral certs, native-client access,
DB/K8s proxying, discovery) plus a broken step-up and an older, weaker
temp-access module.

| Pri | Effort | Gap | OpenIDX status | Recommendation |
|---|---|---|---|---|
| P0 | M | **Break-glass / emergency access** | Planned-only; closest is the audited admin reveal-bypass | Build on the reveal-bypass: `break_glass_events` (org-RLS), a named-principal endpoint requiring reason + second factor, auto forced-rotation + mandatory post-hoc review |
| P0 | L | **Privileged-account discovery + auto-onboarding** | Missing; vault onboarding is 100% manual | New `internal/credentials/discovery`: leader-gated scanners reusing existing clients — LDAP/AD privileged-group sweep, AWS IAM key-age, local accounts — auto-onboarding to the vault by rule |
| P0 | M | **Enforced step-up MFA at checkout/session launch** | `/oauth/stepup-verify` issues a step-up JWT **without verifying the code**; nothing requires step-up at reveal/retrieve/session | (1) Make `handleStepUpVerify` actually call TOTP/WebAuthn verification; (2) `require_step_up` flag on secrets + Guacamole routes enforced in vault/guacamole handlers |
| P0 | S | **Harden vendor/third-party temp access** | `temp_access.go` audit is a stub that never reaches the audit service; `require_mfa`/`notify_on_use` are dead flags; no org_id (not tenant-isolated) | Route audit through `UnifiedAuditService`; enforce `require_mfa` via the fixed step-up; implement `notify_on_use` via webhooks; add org_id + FORCE-RLS |
| P0 | XL | **Database session brokering w/ query-level audit** | Guacamole covers only ssh/rdp/vnc/telnet; DB is credential-rotation only | New `internal/access/dbproxy`: Postgres wire-protocol proxy authenticating via forward-auth/OIDC, injecting vault creds server-side like `guacamole.go`, logging parsed queries |
| P1 | L | **Ephemeral SSH certificates / ZSP** | Teleport's core wedge + CyberArk SIA; a Gartner scoring criterion | JIT checkout retrieves static creds; no CA | SSH CA in `internal/vault` (CA key as an envelope-encrypted secret); cert-issuance branch in `handleRetrieveCredential` (`x/crypto/ssh` already a dep) |
| P1 | XL | **Native-client access (ssh/psql/kubectl unmodified)** | "Nothing changes for engineers" decides dev-platform evals | All sessions are browser HTML5 | Exploit the integrated OpenZiti stack: `openidx connect <target>` CLI → session-request/approval → short-lived scoped Ziti identity → local listener native tools use |
| P1 | L | **Windows rotation + service-account dependencies** | 300–400+ connectors at leaders; OpenIDX has 8 | No WinRM/Windows rotator | `windows_rotator.go` via a WinRM client; dependents (services/tasks/IIS pools) as a post-rotate hook list |
| P1 | M | **ChatOps approvals + ticketing enforcement** | Slack/Teams approvals + ticket-number validation are table stakes | Approvals only in the console; no ticket field | Extend `internal/webhooks` w/ signed interactive Slack/Teams payloads; `required_ticket` policy validated against ServiceNow/Jira |
| P1 | S | **Checkout exclusivity + dual-control reveal** | Four-eyes on prod credentials is SOX/PCI | Ledger/leases exist but nothing prevents concurrent checkout or gates direct reveal | `exclusive`/`require_dual_control` flags; enforce exclusivity w/ atomic `UPDATE…RETURNING`; gate reveal on an approved access-request |
| P1 | S | **Encrypted, tamper-evident recording storage** | CyberArk sells "audit-grade tamper-evident evidence" | WebRTC recordings encrypted; **guacd recordings plaintext on disk** | Run guacd recordings through the existing `recording_crypto.go` keyring at session end; SHA-256 hash chain into the audit service |
| P1 | S | **SIEM streaming of PAM events (syslog/CEF, HEC)** | On every scorecard | Unified ingestion + CSV export exist; no forwarder | Forwarder worker in `internal/audit` emitting CEF/TLS-syslog + Splunk HEC, reusing the webhooks retry pattern |
| P1 | M | **Terraform provider / access-as-code** | Table stakes for cloud PAM | Only IaC for deploying OpenIDX itself | `terraform-provider-openidx` from the OpenAPI specs: vault secrets (metadata only), rotation policies, routes, apps |
| P1 | M | **AAPM SDKs + dynamic per-lease secrets** | CyberArk CP/CCP, Vault dynamic secrets | Grants support service accounts but no SDKs, no dynamic mode | Thin Go/Python SDKs wrapping service-account auth + `/use`; add an `Issue()` dynamic mode to the connector interface (the AWS Minter pattern already exists) |
| P1 | M | **Rotation connector breadth + SDK** | Leaders advertise 300–400+; OpenIDX loses 8-vs-300 | Framework is good; only 8 connectors | Publish `pkg/rotator` interfaces w/ the test harness as a template; seed MSSQL/Oracle/MongoDB/Redis/network-SSH; lean on community for the long tail |
| P1 | L | **Kubernetes access brokering** | Table stakes for Teleport/StrongDM/Boundary | Missing | Authenticating reverse proxy mapping the OpenIDX session to K8s impersonation; short-lived kubeconfigs from JIT grants; verb/resource audit |
| P1 | L | **Cloud console/CLI JIT elevation** | CyberArk Secure Cloud Access; Entra PIM/AWS TEAM are the "free" benchmarks | AWS/GCP coverage is key rotation only | `cloud_role` grant type: on approval, `AssumeRole` (STS client already imported) → federated console URL; expiry revokes |
| P2 | L | **AI-agent privileged access (identity, MCP, action approval)** | All three PAM leaders shipped named offerings | Missing | First-class agent principals w/ vault grants + JIT; MCP gateway route evaluating each tool call against OPA; every call audited |
| P2 | M | **AI session summaries / transcript intelligence** | Teleport LLM summaries; Delinea Iris, CyberArk CORA | guaclog transcripts exist; nothing summarizes | Leader-gated post-session job feeding transcripts to a pluggable (self-hostable) LLM endpoint; store summary+commands+risk flags; ES full-text search |
| P2 | M | **Privileged-session risk scoring + auto-suspend** | CyberArk PTA; StrongDM runtime authZ | Force-terminate exists for ZTNA sessions; five orphaned risk engines unused | Extend `continuous_verify.go` to score Guacamole sessions (login-risk + transcript keyword hits + off-hours), resurrecting orphaned `internal/risk` logic |
| P2 | L | **Secrets federation with cloud vaults (AWS SM/Azure KV/GCP SM)** | CyberArk Secrets Hub | Rotators change creds but nothing syncs to/from cloud stores | Sync worker: the promote step additionally pushes new versions to cloud secret stores; pull-mode discovery |
| P2 | M | **Moderated sessions + command-level dual authZ** | Teleport moderated sessions satisfy SOX/PCI supervised access | Read-only share + force-terminate only | `require_moderator` flag holding session in a waiting state until a second user attaches (Guacamole 1.3+ interactive sharing) |
| P2 | XL | **Endpoint privilege management (PEDM)** | All three MQ leaders ship it; anchors renewals | Missing; the `agent/` skeleton could host it | **Linux-first** (where the OSS audience lives): a sudo-policy plugin in the existing agent brokering elevation through OPA + JIT approval, streaming events to audit |
| P2 | L | **Identity attack-path / effective-privilege graph** | BeyondTrust True Privilege spearhead | Raw data all in one Postgres; nothing computes transitive privilege | Graph materializer (recursive CTEs over existing tables), `GET /pam/privilege-graph`, "who can reach secret X, via which path". **Native because OpenIDX owns IdP+IGA+PAM tables** |
| P3 | L | **Workforce password management + browser extension** | CyberArk WPM inflates seat count | Vault is admin/infra-focused | After P0/P1: a user-scoped secret class + a minimal WebExtension autofill w/ WebAuthn unlock |

---

## Pillar 4 — ZTNA / OpenZiti network access

**Current maturity:** one of the most mature pillars — a real OpenZiti
integration (SDK + controller REST) w/ a desired-state reconciler, three hosting
modes, BrowZer clientless access, posture enforcement in the proxy path, and two
real agents. **The single biggest strategic opening in the whole product is
here:** the "no-code multi-tenant console with delegated RBAC, SCIM→Ziti
lifecycle, JIT/NHI, and usage metering" that the research marks as **"NetFoundry
commercial only — absent from OSS."** OpenIDX is one refactor (removing the
hardcoded fallback org UUID) away from being the OSS OpenZiti management plane
the ecosystem conspicuously lacks.

| Pri | Effort | Gap | OpenIDX status | Recommendation |
|---|---|---|---|---|
| P0 | S | **Real overlay dial diagnostics** | `TestServiceDial` returns `true` if the service record exists — **it never dials**. Both connection-test endpoints report reachable without probing | Replace w/ a real `zitiCtx.Dial(serviceName)` (same SDK context `ZitiTransport` uses) + short timeout + 1-byte probe; surface latency. One-file fix removing a demo-killer |
| P0 | M | **Ziti access-event ingestion into unified audit/SIEM** | `GetAuditEvents` returns an empty slice; the ingestion pipeline is real but nothing feeds it Ziti events | Subscribe to the controller fabric event stream from `cmd/access-service`, normalize circuit/session/posture events into the unified audit schema, index to ES |
| P0 | M | **Continuous posture w/ mid-session revocation on the tunneler path** | Proxy/BrowZer enforces per-request fail-closed, but native-tunneler users keep sessions when posture degrades | Revocation worker watching `device_posture_results`; on fail, DELETE the identity's api-sessions via MgmtRequest / toggle a posture attribute; decide via OPA |
| P0 | M | **UDP + arbitrary-protocol publishing** | `host.v1` configs hardcode `"protocol":"tcp"`; no protocol selector | `protocol` field (tcp/udp/both) on routes, threaded through the reconciler config generation + UI; direct/hop modes get full UDP |
| P0 | L | **Production K8s deployment of the Ziti fabric + HA control plane** | docker-compose is turnkey; Helm only wires access-service to an **externally-operated** fabric | Optional subchart on upstream openziti Helm charts (controller+router), cert bootstrap, validated against a 3-node Raft cluster; HPA for access-service |
| P0 | M | **Windows posture-check parity** | Several checks return `warn` on Windows | Implement Windows backends (BitLocker via WMI, firewall via netsh, AV via Security Center, patch via QFE, domain join) in the existing per-check files |
| P1 | M | **EDR/MDM risk-signal ingestion** | Zero CrowdStrike/SentinelOne/Defender/Intune/Jamf integration | EDR connector package polling Falcon ZTA + Intune compliance, cached in Redis, persisted keyed by Ziti identity; comparative conditions (`zta_score >= N`) in the evaluator |
| P1 | L | **Terraform provider + K8s operator (policy-as-code)** | Only deploys OpenIDX's own AWS infra | Generate a client from the OpenAPI specs; provider covering routes/apps/posture/policies; slim operator w/ Route/PublishedApp CRDs |
| P1 | M | **Complete certificate lifecycle** | `rotateIdentityCert` inserts a placeholder row; CA rotation **refuses** | Poll the controller for the new cert after re-enroll and replace the placeholder; use the authenticator-extend API; guided CA-rotation runbook |
| P1 | S | **Runtime-connect correctness + Play Integrity hard mode** | `NewAgentAPIHandler` captures a one-time `svc.ziti()` snapshot — agents enrolled after a runtime controller connect get **no identity until restart**; Play Integrity soft-fails | Pass the swappable `ZitiProvider` (built for exactly this); add `require_play_integrity` org setting |
| P1 | M | **JIT/time-bound network grants wired to governance** | temp/vendor links exist, but no time-bound grant of a Ziti service policy | On access-request approval, add the user's role attribute to the target policy w/ `expires_at`, enforced by a sweeper that removes it + kills sessions |
| P1 | M | **Step-up MFA on risk/posture change in the access path** | Posture gates requests but degraded posture can't demand re-auth mid-session | Add a `step_up` outcome to the evaluator: proxy 302s to OAuth w/ `acr_values=mfa`; expose Ziti's MFA posture-check type for tunneler paths |
| P1 | L | **First-class multi-tenant overlay (per-org Ziti scoping, delegated admin)** | Access-pillar paths fall back to a **hardcoded org UUID**; NetFoundry-only in the market | Make org_id mandatory through posture/policy/route paths; namespace Ziti attributes/service names per org; scope the reconciler; org-RBAC on Ziti passthrough. **The biggest OSS-vs-NetFoundry win** |
| P2 | L | **AI-assisted app discovery + segmentation** | Path discovery/classification exist; nothing observes live traffic to propose segments | After event ingestion lands: flow rollups → extend AI recommendations to propose route splits/least-privilege policies as one-click actions |
| P2 | M | **SSF/CAEP transmitter + receiver** | Zero CAEP/SSF/RISC | Receiver mapping session-revoked/device-compliance events onto the posture-revocation worker + transmitter emitting CAEP from auth/risk events. **One impl serves both IdP and ZTNA** |
| P2 | L | **MCP / AI-agent access gateway** | No MCP; no agent NHI registry | Integrate upstream `openziti/mcp-gateway`: mint a Ziti identity per agent, publish MCP servers as dark services, tool-level OPA allowlists, every call audited |
| P2 | M | **Usage metering / chargeback / consumption analytics** | Fabric metrics exist; no attribution/rollup/chargeback | Per-org/service/identity counters from the event pipeline; consumption dashboard. Direct parity play vs NetFoundry's paid tier |
| P2 | L | **DEM-lite (per-user path quality)** | Router health exists; no per-user experience | Synthetic-probe agent plugin (periodic dial + HTTP timing) → per-user experience view correlated w/ router latency |
| P2 | L | **BrowZer last-mile data controls** | Clientless path applies zero data controls after render | Inject a policy layer at the bootstrapper/hop: watermark, clipboard restriction, download blocking as injected JS/headers. Honestly positioned as best-effort |
| P2 | M | **Workload identity federation (OIDC → ephemeral Ziti identity)** | Agent enrollment uses one-time tokens; no CI-token path | Register GitHub/GitLab OIDC issuers as ext-JWT signers; JIT endpoint mapping repo/workflow claims to scoped attributes; TTL sweeper GCs ephemeral identities |
| P3 | L | **DNS filtering / basic egress security** | No SWG | Don't build an SSE stack. Ship a DNS-filtering profile for the tunneler path (CoreDNS + OPA blocklist) as a consolidation checkbox |
| P3 | S | **Post-quantum / FIPS crypto posture + roadmap** | Inherited silently from OpenZiti; no doc | Publish a crypto-posture doc; expose upstream FIPS/PQ toggles as passthrough; add a "cryptography" section to compliance reports. Cheap RFP insurance |
| P3 | XL | **IoT/OT + agentless-device segmentation** | Nothing discovers/classifies agentless devices | Defer full IoT/OT; package hop-mode + temp links + recorded Guacamole as an "OT vendor access" solution pattern first |

---

## Pillar 5 — Risk, ITDR & AI-era identity

> Synthesized from the risk/adaptive + audit code audits and the ITDR/ISPM,
> AI-identity, and MFA/passwordless market reports. (The dedicated gap agent for
> this pillar hit the session limit; this section was compiled from its inputs.)

**Current maturity:** a genuinely wired core — heuristic login-risk scoring +
device fingerprinting persisted to `login_history`/`known_devices` and consumed
in the live OAuth flow, adaptive MFA gating, a strong zero-trust proxy layer w/
a leader-gated continuous session verifier. **Around that spine sit at least
five never-invoked risk engines and two outright-broken security features.** The
2026 market has moved to session-centric ITDR (token theft), SSF/CAEP continuous
evaluation, and AI-agent risk — areas where OpenIDX's unified ownership of IdP +
gateway + network is a structural advantage it isn't yet cashing in.

| Pri | Effort | Gap | Market evidence | OpenIDX status | Recommendation |
|---|---|---|---|---|---|
| P0 | S | **Make admin risk policies actually apply** | Every leader's risk policies take effect | `parseJSON` in `adaptive_mfa.go:637` is a **literal no-op** — every admin-configured risk policy has zero effect on login while CRUD+UI imply otherwise | Implement `parseJSON` (unmarshal into the policy struct); regression test that a configured policy changes the risk outcome |
| P0 | S | **Fix step-up verification (security hole)** | Step-up must verify the factor | `/oauth/stepup-verify` (`stepup.go:149`) accepts method+code but **never verifies the code** — it mints a signed step-up JWT for any authenticated session | Call the existing TOTP/WebAuthn verifiers before completing the challenge (shared with the PAM step-up gap) |
| P0 | S | **Multi-tenant risk policies** | Cross-tenant leakage is an instant disqualifier | `risk_policies` has **no org_id**; queries unscoped — policies are global across tenants | Add org_id + RLS (matching the `sql_v37` pattern the rest of the risk tables already got); scope queries via `orgctx` |
| P0 | M | **Wire anomaly detection + auto-remediation** | Impossible-travel, brute-force, credential-stuffing detection + automated response are ITDR table stakes | Complete, org-scoped logic exists but `RunAnomalyCheck` is **never called** — `security_alerts` is never auto-populated, accounts never auto-locked, IPs never auto-blocked; the alerts UI reads an always-empty table | Invoke `RunAnomalyCheck` from a leader-gated worker over `login_history`; wire auto-lock/auto-IP-block via the existing IP-threat-list; surface in the security-alerts UI |
| P1 | M | **Enforce OPA deny-overrides in Go middleware** | Deny-by-default policy is assumed | The rego computes `final_allow` (tenant isolation + SoD deny), but the Go middleware only enforces `result.allow` — **deny rules are logged, not enforced**; identity/oauth/audit have no OPA middleware at all | Enforce `final_allow`; add the middleware to the other services; make OPA enforcement a documented, testable posture (it defaults off today) |
| P1 | M | **UEBA: write and use user risk baselines** | Per-identity behavioral baselining + 0–100 risk score is ITDR/ISPM table stakes | `user_risk_baselines` has a migration, an admin endpoint, and a UI panel, but **the only writer is never called** — the profile always renders defaults | Call `UpdateUserRiskBaseline` from the login pipeline (typical hours/countries/IPs); feed the baseline into `AssessLoginRisk`; consolidate toward one baseline impl (three exist) |
| P1 | M | **Session/token-theft detection** | The dominant 2026 attack vector (51.7M stolen-cookie packages, +72% YoY); Duo Passport, MDI token-replay, DBSC | No token-theft/replay detection; sessions in localStorage w/ no binding | Bind sessions to a device marker (UA + fingerprint at issue), flag replay from a new fingerprint on the same session, force step-up/revoke; align w/ DBSC when Chrome ships it broadly |
| P1 | M | **MFA-fatigue / push-bombing detection** | Table stakes across ITDR; number matching alone isn't enough | Push MFA has number matching but no rate/anomaly detection on repeated challenges | Rate-limit + anomaly-flag rapid repeated push challenges; alert + optional lockout; feed into the anomaly pipeline |
| P1 | M | **Consolidate the five parallel risk engines** | — (tech-debt / correctness) | `risk.Scorer`, `BehaviorTracker`, `scoring_engine`, `mfa.AdaptiveService`, `audit.AnomalyDetector` are all fully written, tested, and **unwired**; some query tables no migration creates; READMEs overstate integration | Pick the one to be canonical (the live heuristic `AssessLoginRisk` + `internal/risk` scorer), wire it end-to-end, delete or clearly quarantine the rest, correct the READMEs |
| P1 | S | **Geo-IP hardening** | Production risk scoring needs reliable, private geo | Depends on `ip-api.com` free tier over **plain HTTP** (rate-limited, unencrypted); two caching impls | Switch to a bundled MaxMind GeoLite2 DB (works air-gapped) or a paid TLS endpoint; unify the caches |
| P2 | L | **SSF/CAEP transmitter + receiver + universal logout** | The 2026 standards battleground (Okta ITP, finalized OpenID SSF/CAEP, IPSIE); explicitly a gap in every OSS rival | Missing, but the substrate (Redis revocation, SCIM session kill, Ziti termination) is unusually strong | **First OSS SSF/CAEP implementation.** Transmitter emits CAEP from auth/risk events; receiver maps inbound events to `deprovisionUser` + token revocation + Ziti termination. Shared with IAM/ZTNA CAE gaps — one impl, three pillars |
| P2 | M | **ITDR-to-governance closed loop** | Okta ITP → Security Access Reviews; Entra risk gates approvals | Both ends exist; nothing connects a detection to a review/clamp-down | On high risk / verify-fail: auto-create a scoped micro-review, expire JIT access, raise step-up. Event wiring, not new engines (shared w/ IGA) |
| P2 | M | **Shadow-SaaS / OAuth-grant discovery** | Push/Okta ISPM browser-native discovery; the #1 SSO blind spot | No shadow-app discovery | Longer-horizon: a browser-extension or log-based inventory of app logins + OAuth grants w/ MFA/SSO-bypass flags. Pairs with NHI discovery (Pillar 6) |
| P2 | L | **AI-agent risk scoring + detection** | Entra ID Protection for agents, CrowdStrike CAEP for agents, Silverfort AI Agent Security | No agent risk model | Once agent identities exist (IAM/IGA gaps), extend the risk scorer to agent sessions (anomalous tool-use, off-hours, scope-escalation); CAEP revocation for agent sessions |
| P2 | M | **NL admin copilot / platform MCP server** | GenAI admin copilots + vendor MCP servers are now RFP checkboxes | Broken `ai_policy_recommendations` (500s); no MCP server for the platform | Fix/delete the broken module; ship an MCP server exposing read + guarded-write admin operations so any LLM client can operate OpenIDX in natural language |
| P3 | M | **Identity deception / honeytokens** | KuppingerCole scores deception as its own ITDR axis | Missing | Seed honeytoken accounts/API keys; alert on any use (near-zero false positive). Cheap, high-signal — OpenIDX mints the tokens so it knows they're fake |

---

## Pillar 6 — Platform, NHI & operations

**Current maturity:** one of the most mature pillars, and unusually the code is
*ahead* of the docs — genuine end-to-end multitenancy (org_id on ~68 tables,
FORCE RLS, a non-BYPASSRLS runtime role, a custom `orgscope` CI linter),
production migration framework, leader election, health/metrics. **Two headline
defects:** API keys/service accounts can't actually authenticate anywhere (every
service passes a nil validator), and the org-management UI expects response
shapes the backend doesn't return. The **NHI category** — the fastest-growing
identity segment — is almost entirely greenfield here, and it's where the
unified store is the sharpest weapon.

| Pri | Effort | Gap | OpenIDX status | Recommendation |
|---|---|---|---|---|
| P0 | S | **API keys / service accounts actually authenticate** | Full CRUD/hashing/Redis-cached validator exists, but `middleware.Auth()` hardcodes a **nil validator** — no minted key/PAT can authenticate anywhere | Construct `apikeys.Service` in each of the 7 service mains and pass it to `middleware.AuthWithAPIKey`. Validator/org-propagation/scopes/tests already exist — pure wiring |
| P0 | S | **Close tenant-isolation bypasses** | X-Org-Slug strip only in the "mostly bypassed" gateway-service; **ES audit search has no org filter** (cross-tenant leak when ES enabled) | Strip/re-derive X-Org-Slug at APISIX+nginx; add org_id to the ES mapping + query filter; extend the cross-org spoofing test against the compose topology |
| P0 | S | **Tenant admin authZ (stop org enumeration)** | `GET /organizations` has **no admin gate** — any user enumerates every tenant's name/slug/plan/member-count | Reuse `auth.SuperAdminPredicate` as route middleware; scope the list for non-admins to member orgs; org-role checks on member add/remove |
| P0 | S | **Working org/tenant management console** | Backend returns a bare array; the two React pages expect `{organizations:[...]}` / `{data:[...]}` — **the org list renders empty** | Standardize on bare-array + `X-Total-Count`; fix the readers; add a Playwright spec mocking the *real* backend shape |
| P0 | M | **Helm production parity** | No migrate Job, no backup CronJob; `DATABASE_URL` uses the table-owner user (undermining FORCE RLS); leftover Keycloak plumbing | Pre-install/upgrade Helm hook running `cmd/migrate`; backup CronJob wrapping `cmd/backup`; app-role cutover so DATABASE_URL defaults to `openidx_app`; delete Keycloak |
| P1 | M | **OIDC workload identity federation + Token Exchange (RFC 8693)** | No token-exchange grant, no `private_key_jwt`, no federated-credential trust; nothing SPIFFE | RFC 8693 grant + a `federated_credentials` table so CI/K8s exchange their OIDC token for an OpenIDX token w/ no stored secret. JWKS verify machinery already exists (shared w/ IAM) |
| P1 | L | **NHI inventory, ownership & posture scoring** | Manages only self-minted identities; no discovery of external service accounts/cloud IAM/OAuth grants/SSH keys/K8s SAs, no ownership, no staleness scoring | `nhi-inventory` package (directory-sync pattern): connectors for AWS IAM/GCP SA/GitHub/K8s SAs → org-scoped `nhi_identities`; score staleness/over-privilege; owner attribution |
| P1 | M | **Short-lived / JIT dynamic credentials** | Everything rotates *standing* credentials; no per-lease ephemeral issuance | `Issue()` path per rotator (`CREATE ROLE … VALID UNTIL`, `AssumeRole`/`GetFederationToken`, short-lived SA keys, signed SSH certs); leases in an org-scoped table revoked by the sweeper (shared w/ PAM) |
| P1 | L | **Terraform provider + declarative bootstrap** | Only AWS infra IaC; no provider for OpenIDX resources; no Kickstart-style seed | `terraform-provider-openidx` (orgs/clients/users/policies/webhooks/keys) from the OpenAPI specs; `openidx bootstrap -f config.yaml` for reproducible working-login (POC-winner) |
| P1 | M | **Complete the DR story** | `cmd/backup` is production-grade but scheduling is display-only; no Helm CronJob; no ES snapshots; no restore drills | Real in-process HA-safe cron; Helm CronJob; ES snapshot policies; a scheduled restore-verification job (restore latest into a scratch DB + verify) |
| P1 | S | **Repo & docs hygiene (OSS credibility)** | `SECURITY-TENANCY.md` still says "Single-Tenant by Design" (contradicting shipped RLS); dead conflicting migration files; committed `team.sh.bak.*` backups; stale test references | One cleanup PR: rewrite the doc around the real RLS belt, delete legacy SQL + backups, scrub stale references. OSS adopters read the repo before the product |
| P1 | L | **Internationalization** | **Zero i18n** — no framework, all strings hardcoded English (ironic given 7 Turkish SMS gateways) | `react-i18next`, namespace-per-page; extract auth-critical surfaces first (login, reset, MFA enrollment, portal); per-tenant default locale in `tenant_settings` |
| P2 | L | **AI-agent / MCP identity (agent accounts, MCP AS, blended identity)** | AI pages exist but no MCP AS, no DCR, no agent↔human token binding | DCR+CIMD for MCP clients; an `agent` client type whose tokens carry an `act` claim; OPA-evaluated per-tool scopes (shared across IAM/IGA/PAM/ZTNA) |
| P2 | L | **Secretless credential injection at the Ziti/BrowZer edge** | Substrate exists (encrypted vault + Ziti tunnelers) but no injection feature | Injection option on published apps: access service resolves a vault secret at connect time and injects it at the tunneler; client authenticates w/ its Ziti identity and never sees the secret. **Aembit/Conjur-class, no new agent** |
| P2 | M | **Conditional access for workloads** | OPA deployed platform-wide but token/credential issuance consults no policy | OPA check in `client_credentials` + token-exchange + vault reveal/JIT paths; ship default Rego (deny-off-hours, deny-new-geo, scope ceilings). "Entra Workload ID Premium" as flat-cost |
| P2 | L | **Certificate lifecycle automation (ACME, inventory, 47-day readiness)** | certbot sidecar + a cert-expiry health check exist; no inventory, no ACME management | Start w/ inventory+alerting (scan published-app endpoints + Ziti PKI, expiry SLOs to Prometheus); Phase 2 embed an ACME client |
| P2 | M | **Secret scanning w/ liveness validation** | No scanning; but OpenIDX **uniquely holds hashes of every key it minted** | `openidx scan` CLI checking `oidx_`-prefixed findings against the apikeys hash table → "this leaked key is LIVE in your org" (no generic scanner can do this); auto-revoke + notify |
| P2 | L | **Kubernetes Operator + zero-downtime upgrade contract** | Helm only; upgrades rely on AUTO_MIGRATE w/ no N-1 compatibility contract | Cheaper 80% first: document + CI-test an N-1 migration-compat contract, pre-upgrade migrate hook, PDB-respecting rolling updates; Operator later if demanded |
| P2 | M | **HA simplification (etcd SPOF, three proxy layers)** | The repo's own review flags single-node etcd for APISIX as a SPOF and calls three proxy layers "a smell" | Promote APISIX standalone (yaml, no etcd) since routes are static, or fold routing into nginx; retire/demote gateway-service after moving its tenant-header logic to the surviving edge |
| P2 | XL | **SPIFFE-compatible workload identity + federation** | No SPIFFE/SVID/attestation; Ziti speaks its own format | Long-horizon: issue JWT-SVIDs from the OAuth service (K8s SA attestation = SPIRE pattern); SPIFFE trust-bundle endpoint; bridge Ziti identities to SPIFFE IDs so enrollment doubles as attestation |
| P3 | S | **Console UX completion** | Full dark-mode CSS exists but `setTheme` is never called; idle-timeout dialog fully built but never mounted; notifications split across two API surfaces | Three small PRs: theme toggle, mount idle-timeout in the authenticated layout, consolidate notifications |
| P3 | S | **Fleet-wide profiling** | `internal/profiling` + `cmd/profiler` exist but pprof only in identity-service, dev-only | Register the middleware in all mains behind `ENABLE_PPROF` (default off, localhost-bound); Grafana panel linking capture commands |

---

## Cross-cutting gaps (the completeness critique)

> The per-pillar registers cover features. These dimensions cut across all
> pillars and are, individually, capable of blocking the "ultimate product"
> ambition regardless of feature completeness. (Synthesized from the audits and
> market reports; the dedicated critic agent hit the session limit.)

1. **Compliance attestations are the real enterprise gate — and they're absent.**
   The sovereignty/self-host story is strongest exactly in regulated and
   public-sector deals (eIDAS/NIS2/Schrems II, FedRAMP, defense), and those deals
   are won on **SOC 2 Type II, ISO 27001, FIPS 140-3, Common Criteria, FedRAMP**
   — none of which OpenIDX has. Even self-hosted, buyers ask for the platform's
   own attestations and a documented control set. *This is a program, not a
   feature: control mapping, evidence automation (which the audit service should
   generate about OpenIDX itself), pentest, and a certification roadmap.*

2. **Connector/integration ecosystem breadth is a raw-count RFP row OpenIDX loses
   today.** Okta OIN has 7,000+ integrations; SailPoint 250+ entitlement-level
   connectors; the mid-market is defined by "time-to-onboard a new SaaS app."
   OpenIDX has ~8 rotation connectors and inbound-only SCIM. The answer is not to
   hand-build 7,000 — it's to ship **stable connector SDKs** (rotator, SCIM
   target, HR source, EDR, NHI) with the existing test harnesses as templates and
   a **community marketplace**, then seed the top 20–30. Connector depth is also
   the standard technical knockout in IGA evals (entitlement-level read/write).

3. **App catalog / SSO template gallery.** Leaders ship pre-integrated SSO
   templates + password-vaulting fallback for non-federated apps. OpenIDX has an
   applications registry but no gallery of pre-built app configs. A curated,
   community-contributable SSO template catalog is a visible parity item.

4. **Migration tooling from incumbents is how displacement deals are actually
   won.** There is no importer for Okta, Auth0, Keycloak, AD, or CyberArk. Users
   won't rip-and-replace without a migration path (users, groups, apps, policies,
   passkeys via CXF, vault secrets). Build **importers** as a first-class
   onboarding surface — this is the wedge that converts the cost story into
   signed deals.

5. **Mobile + agent packaging.** Push MFA is broken partly because **there is no
   companion authenticator app** — the Android agent is MDM/kiosk-focused, and
   there is no iOS at all. The "ultimate product" needs: an iOS/Android
   authenticator (push approve, TOTP, passkey, QR), and unified desktop clients
   (Windows/macOS/Linux) with **code signing and an auto-update channel**. Agent
   auto-update and signed releases are also a supply-chain trust requirement.

6. **Licensing / open-core monetization is undefined — and the market is in
   license turbulence in OpenIDX's favor.** Zitadel went AGPL, Teleport restricted
   Community Edition, HashiCorp went BUSL into IBM — each pushing adopters toward
   permissive, foundation-governed alternatives. OpenIDX should make **license
   posture a feature**: a clear, permissive core + an explicit open-core boundary
   (what, if anything, is commercial — hosted control plane? support? compliance
   packs? connector marketplace?). Ambiguity here stalls OEM/ISV/procurement
   adoption. Decide and document it.

7. **Community, docs, and repo hygiene are the first thing OSS adopters
   evaluate — and they currently undercut credibility.** Contradictory docs
   (SIEM "done" vs "roadmap" in the same README; single-tenant vs multi-tenant),
   `team.sh.bak.*` and `update_password.sql` committed at the repo root, dead
   parallel implementations, a committed compiled bundle masquerading as a second
   app. A "clean the repo, reconcile the docs, delete the dead code" pass is
   disproportionately high-leverage for adoption.

8. **Published performance/scale benchmarks.** Leaders quote millions of users
   and contractual latency SLAs; OpenIDX has no published load-test numbers. A
   reproducible benchmark harness + published RPS/latency/user-count figures is
   both an RFP row and a way to find the single-Postgres scale ceiling before a
   customer does.

9. **MSP / white-label.** The multi-tenant console with delegated admin is the
   NetFoundry-shaped gap (ZTNA pillar) *and* the MSP channel requirement across
   mesh ZTNA. White-label branding already exists; delegated org-admin roles,
   per-tenant isolation at every ingress, and chargeback/usage metering complete
   the MSP story.

10. **Supply-chain security of the platform itself.** No SBOM, no signed
    releases (cosign/SLSA provenance), no published bug-bounty. CodeQL and a
    security-scan workflow exist. For a security product, **being demonstrably
    secure in your own supply chain** is table stakes buyers now audit
    (post-Salesloft/Drift, post-xz).

11. **Offline / air-gapped completeness.** Sovereignty is a structural tailwind,
    but several features silently require the internet (geo-IP over HTTP, HIBP,
    FCM/APNS push). An "air-gap mode" that swaps in bundled MaxMind, offline
    breach lists, and self-hosted push is a differentiated, checkable posture.

12. **Accessibility (WCAG) and verifiable credentials.** The console has no stated
    a11y conformance (a public-sector procurement gate). And eIDAS 2.0 mandates
    EUDI-wallet acceptance for large EU sectors by 2026–2027 — Keycloak already
    ships OpenID4VCI issuance; a VC roadmap is a European-tender differentiator.

13. **Identity verification / deepfake defense at helpdesk reset.**
    Scattered-Spider-style social engineering of the helpdesk reset is the #1 hole
    in otherwise phishing-resistant stacks; the market answer is IdV
    (liveness/deepfake detection) at enrollment and recovery. A roadmap item, but
    increasingly an RFP section.

---

## Unfair advantages of the unified architecture

These are the reasons to build the "ultimate product" as *one* platform rather
than assembling point tools — the capabilities that are **a JOIN or an event
wire in OpenIDX, but a multi-vendor integration project for everyone else.**
Every one of these is already substantially wired; the plan's job is to finish
the seams.

1. **One kill-switch from token to packet.** OpenIDX owns the IdP, the session
   store (Postgres+Redis), the API gateway (APISIX), *and* the network layer
   (OpenZiti). A single risk event can revoke OAuth tokens, kill DB/Redis
   sessions, **and** sever live ZTNA circuits in milliseconds. Okta ITP can only
   *request* this of third-party SSF receivers; Entra CAE only does it inside
   Microsoft's own resources. **First OSS SSF/CAEP + native network termination is
   a headline no competitor can match.**

2. **Certification-to-network revocation.** Governance policies already gate live
   proxied traffic fail-closed and a Ziti policy-sync pipeline exists — so an
   access-review "revoke" can terminate sessions and network paths in seconds.
   SailPoint/Saviynt mark revoked and wait for a downstream connector.

3. **IGA + PAM as one workflow, not two SKUs.** Vault checkout/reveal/return with
   rotation runs inside the *same* access-request pipeline that grants roles — so
   certifying vault access, JIT credentials, and standing roles happens in one
   campaign engine and one audit trail. Competitors need CyberArk + SailPoint
   integration projects to tell this story.

4. **Zero standing privilege for the whole workforce at $0 incremental cost.** JIT
   grants with real expiry deletion + approval workflows + (with PIM-style
   eligibility) give every user and machine time-bound access without Entra P2/PIM
   or Saviynt cloud-PAM add-ons — monetizing the market's "eliminate standing
   access" shift against the per-identity pricing revolt.

5. **Free NHI + AI-agent governance.** An `ai_agents` table, API keys, OAuth
   clients, a vault w/ rotation, OPA, and an attestation engine w/ enforced
   revocation already coexist in one Postgres. Classifying them as governable
   principals gives away exactly what SailPoint sells as per-identity Machine
   Identity and Agent Identity add-ons — the highest-growth, highest-margin SKUs
   in the category.

6. **Posture-gated auth without an MDM tax.** OpenZiti posture checks (OS,
   process, domain, MAC) already ship for ZTNA enrollment; feeding them into the
   adaptive-MFA risk engine delivers "posture-gated authentication" that Duo gates
   behind Premier (3×) and Beyond Identity sells as its entire product — at zero
   marginal cost and covering the BYOD/contractor devices MDM-dependent rivals
   miss.

7. **Secretless delivery on a fabric you already run.** Ziti identities are
   cryptographically enrolled and terminate every published-app connection;
   pairing the vault with credential injection at the tunneler yields
   Aembit/Conjur-class secretless brokering **with no new agent to deploy** — and
   ZTNA policy + workload credentialing live in one control plane.

8. **The blended-identity audit chain is a query, not an integration.** Auth
   events, vault reveal leases, PAM session recordings, JIT grants, and (future)
   agent on-behalf-of tokens all land in one org-scoped Postgres — so "which human
   did this agent/service act for, and what did it touch" is a single query, with
   tamper-evident potential (the hash-chain subsystem already exists as dead code
   waiting to be wired).

9. **The missing NetFoundry console, open source.** The audited multi-tenant
   console machinery (tenant selector, X-Org-Slug, white-label branding, role
   hierarchy) sits one refactor from being the multi-tenant, delegated-admin,
   white-labeled OpenZiti management plane the OSS ecosystem conspicuously lacks —
   instantly the default choice for MSPs and EU-sovereignty deployments.

10. **Structural pricing attack.** The market's dominant pain is per-user /
    per-identity / per-MAU pricing exploding at 50–82:1 machine:human ratios and
    47-day cert churn, plus SKU stacking. A genuinely open, self-hostable, flat
    infrastructure-cost platform makes ephemeral CI runners, pods, and AI agents
    cost zero marginal dollars — the exact wedge FusionAuth ("no MAU tax"), NetBird
    (BSD-3), and Authentik ("the Okta tax") ride, but across *all four* pillars at
    once.
