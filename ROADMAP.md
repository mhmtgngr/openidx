# OpenIDX Roadmap

This page is the one source of truth for OpenIDX's priorities. The maintainer
changes it at milestone boundaries, and every change points to an
[ADR](docs/adr/README.md) or an issue. Work items live in GitHub issues.
[docs/plans/2026-09-23-proje-analizi-ve-yol-haritasi.md](docs/plans/2026-09-23-proje-analizi-ve-yol-haritasi.md)
records the analysis behind this version (in Turkish).
[ADR 0001](docs/adr/0001-product-focus-and-trusted-core.md) records the
decision.

*Last updated: 2026-09-24.*

## What OpenIDX is

| | |
|---|---|
| **Vision** | Organizations run identity, authorization, privileged access and network access from **one self-hosted control plane**, and one access decision reaches every layer in seconds. |
| **Problem** | Mid-sized organizations buy and integrate four or five products: an IdP, IGA, PAM and a VPN or ZTNA product. Per-user licences are expensive. The gaps between the products become audit findings and breaches, for example a leaver whose VPN or server access stays open. |
| **For whom** | Organizations of 200 to 5,000 people that must keep their data in their own infrastructure, and the MSPs and integrators who serve them. Examples: KVKK-, BDDK- or public-sector-regulated organizations, healthcare, education, and foundations and NGOs. |
| **Entry wedge** | **Privileged and third-party access without a VPN, approved and recorded**, with SSO and MFA included. No inbound ports. Every session is approved, recorded, and revocable in seconds. |
| **Why OpenIDX** | One control plane and one kill switch, which cuts tokens, sessions, vault checkouts, live privileged sessions and network circuits together. Multi-tenancy is enforced in PostgreSQL. It is fully self-hosted, Apache-2.0, and has a Turkish UI. |
| **Not now** | Multi-region SaaS; FedRAMP and FIPS; a connector marketplace; WASM app virtualization; 50-million-user scale; a separate Kotlin Android agent. |
| **North Star** | The number of independent organizations running OpenIDX in production. The first goal is three design partners within 90 days. |

## Milestones

### M0 — Clean-up and definition (week of 2026-09-21) · [#978](https://github.com/mhmtgngr/openidx/issues/978)

- [x] SECURITY.md sends reports through GitHub private vulnerability reporting.
  The dead `openidx.io` addresses and the bounty and SLA promises are removed.
- [x] The README links work, and the status note is honest.
- [x] Product defaults no longer name the maintainer's own site
  ([#977](https://github.com/mhmtgngr/openidx/issues/977) covers the rest).
- [x] [The AI working agreement](docs/AI-WORKING-AGREEMENT.md) is written. ADR 0001 records the decisions.
  The global-scale programme is frozen.
- [x] The 23 stale pull requests are closed with reasons.
- [ ] Maintainer actions: enable private vulnerability reporting, GitHub
  Pages and Discussions; protect `main`; install Renovate. See
  [#978](https://github.com/mhmtgngr/openidx/issues/978).

### M1 — Trusted Core → v2.0 LTS (target: mid-December 2026) · [#954](https://github.com/mhmtgngr/openidx/issues/954)

**No new features.** M1 covers hardening, verification, secure defaults,
installation, and release work. M1 exits when every item below is closed with
evidence.

| # | Exit criterion | Issue |
|---|---|---|
| 1 | Enforcement on by default for new installs | [#956](https://github.com/mhmtgngr/openidx/issues/956) |
| 2 | The display = enforcement table is automated and recorded for each release | [#957](https://github.com/mhmtgngr/openidx/issues/957) |
| 3 | The OpenID Connect conformance suite runs nightly in CI | [#958](https://github.com/mhmtgngr/openidx/issues/958) |
| 4 | SAML interop and SCIM compliance tests run in CI | [#955](https://github.com/mhmtgngr/openidx/issues/955) |
| 5 | Independent penetration test; ASVS L2; OpenSSF Scorecard | [#959](https://github.com/mhmtgngr/openidx/issues/959) |
| 6 | Release integrity: what is signed is what runs | [#960](https://github.com/mhmtgngr/openidx/issues/960) |
| 7 | Lite install: log in within 15 minutes on 4 GB of RAM | [#961](https://github.com/mhmtgngr/openidx/issues/961) |
| 8 | Operational evidence: restore, upgrade, alerts, SLOs | [#962](https://github.com/mhmtgngr/openidx/issues/962) |
| 9 | Honest docs: a maturity matrix and a doc diet | [#963](https://github.com/mhmtgngr/openidx/issues/963) |
| 10 | Backend robustness: DB tests in CI, the RLS bypass, the migrator, dead code | [#964](https://github.com/mhmtgngr/openidx/issues/964) |
| 11 | Console session security: an httpOnly refresh cookie and a CSP | [#965](https://github.com/mhmtgngr/openidx/issues/965) |
| 12 | The mobile client is ready for the stores; duplicate clients are frozen | [#966](https://github.com/mhmtgngr/openidx/issues/966) |
| 13 | Supply chain and CI hygiene | [#967](https://github.com/mhmtgngr/openidx/issues/967) |
| 14 | A release policy for the v2.0 LTS | [#968](https://github.com/mhmtgngr/openidx/issues/968) |
| 15 | Site configuration moved out of the product tree | [#977](https://github.com/mhmtgngr/openidx/issues/977) |
| 16 | OPA authorization made deployable: the policy parses, ships in the chart and is tested | [#980](https://github.com/mhmtgngr/openidx/issues/980) |

### M2 — First organizations (starts once the lite install works; the launch waits for M1) · [#969](https://github.com/mhmtgngr/openidx/issues/969)

- Design partner programme: three pilots in 90 days ([#971](https://github.com/mhmtgngr/openidx/issues/971))
- Three golden-path guides, each with a video ([#972](https://github.com/mhmtgngr/openidx/issues/972))
- Honest comparison pages and a launch plan ([#973](https://github.com/mhmtgngr/openidx/issues/973))
- A contributor funnel ([#974](https://github.com/mhmtgngr/openidx/issues/974))

### M3 — Wedge depth (after M1's security items) · [#970](https://github.com/mhmtgngr/openidx/issues/970)

- Vendor (third-party) access V1 ([#975](https://github.com/mhmtgngr/openidx/issues/975))
- SSH command policy for privileged sessions ([#976](https://github.com/mhmtgngr/openidx/issues/976))

## Later, when there is demand

These have no issues yet. Each one starts with an issue and, if it changes
scope, an ADR.

- **Migration importers:** Keycloak realms; users, groups and apps from Okta
  and Entra; CyberArk and KeePass vaults.
- **Connector catalogue** on top of outbound SCIM (Microsoft 365, Google
  Workspace, GitHub, Slack, Atlassian, AWS IAM Identity Center), plus a
  connector SDK.
- **Consoles for backends that already ship:** outbound SCIM, HR-driven
  joiner/mover/leaver, and SSF/CAEP.
- **Configuration as code:** Go and TypeScript SDKs generated from OpenAPI, an
  admin CLI, and a Terraform provider.
- **Compliance packs:** KVKK, BDDK, and the public-sector information security
  guide mappings; ISO 27001:2022 Annex A evidence export.
- **HA reference architecture:** 2–3 nodes, with Patroni or CloudNativePG and
  Redis Sentinel, and tested failover.
- **Code structure:** a shared service bootstrap; split `internal/access`;
  typed queries and responses; an optional all-in-one binary.
- **Differentiating bet: privileged access for AI agents.** Agent identities,
  delegation (RFC 8693), just-in-time approval, recording and the kill switch,
  plus OAuth 2.1 authorization for MCP servers.
- **MSP features:** per-organization overlay scoping, an MSP console, and
  billing and quotas.
- **Identity threat detection, EDR/MDM posture, passkey-first sign-in.**
- **Standards, when a customer asks:** OpenID4VP / EU digital identity
  wallet, OpenID Federation, FAPI 2.0.
- **iOS client, macOS agent package; SOC 2, ISO 27001 and FIPS 140-3** (after
  a commercial entity exists).

## On hold

| What | Why | Restart trigger |
|---|---|---|
| Global-scale cell architecture and DDoS programme (`docs/archive/2026-09-13-*`) | The one real deployment runs on a single VM; the scale targets are years ahead of demand | The first customer or MSP that needs more than one region |
| New pillars: WASM app virtualization, Windows app delivery | They widen scope before the core is verified | M1 exits and a design partner asks |
| Separate Kotlin Android agent (`agent-android/`) | It duplicates the Flutter app and has no tests | A customer needs Android Enterprise device-owner mode |

## Open decisions (the maintainer's)

1. **Goal:** is OpenIDX an internal product, a community open-source project,
   or a company? This decides which metrics beyond the North Star matter.
2. **Reference:** may the organization running the live deployment be named
   as a reference?
3. **Release cadence:** monthly minor releases, with v2.0 as the first LTS?
4. **Documentation language:** English first, with Turkish translations?
5. **Contact domain:** register a project domain for contact addresses, or
   stay GitHub-only?
6. **DCO for AI-authored commits:** keep the agent's sign-off, or require the
   maintainer's own before merge?
7. **Mobile identifiers:** the final mobile app ID and bundle ID.
