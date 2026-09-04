# OpenIDX Documentation Map

This directory mixes two very different kinds of writing, and telling them
apart matters:

- **Product documentation** — written for people running or evaluating
  OpenIDX. Kept current; if one of these contradicts the code, that is a
  bug ([PROJECT-READINESS-GUIDE.md §7](./PROJECT-READINESS-GUIDE.md)).
- **Engineering artifacts** — design documents, implementation plans,
  audits and reviews written *for contributors at a point in time*. They
  describe the thinking, not necessarily the current behavior. Nothing in
  them overrides a product doc.

The **published documentation site** (mkdocs, built from
[`docs/docs/`](./docs/) via [`mkdocs.yml`](./mkdocs.yml)) is the curated
front door; this directory is the full depth behind it.

---

## Start here (product docs)

| Doc | What it answers |
|---|---|
| [../README.md](../README.md) | **The** quick start (Docker Compose, generated secrets) — maintained in exactly one place |
| [GETTING-STARTED.md](./GETTING-STARTED.md) | Developer setup from source + first-time tasks incl. the authoritative **First Login** |
| [USER_GUIDE.md](./USER_GUIDE.md) | End-user walkthrough of the portal and console |
| [DEPLOYMENT.md](./DEPLOYMENT.md) | Production deployment reference |
| [PRODUCTION-READINESS.md](./PRODUCTION-READINESS.md) | Deploy-side readiness view |
| [PROJECT-READINESS-GUIDE.md](./PROJECT-READINESS-GUIDE.md) | User-perspective readiness: mental model, journey scorecard, P0–P4 program, recurring controls |
| [RELEASING.md](./RELEASING.md) | How releases are cut |
| [disaster-recovery.md](./disaster-recovery.md) | Backup/restore and DR drills |

## Security & compliance (product docs)

| Doc | What it answers |
|---|---|
| [SECURITY-HARDENING.md](./SECURITY-HARDENING.md) | The enforced production config gates (`ValidateProduction()`) and hardening checklist |
| [SECURITY-TENANCY.md](./SECURITY-TENANCY.md) | The tenant boundary: FORCE row-level security in depth |
| [THREAT-MODEL.md](./THREAT-MODEL.md) | Trust boundaries, per-component STRIDE, residual risks R1–R8 |
| [COMPLIANCE-CONTROL-MAPPING.md](./COMPLIANCE-CONTROL-MAPPING.md) | SOC 2 / ISO 27001:2022 → capability → evidence |
| [OPENBAO_KEK.md](./OPENBAO_KEK.md) | Vault KEKs from OpenBao instead of env |

## Concepts & architecture (product docs)

[IAM_PAM_ZITI_INTERRELATION.md](./IAM_PAM_ZITI_INTERRELATION.md) (the best
conceptual doc — how the pillars share one spine),
[how-network-access-works.md](./how-network-access-works.md),
[zero-trust-architecture.md](./zero-trust-architecture.md),
[OPENIDX_ZITI_ARCHITECTURE.md](./OPENIDX_ZITI_ARCHITECTURE.md),
[OPENIDX_CLIENTLESS_EDGE_ARCHITECTURE.md](./OPENIDX_CLIENTLESS_EDGE_ARCHITECTURE.md),
[v2-multitenancy-design.md](./v2-multitenancy-design.md).

## Feature & integration guides (product docs)

Identity/OAuth: [OAUTH-OIDC.md](./OAUTH-OIDC.md),
[TOKEN_EXCHANGE_AND_DCR.md](./TOKEN_EXCHANGE_AND_DCR.md),
[MFA_IMPLEMENTATION_GUIDE.md](./MFA_IMPLEMENTATION_GUIDE.md),
[PASSWORDLESS_AND_PUSH_MFA_IMPLEMENTATION.md](./PASSWORDLESS_AND_PUSH_MFA_IMPLEMENTATION.md),
[windows/mfa-without-a-phone.md](./windows/mfa-without-a-phone.md).
Provisioning: [SCIM.md](./SCIM.md), [OUTBOUND_SCIM.md](./OUTBOUND_SCIM.md),
[HR_DRIVEN_JML.md](./HR_DRIVEN_JML.md), [SSF_CAEP.md](./SSF_CAEP.md).
ZTNA: [PUBLISHING_A_SERVICE.md](./PUBLISHING_A_SERVICE.md),
[app-publishing.md](./app-publishing.md),
[ZITI_EASY_DEPLOYMENT.md](./ZITI_EASY_DEPLOYMENT.md),
[ZITI_HA_DEPLOYMENT.md](./ZITI_HA_DEPLOYMENT.md),
[ziti-nat-firewall-requirements.md](./ziti-nat-firewall-requirements.md),
[host-firewall-baseline.md](./host-firewall-baseline.md),
[enterprise-lb-firewall-integration.md](./enterprise-lb-firewall-integration.md),
[browzer-public-vhost-generator.md](./browzer-public-vhost-generator.md).
Posture/EDR: [EDR_MDM_POSTURE.md](./EDR_MDM_POSTURE.md),
[WAZUH_EDR_INTEGRATION.md](./WAZUH_EDR_INTEGRATION.md).
Notifications: [NTFY_PUSH_NOTIFICATIONS.md](./NTFY_PUSH_NOTIFICATIONS.md).
Mobile: the client is the Flutter app in [`client/`](../client), over the same
Go engine as the desktop agent. The API contracts below are still current; their
file references point at the deleted Expo prototype and are being retargeted:
[mobile-authenticator-developer-guide.md](./mobile-authenticator-developer-guide.md),
[mobile-openziti-integration-guide.md](./mobile-openziti-integration-guide.md),
[mobile-mfa-and-ziti-posture-access.md](./mobile-mfa-and-ziti-posture-access.md),
[mobile/firebase-fcm-setup.md](./mobile/firebase-fcm-setup.md).
API: [../api/openapi/](../api/openapi/) — per-service OpenAPI specs,
including the full `/pam/*` surface in `access-service.yaml`
([api/](./api/) here is the Swagger-UI viewer for them).

## Runbooks (product docs)

[GOING_DARK_RUNBOOK.md](./GOING_DARK_RUNBOOK.md),
[multitenancy-upgrade-runbook.md](./multitenancy-upgrade-runbook.md),
[remote-support-runbook.md](./remote-support-runbook.md),
[tier3b-cutover-runbook.md](./tier3b-cutover-runbook.md),
[openidx-k8s-always-on.md](./openidx-k8s-always-on.md),
[ci-over-ziti-overlay.md](./ci-over-ziti-overlay.md),
[remote-access-lifecycle-scenarios.md](./remote-access-lifecycle-scenarios.md).

---

## Engineering artifacts (contributor-facing; point-in-time)

Design docs, plans, audits and reviews. Read them for the *why*; verify
any *what* against the code before relying on it.

- **Plans & designs**: [plans/](./plans/) (the convergence rollout plan
  lives here), [access-model-redesign.md](./access-model-redesign.md),
  [access-and-login-convergence-design.md](./access-and-login-convergence-design.md),
  [architecture/](./architecture/) (per-topic design notes and reviews),
  [IMPLEMENTATION_PLAN_PARALLEL.md](./IMPLEMENTATION_PLAN_PARALLEL.md),
  [selfheal/](./selfheal/) (self-heal loop design + runbook),
  [ux-audit/](./ux-audit/) (admin-console UX audit and UI roadmap).
- **Audits & reviews**:
  [API_CONTRACT_INTEGRITY_AUDIT.md](./API_CONTRACT_INTEGRITY_AUDIT.md),
  [production-audit-2026-07-16.md](./production-audit-2026-07-16.md),
  [architecture-and-ha-review.md](./architecture-and-ha-review.md).
- **Contributor references**:
  [DESIGN_PATTERNS.md](./DESIGN_PATTERNS.md),
  [PATTERN_EXAMPLES.md](./PATTERN_EXAMPLES.md),
  [FRONTEND_NAVIGATION.md](./FRONTEND_NAVIGATION.md),
  [SCIM-FEATURES-LOCATION.md](./SCIM-FEATURES-LOCATION.md),
  [DEV-BRANCH-SUMMARY.md](./DEV-BRANCH-SUMMARY.md).

## Historical (superseded — kept for context, bannered)

[PROJECT-STATUS.md](./PROJECT-STATUS.md),
[FEATURE_PRIORITY_PLAN.md](./FEATURE_PRIORITY_PLAN.md) — both carry
banners pointing at the current docs.

## Türkçe / Turkish-language docs

- [FEATURE_TEST_GUIDE_TR.md](./FEATURE_TEST_GUIDE_TR.md) — uçtan uca
  özellik test rehberi (end-to-end feature test guide, Turkish).
- [openidx-trafik-mimarisi.md](./openidx-trafik-mimarisi.md) — trafik
  yönetimi mimarisi (traffic management architecture, Turkish).
