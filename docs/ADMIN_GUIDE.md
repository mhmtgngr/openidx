# OpenIDX Administrator Guide

A consolidated, task-oriented guide for administering OpenIDX through the Admin
Console and Admin API. It complements:

- [`USER_GUIDE.md`](USER_GUIDE.md) — end-user + console walkthrough
- [`app-publishing.md`](app-publishing.md) — publishing apps for SSO
- [`DEPLOYMENT.md`](DEPLOYMENT.md) — production deploy & hardening
- [`docs/api/admin.md`](docs/api/admin.md) — Admin API reference
- [`multitenancy-upgrade-runbook.md`](multitenancy-upgrade-runbook.md) — multi-tenant operations

> **Live, always-current reference:** the console ships interactive API docs at
> **`/api-docs`** and an **`/api-explorer`** — use those for the exact request
> shapes of the running version.

---

## Table of Contents

1. [Accessing the console](#1-accessing-the-console)
2. [Dashboard](#2-dashboard)
3. [Identity — users, groups, roles, service accounts](#3-identity)
4. [Authentication & MFA](#4-authentication--mfa)
5. [Applications & SSO](#5-applications--sso)
6. [Access governance](#6-access-governance)
7. [Provisioning & lifecycle](#7-provisioning--lifecycle)
8. [Network & Zero Trust (ZTNA)](#8-network--zero-trust-ztna)
9. [Devices](#9-devices)
10. [Audit, analytics & compliance](#10-audit-analytics--compliance)
11. [Security & risk](#11-security--risk)
12. [Notifications](#12-notifications)
13. [Multi-tenancy & branding](#13-multi-tenancy--branding)
14. [Developer & API tools](#14-developer--api-tools)
15. [System settings & health](#15-system-settings--health)
16. [Admin API quick reference](#16-admin-api-quick-reference)

---

## 1. Accessing the console

### URLs (local docker-compose defaults)

| Surface | URL |
|---------|-----|
| Admin Console | `http://localhost:3000` |
| API Gateway | `http://localhost:8088` (APISIX) |
| OAuth/OIDC | `http://localhost:8006` |

In a deployed environment these are your configured hostnames (e.g.
`https://admin.example.com` and `https://api.example.com`); see
[`DEPLOYMENT.md`](DEPLOYMENT.md).

### Default admin credentials

The initial seed (migration v10) creates a platform admin:

```
Username: admin
Email:    admin@openidx.local
Password: Admin@123
```

Change this immediately in any non-throwaway environment (Users → admin → Reset
Password, or via `POST /api/v1/identity/users/{id}/set-password`).

### Login flow

The console uses OAuth 2.0 + PKCE. Clicking **Sign in** redirects to the OAuth
server's login page, then back to the console. Sessions can be governed by
concurrent-session limits and idle timeout (Settings → Security).

### Authorization model

Access is role-based. `super_admin` is the platform admin (may cross
organizations, with every cross-org read written to the audit log);
`admin`, `manager`, `auditor`, `developer`, `user`, and `compliance_reader`
(read-only audit) are the standard seeded roles. Most management pages require
`admin` or `super_admin`.

---

## 2. Dashboard

**Console:** `/dashboard` · **API:** `GET /api/v1/dashboard`

System overview: user/session counts, recent authentication activity, security
alerts, and service health at a glance. Start here to spot anomalies (e.g. a
spike in failed logins) before drilling into Audit or Security.

---

## 3. Identity

The core directory: who exists and what they are.

| Area | Console | Primary API |
|------|---------|-------------|
| **Users** | `/users` | `GET/POST /api/v1/identity/users`, `…/{id}` |
| **Groups** | `/groups` | `GET/POST /api/v1/identity/groups`, `…/{id}/members` |
| **Roles** | `/roles` | `GET /api/v1/identity/roles`, `…/{id}/permissions` |
| **Service accounts** | `/service-accounts` | `/api/v1/service-accounts` |

### Common tasks

- **Create a user:** Users → **Add User** (username, email, name; set a password
  or send an invitation). API note: the user endpoints use the SCIM model
  (`userName`, `name.givenName`, `emails[].value`); `/scim/v2/Users` is the
  dedicated SCIM surface.
- **Assign roles:** open a user → **Roles** → add/remove. Roles are per-org.
- **Group membership:** Groups → a group → **Manage Members**. Groups support a
  parent (sub-groups) and are used by access policies.
- **Enable/disable / reset password / delete:** row actions on `/users`. A
  disabled user cannot authenticate.
- **Bulk changes:** see [Bulk operations](#7-provisioning--lifecycle).

---

## 4. Authentication & MFA

| Area | Console | Notes |
|------|---------|-------|
| MFA management | `/mfa-management` | Per-user MFA status, enrollment stats, policies |
| MFA bypass codes | `/mfa-bypass-codes` | One-time recovery codes (audited) |
| Passwordless | `/passwordless-settings` | Magic link, passkeys, QR login |
| Hardware tokens | `/hardware-tokens` | FIDO2 / OTP hardware tokens |
| Security keys | `/security-keys` | WebAuthn credentials |
| Sessions | `/sessions` | Active sessions; revoke individually |

Supported MFA methods: **TOTP**, **WebAuthn/passkeys**, **push**, **SMS**,
**email OTP**. Configure which are enabled via `PUT /api/v1/mfa/methods`, and
require MFA via MFA policies. WebAuthn requires the console to be served over a
secure context (HTTPS or `localhost`) and a correct `WEBAUTHN_RP_ID`/origin.

---

## 5. Applications & SSO

| Area | Console | Primary API |
|------|---------|-------------|
| Applications (OAuth/OIDC clients) | `/applications` | `/api/v1/applications`, `…/{id}/sso-settings` |
| Identity providers (inbound SSO) | `/identity-providers` | `/api/v1/identity/providers` |
| Social providers | `/social-providers` | `/api/v1/admin/social-providers` |
| SAML service providers | `/saml-service-providers` | `/api/v1/admin/saml-service-providers` |
| Federation rules | `/federation-config` | `/api/v1/admin/federation/rules` |
| OAuth playground | `/oauth-playground` | — (interactive test of the OAuth flow) |
| App launcher / publishing | `/app-launcher`, `/app-publish` | see [`app-publishing.md`](app-publishing.md) |

### Register an OAuth/OIDC application

Applications → **Create** → set type (`web`, `spa`, `native`, `service`),
redirect URIs, scopes, and PKCE. Public clients (SPA/native) must use PKCE.
Configure SSO/claims under the app's **SSO Settings**. Full walkthrough:
[`USER_GUIDE.md` › Applications & SSO](USER_GUIDE.md).

---

## 6. Access governance

OpenIDX's IGA surface — request, review, and certify access.

| Area | Console | Primary API |
|------|---------|-------------|
| Access requests | `/access-requests` | `/api/v1/governance/requests`, `…/my-approvals` |
| Approval policies | `/approval-policies` | `/api/v1/governance/approval-policies` |
| Access reviews | `/access-reviews`, `/access-reviews/{id}` | `/api/v1/governance/reviews` |
| Certification campaigns | `/certification-campaigns` | `/api/v1/governance/campaigns` |
| Attestation campaigns | `/attestation-campaigns` | `/api/v1/admin/attestation-campaigns` |
| Policies | `/policies` | `/api/v1/governance/policies` |
| ABAC policies | `/abac-policies` | `/api/v1/governance/abac-policies` |
| Entitlements | `/entitlements` | `/api/v1/entitlements` |
| Delegations | `/delegations` | `/api/v1/delegations` |
| My access (self-service) | `/my-access` | — |

### Typical flows

- **Approve/deny a request:** Access Requests shows items awaiting *your*
  decision (per the approval policy's step). Approving advances or fulfils the
  request; the decision is audited.
- **Run an access review:** create a review (a set of user→resource items),
  assign a reviewer, and approve/revoke each item. Completed reviews are retained
  for compliance evidence.
- **Policies vs ABAC:** Policies are role/condition rules evaluated by the OPA
  policy engine; ABAC policies add attribute-based conditions.

---

## 7. Provisioning & lifecycle

| Area | Console | Primary API |
|------|---------|-------------|
| Directories (LDAP/AD/SCIM sync) | `/directories` | `/api/v1/directories`, `…/{id}/sync` |
| Provisioning rules | `/provisioning-rules` | `/api/v1/provisioning/rules` |
| Lifecycle policies | `/lifecycle-policies` | `/api/v1/admin/lifecycle-policies` |
| Lifecycle workflows | `/lifecycle-workflows` | `/api/v1/identity/lifecycle/workflows` |
| Bulk operations | `/bulk-operations` | `/api/v1/admin/bulk-operations` |

- **Directory sync:** connect an LDAP/AD or SCIM source; trigger a sync with
  `POST /api/v1/directories/{id}/sync`. Synced users/groups are marked with their
  source and directory ID.
- **Joiner/mover/leaver:** model onboarding/offboarding with lifecycle policies
  and workflows (e.g. auto-assign groups on join, revoke on disable).
- **Bulk operations:** enable/disable/delete users, assign/remove roles, add to
  group, or force password reset across many users at once.
- **SCIM 2.0:** OpenIDX is a SCIM provider at `/scim/v2/Users` and
  `/scim/v2/Groups`; see [`SCIM.md`](SCIM.md).

---

## 8. Network & Zero Trust (ZTNA)

OpenIDX bundles OpenZiti-based Zero Trust network access.

| Area | Console | Notes |
|------|---------|-------|
| Proxy routes | `/proxy-routes` | Reverse-proxy/app routes behind the access proxy |
| Ziti network | `/ziti-network` | Fabric overview, edge routers |
| Ziti discovery | `/ziti-discovery` | Discover services/identities |
| Device trust approval | `/device-trust-approval` | Approve/deny device trust requests |
| BrowZer management | `/browzer-management` | Clientless (browser) Zero Trust access |
| Remote support | `/remote-support` | Guacamole-based remote sessions (recorded) |
| Kiosk policies | `/kiosk-policies` | Kiosk-mode access policies |
| Certificates | `/certificates` | Ziti / service certificates |

These features require the Ziti controller/router and (for BrowZer/remote)
their supporting services to be running — see the docker-compose stack and
[`ACCESS_SETUP.md`](../ACCESS_SETUP.md).

---

## 9. Devices

| Area | Console | Audience |
|------|---------|----------|
| Devices (all) | `/devices` | admin |
| Trusted browsers | `/trusted-browsers` | admin / self |
| Push devices | `/push-devices` | admin / self |
| My devices | `/my-devices` | self-service |

Review enrolled/known devices, device posture results, and revoke trust. Device
trust requests from new devices are approved under
[Device trust approval](#8-network--zero-trust-ztna).

---

## 10. Audit, analytics & compliance

| Area | Console | Primary API |
|------|---------|-------------|
| Audit logs | `/audit-logs` | `GET /api/v1/audit/events` |
| Unified audit | `/unified-audit` | `/api/v1/access/audit/unified` |
| Admin audit log | `/admin-audit-log` | `/api/v1/admin/admin-audit` |
| Audit archival | `/audit-archival` | `/api/v1/admin/audit-archives`, `…/audit-retention` |
| Compliance dashboard | `/compliance-dashboard` | `/api/v1/compliance-posture` |
| Compliance reports | `/compliance-reports` | `POST /api/v1/audit/reports` |
| ISPM (posture) | `/ispm` | `/api/v1/ispm/{score,findings,rules}` |
| Consent management | `/consent-management` | `/api/v1/admin/privacy/consents` |
| Privacy dashboard (GDPR/DSAR) | `/privacy-dashboard` | `/api/v1/admin/privacy/*` |
| Reports | `/reports` | — |
| Login analytics | `/login-analytics` | `/api/v1/identity/analytics/logins` |
| Auth / usage / predictive analytics | `/auth-analytics`, `/usage-analytics`, `/predictive-analytics` | `/api/v1/admin/analytics/*` |

- **Investigate:** Audit Logs supports filtering by actor, event type, outcome
  (e.g. `failure`), and time. Every privileged action — user/role changes,
  governance decisions, platform-admin cross-org reads — is recorded.
- **Compliance evidence:** generate reports (`POST /api/v1/audit/reports`) and
  use completed access reviews / certification campaigns as attestation.
- **Retention/archival:** configure how long audit data is kept and archived.

---

## 11. Security & risk

| Area | Console | Primary API |
|------|---------|-------------|
| Risk dashboard | `/risk-dashboard` | `/api/v1/admin/analytics/risk` |
| Risk policies | `/risk-policies` | `/api/v1/identity/risk/policies` |
| Security alerts | `/security-alerts` | `/api/v1/security-alerts` |
| Login anomalies | `/login-anomalies` | `/api/v1/risk/anomalies` |
| AI agents / recommendations | `/ai-agents`, `/ai-recommendations`, `/agent-fleet` | `/api/v1/ai-agents`, `/api/v1/recommendations` |

Risk policies drive adaptive auth (e.g. step-up MFA on anomalous logins). The
risk dashboard and login-anomaly views surface suspicious activity (impossible
travel, new device, failed-login bursts) for triage.

---

## 12. Notifications

| Area | Console | Primary API |
|------|---------|-------------|
| Notification admin (broadcasts, routing) | `/notification-admin` | `/api/v1/admin/notifications/*` |
| Notification center | `/notification-center` | `/api/v1/notifications/*` |
| Preferences | `/notification-preferences` | `/api/v1/identity/notifications/preferences` |
| Email templates & branding | `/email-templates` | `/api/v1/admin/email-templates`, `…/email-branding` |

Configure delivery channels (in-app, email), routing rules, broadcast messages,
and customize transactional email templates and branding.

---

## 13. Multi-tenancy & branding

| Area | Console | Primary API |
|------|---------|-------------|
| Organizations | `/organizations` | `/api/v1/organizations` |
| Tenant management | `/tenant-management` | `/api/v1/admin/organizations` |
| Branding | `/branding` | `/api/v1/tenants/{orgId}/branding` |

OpenIDX is multi-tenant (v1.6+): every record is scoped to an `org_id`, enforced
in the app layer **and** by a Postgres Row-Level-Security belt. Per-tenant
**branding** (logo, colors, login title/message, custom CSS, footer, favicon) is
edited here and applied to both the SPA and the server-rendered OAuth login page;
the public read endpoint is `GET /api/v1/identity/branding?org=<slug>|domain=<d>`.

Operational details (subdomains, `TENANT_BASE_DOMAIN`, `DEFAULT_ORG_FALLBACK`,
the RLS belt, platform-admin cross-org access):
[`DEPLOYMENT.md` § Multi-tenancy](DEPLOYMENT.md#step-4b--multi-tenancy-and-row-level-security-v16),
[`v2-multitenancy-design.md`](v2-multitenancy-design.md), and the
[upgrade runbook](multitenancy-upgrade-runbook.md).

---

## 14. Developer & API tools

| Area | Console | Notes |
|------|---------|-------|
| API docs | `/api-docs` | Interactive OpenAPI for the running version |
| API explorer | `/api-explorer` | Try endpoints from the browser |
| Developer settings | `/developer-settings` | API keys, dev config |
| Webhooks | `/webhooks` | Outbound event subscriptions |
| Error catalog | `/error-catalog` | Reference for API error codes |

- **API keys / service tokens:** issue under Developer Settings / Service
  Accounts; keys carry an org scope and are validated on the auth path.
- **Webhooks:** subscribe to events (e.g. `user.created`); deliveries are
  tracked and retried.

---

## 15. System settings & health

| Area | Console | Primary API |
|------|---------|-------------|
| Settings | `/settings` | `GET/PUT /api/v1/settings` (+ `/settings/sms`) |
| System health | `/system-health` | service `/health`, `/health/ready` |

Settings covers general, security (CSRF, CORS, session limits, idle timeout),
SMS/SMTP, password policy, and feature toggles. **Production startup is gated** —
services refuse to boot with insecure config (`APP_ENV=production`); see the
[production config checklist](DEPLOYMENT.md#production-config-checklist).

---

## 16. Admin API quick reference

Base path `/api/v1`, fronted by the API gateway. All calls require a Bearer
access token from the OAuth server; admin endpoints require an admin role.

| Domain | Base |
|--------|------|
| Identity (users/groups/roles) | `/api/v1/identity/...` |
| SCIM 2.0 | `/scim/v2/Users`, `/scim/v2/Groups` |
| OAuth/OIDC | `/oauth/*`, `/.well-known/openid-configuration` |
| Governance | `/api/v1/governance/...` |
| Audit | `/api/v1/audit/...` |
| Admin (dashboard/settings/apps/analytics) | `/api/v1/admin/...`, `/api/v1/applications`, `/api/v1/settings`, `/api/v1/dashboard` |
| Access/ZTNA | `/api/v1/access/...` |
| Risk | `/api/v1/risk/...` |

Authoritative, version-specific request/response shapes: the console's
**`/api-docs`** + [`docs/api/admin.md`](docs/api/admin.md) and the per-service
references under [`docs/api/`](docs/api/).

---

*This guide maps the Admin Console feature surface as of the current branch. For
deployment and hardening see [`DEPLOYMENT.md`](DEPLOYMENT.md); for end-user
instructions see [`USER_GUIDE.md`](USER_GUIDE.md).*
