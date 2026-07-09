# API Contract Integrity Audit — IAM / Ziti / PAM

Companion to `docs/FRONTEND_NAVIGATION.md`. This audit cross-checked the
admin-console's ~505 API calls against the real backend HTTP surface of the
IAM (identity/governance/provisioning/admin), Ziti (access), and PAM
(vault/credentials/guacamole) services.

Method: the backend routes were enumerated from the live gin routers (not
guessed) — for admin-api by registering `admin.RegisterRoutes`,
`adminhandlers.RegisterAllRoutes`, and `organization.RegisterRoutes` on a
`/api/v1` group and dumping `router.Routes()` (261 routes) — and corroborated
against `api/openapi/*.yaml` and the APISIX route configs
(`deployments/docker/apisix/`, `load-production-routes.sh`).

## FIXED — erroneous `/api/v1/admin/` prefix (frontend was calling 404s)

**Finding.** admin-api registers every route directly under `/api/v1/*`
(e.g. `/api/v1/social-providers`, `/api/v1/dashboard`, `/api/v1/directories`).
There is **no `/api/v1/admin/*` namespace** anywhere: not in the gin routers,
not in `admin-api.yaml`, and neither APISIX nor the Go gateway rewrites one in
(`httputil.NewSingleHostReverseProxy` rewrites host only; the production APISIX
loader routes `/api/v1/dashboard|settings|applications|users` with no
`proxy-rewrite`). Yet 84 admin-console call sites called `/api/v1/admin/...`,
which 404s in every deployment. The regression was masked because the e2e suite
**mocks** those URLs (`page.route('**/api/v1/admin/...')`) and no integration
test hits them for real. The same resources were even called both ways in the
frontend (`/api/v1/applications/:id` worked; `/api/v1/admin/applications/:id/claims`
did not), confirming frontend drift rather than an intended gateway prefix.

**Fix.** Corrected all 84 call sites to the verified backend paths:

- 61 distinct paths: dropped the `/admin/` segment (`/api/v1/admin/social-providers`
  → `/api/v1/social-providers`, etc.).
- Renamed endpoints (backend name differs, not just the prefix):
  - `/api/v1/admin/admin-audit` → `/api/v1/audit-log`
  - `/api/v1/admin/developer/api-endpoints` → `/api/v1/developer/api-catalog`
  - `/api/v1/admin/developer/playground/session` → `/api/v1/developer/playground/sessions`

**Regression guard.** `src/lib/api-contract.test.ts` fails the build if any
source file references `/api/v1/admin/` again.

## FIXED (frontend) / OPEN (gateway) — SAML Service Provider management

The SAML SP admin API is served by **oauth-service** at
`/api/v1/saml/service-providers` (`internal/oauth/saml.go:1194`), and IdP
metadata at `/saml/idp/metadata`. The console was calling
`/api/v1/admin/saml-service-providers` and `/api/v1/oauth/saml/idp/metadata` —
wrong on both the `/admin` prefix and the path shape.

- **Fixed (frontend):** `src/pages/saml-service-providers.tsx` now calls
  `/api/v1/saml/service-providers[...]` and `/saml/idp/metadata`, matching the
  backend contract.
- **Still open (gateway):** APISIX routes only `/oauth/*` and `/.well-known/*`
  to oauth-service; it does **not** route `/api/v1/saml/*` or `/saml/*`. So SAML
  SP management stays unreachable until a gateway route is added. Suggested
  addition to `deployments/docker/apisix/apisix.yaml` (and the equivalent
  upstream in `load-production-routes.sh`):

  ```yaml
  - uri: /api/v1/saml/*
    name: oauth-saml-sp-api
    upstream: { type: roundrobin, nodes: { "oauth-service:8006": 1 } }
  - uri: /saml/*
    name: oauth-saml-idp
    upstream: { type: roundrobin, nodes: { "oauth-service:8006": 1 } }
  ```

  This is deployment-affecting and left for a deliberate infra review rather
  than bundled here.

## OPEN — backend authorization gaps (report-only, need a product decision)

These are backend design questions; nothing was changed. Verified via the
service route maps.

1. **Ziti admin routes missing a role gate.** Agent-fleet
   (`internal/access/agent_api.go`), kiosk (`kiosk_api.go`), and remote-support
   (`remote_support_api.go`) admin routes are registered on the authenticated
   `/api/v1/access` group but, unlike the Ziti/BrowZer mutation routes, do
   **not** apply `svc.requireAdminRole()`. Any authenticated caller can reach
   them. Consider adding the admin gate.

2. **Governance & provisioning/SCIM are JWT-only.** `internal/governance` and
   `internal/provisioning` enforce authentication but apply RBAC **only** when
   `ENABLE_OPA_AUTHZ` is set (off by default). Access reviews, policies, and
   SCIM user/group provisioning have no static role guard otherwise.

3. **admin-api's role-guarded route registrar is dead code.**
   `internal/admin/handler.go` `RegisterAdminRoutes` (with
   `RequireRole("super_admin","admin")`) is never wired; the live surface is the
   unguarded `service.go` `RegisterRoutes`, protected only by
   `PermissionResolver` + resolved permissions. The only runtime role gate in
   admin-api is `RequireAdmin()` on the vault/rotation (PAM) group.

4. **PAM guards use literal role matching, not the hierarchy.** Vault, rotation,
   and guacamole-admin routes check `role == "admin" || role == "super_admin"`
   directly rather than `auth.RoleAdmin.IsHigherOrEqual`. Operators/auditors are
   denied all PAM management, which is intended, but the vault code comments
   claim hierarchy derivation it doesn't actually perform.

## OPEN — PAM feature gaps (report-only)

- **No Guacamole session-recording download.** Recordings are written by guacd
  and their path stored, and legal-hold/retention APIs exist, but there is no
  endpoint to retrieve the recording artifact — only the live transcript
  (`internal/access/guacamole_sessions.go`).
- **Rotation scheduler is admin-api-only.** `credentials.StartScheduler` is
  wired in `cmd/admin-api`; an access-service-only deployment mounts neither the
  rotation routes nor the scheduler.

## Menu ↔ backend role alignment

The sidebar `minRole` tiers (`src/config/navigation.ts`) mirror
`internal/auth/roles.go`. Note that identity-service gates all non-self-service
user/group routes behind admin/super_admin (`requireAdminUnlessSelfService`),
which is stricter than the `operator` permissions the RBAC model grants — so an
operator may see a management-tier menu item that the identity service still
403s. This is a backend-consistency question (blunt admin gate vs. the
permission model) flagged for follow-up, not worked around in the menu.
