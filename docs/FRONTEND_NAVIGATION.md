# Frontend Navigation & Menu Management

This document describes the admin-console navigation system introduced by the
frontend menu audit, the gaps that audit found, and how to manage menus going
forward.

## Frontend surfaces in this repository

| Surface | Path | Menus? |
|---|---|---|
| Admin Console (React/Vite) | `web/admin-console` | Yes — the only navigable UI |
| Standalone e2e harness | `frontend/` | No app code, Playwright specs only |
| Keycloak login theme | `web/admin-console/keycloak-theme` | Login pages only |
| Desktop/mobile agents | `agent/`, `agent-android/` | Native, no web menus |

## Audit findings (2026-07) and resolutions

1. **Branding page unreachable** — `/branding` had a route and a page but no
   menu entry. → Added under *Platform → System*.
2. **Live Audit Dashboard dark** — `src/pages/audit/AuditDashboard.tsx`, the
   `AuditStream` component and the `audit-stream` store formed a complete
   real-time feature nothing routed to (the `frontend/e2e` suite even expected
   it at `/audit/dashboard`). → Routed at `/audit/dashboard`, menu entry
   *Audit & Reporting → Live Audit Stream*.
3. **Tenant selector unmounted** — the super_admin org switcher (with its
   `X-Org-Slug` request plumbing already live in `lib/api.ts`) existed only in
   a dead component. → Extracted to `components/tenant-selector.tsx`, mounted
   in the console header for `super_admin`.
4. **Binary role model** — the sidebar only understood `admin`, although the
   backend (`internal/auth/roles.go`) defines
   `super_admin > admin > operator > auditor / compliance_reader > user`.
   Auditors and operators logging in saw nothing but their personal pages.
   Pure `super_admin` tokens (without a literal `admin` role) saw no admin
   menus at all. → Fixed via `lib/roles.ts` + per-item `minRole`.
5. **Dead duplicate layout** — `components/layout/{Layout,Header,Sidebar}.tsx`
   was unused, shadowed by `components/layout.tsx`, and its sidebar linked to
   routes that do not exist (`/reviews`, `/audit`). → Deleted (the tenant
   selector was rescued first, see #3).
6. **Unmanageable menu source** — ~85 items hardcoded inside the layout
   component. → Moved to `src/config/navigation.ts` (single source of truth).

Still open (documented, intentionally untouched):

- `src/pages/mfa/WebAuthnCredentials.tsx` duplicates `/security-keys` with a
  richer implementation but is unrouted — decide which to keep.
- `src/lib/api/` and `src/lib/store/` directories are shadowed by the
  same-named `.ts` files and are mostly dead scaffolding.

## How navigation works now

Everything lives in **`src/config/navigation.ts`**:

```
navigation: NavDomainGroup[]        // domains → sections → items
filterNavigation({ roles, viewMode, query })  // pure filter the sidebar renders
```

### Domains

The platform's pillars are first-class, collapsible sidebar groups:

- *(personal workspace — no heading)*
- **Identity & Access (IAM)** — Identity, Applications & Federation,
  Governance, Security & MFA
- **Zero Trust Network (Ziti)** — Network Access, Devices & Endpoints
- **Privileged Access (PAM)** — vault, rotation, privileged sessions
- **Audit & Reporting** — audit trail, analytics & reports
- **AI & Intelligence**
- **Platform** — System, Developer

### Role-based visibility

Each item declares a `minRole`. `lib/roles.ts` mirrors the backend hierarchy:

| Level | Role | Sees |
|---|---|---|
| 4 | `super_admin` | everything + Tenant Mgmt + tenant selector |
| 3 | `admin` | everything except super_admin-only entries |
| 2 | `operator` | day-to-day management (users, groups, devices, sessions, MFA ops, audit) |
| 1 | `auditor` | Audit & Reporting + personal pages |
| 1 | `compliance_reader` | audit domain only (matches its backend scoping) |
| 0 | `user` | personal workspace |

### View modes (console lenses)

Operator+ users get an **Admin / Manage / Report** switcher at the top of the
sidebar. It caps the effective role level (management → operator slice,
reporting → auditor slice) so an admin can work in a focused management or
reporting console without logging out. The choice persists in `localStorage`.

### Menu search

The sidebar search box filters items by name, href, section/domain label and
per-item `keywords` (e.g. "pam", "ldap", "passkey", "reporter"). While
searching, collapsed groups are ignored so results are always visible.

## Adding a menu item

1. Add the page + `<Route>` in `src/App.tsx` (lazy export in `src/pages/index.ts`).
2. Add one entry to the right section in `src/config/navigation.ts` with an
   icon, a `minRole`, and search `keywords`.
3. Done — `src/config/navigation.test.ts` fails CI if the href has no matching
   route (or is duplicated), which is what previously let unreachable pages
   accumulate.
