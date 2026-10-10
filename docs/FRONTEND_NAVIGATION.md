# Frontend Navigation & Menu Management

This document describes the admin-console navigation system introduced by the
frontend menu audit, the gaps that audit found, and how to manage menus going
forward.

## Frontend surfaces in this repository

| Surface | Path | Menus? |
|---|---|---|
| Admin Console (React/Vite) | `web/admin-console` | Yes — the only navigable UI |
| Browser journey suite | `web/admin-console/e2e` | No app code, Playwright specs only |
| Mobile client (Flutter) | `client/` | Native, no web menus |
| Desktop/Android agents | `agent/`, `agent-android/` | Native, no web menus |

Two surfaces this table used to list are gone and are not coming back: the
standalone `frontend/` harness (its specs live in `web/admin-console/e2e`
now) and `web/admin-console/keycloak-theme` — OpenIDX is its own IdP and
renders its own login, so there is no Keycloak theme to style. The Expo
`mobile/` tree was deleted in favour of `client/`.

## Audit findings (2026-07) and resolutions

1. **Branding page unreachable** — `/branding` had a route and a page but no
   menu entry. → Added under *Platform → System*.
2. **Live Audit Dashboard dark** — `src/pages/audit/AuditDashboard.tsx`, the
   `AuditStream` component and the `audit-stream` store formed a complete
   real-time feature nothing routed to (the browser journey suite even
   expected it at `/audit/dashboard`). → Routed at `/audit/dashboard`, menu
   entry *Audit & Reporting → Live Audit Stream*.
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

Both items this section left open have since been closed, in the direction
the audit implied:

- `src/pages/mfa/WebAuthnCredentials.tsx` — deleted. `/security-keys` is the
  one passkey surface, and it has a test.
- `src/lib/api/` and `src/lib/store/` — deleted. The shadowing `.ts` files
  (`lib/api.ts`, `lib/store.ts`) were the live ones all along; a directory
  that shadows a module is a trap for the next reader, not scaffolding.

## How navigation works now

Everything lives in **`src/config/navigation.ts`**:

```
navigation: NavDomainGroup[]        // groups → items → children (one level)
filterNavigation({ roles, viewMode, query })  // pure filter the sidebar renders
findNavPath(pathname)               // group / parent / page, for breadcrumbs
```

### Groups

Seven collapsible groups, in the order an administrator thinks — what people
reach, who they are, what they reach it from, how it is protected, what
happened, how the platform is set up:

- *(personal workspace — no heading)* — Dashboard, My Apps & Network, My
  Access, My Devices, My Security, My Profile
- **Resources & Access** — Applications, Network Services, Privileged
  Connections, PAM Overview, Access Policies, Access Reviews, Overlay
  Network, Remote Support
- **Identity** — Users, Groups, Roles, Organizations, Identity Providers,
  Lifecycle, Privacy
- **Devices** — Devices, Agent Fleet, Kiosk Policies
- **Security** — MFA, Sessions, Risk & Alerts, Security Posture, Enforcement
- **Audit & Reporting** — Audit Logs, Analytics, Risk Dashboard, Compliance,
  Reports
- **Settings** — System Health, Settings, Notification Mgmt, Developer

The sidebar shows at most `NAV_TOP_LEVEL_LIMIT` (40) top-level entries;
`navigation.test.ts` enforces it. Every other page is a **child** of one of
them (`children` on the item) and appears indented beneath its parent while
the parent or one of its children is the current page, or after a click on
the parent's chevron. The command palette offers every page, parent or
child; breadcrumbs read *group / parent / page* and link the parent.

Two rules keep a child from disappearing: a child the caller may see under
a parent they may not (Network Topology is an operator page under the
admin-only Overlay Network) is lifted to the group on its own, and a search
answers with a flat list of matching pages — a child also matches its
parent's name, so "overlay" finds Network Topology.

### Role-based visibility

Each item declares a `minRole`. `lib/roles.ts` mirrors the backend hierarchy:

| Level | Role | Sees |
|---|---|---|
| 4 | `super_admin` | everything + Tenant Mgmt; the tenant selector only when the role is held in the default organization |
| 3 | `admin` | everything except super_admin-only entries |
| 2 | `operator` | day-to-day management (users, groups, devices, sessions, MFA ops, audit) |
| 1 | `auditor` | Audit & Reporting + personal pages |
| 1 | `compliance_reader` | audit group only (matches its backend scoping) |
| 0 | `user` | personal workspace |

The tenant selector acts in other organizations, which only a platform admin
may do: `super_admin` held in the default organization, read from the token's
`org_id` (`lib/platform-admin.ts`, the same rule as
`middleware.IsPlatformAdmin`). Nobody else sees it, and a selection left in
storage is not sent with anyone else's requests.

`minRole` hides a menu entry; it does not stop a typed URL. Pages that only
administrators can use are also wrapped in `AdminRoute` in `App.tsx`:
Applications, SAML Providers, Proxy Routes and Upstream Pools (whose APIs
answer administrators only, reads included), Quick Links admin, Vault
Secrets, Rotation Policies, the PAM dashboard, Guacamole sessions and
Access 360. Anyone else is sent to the dashboard rather than shown a page of
refused requests.

### View modes (console lenses)

Operator+ users get an **Admin / Manage / Report** switcher at the top of the
sidebar. It caps the effective role level (management → operator slice,
reporting → auditor slice) so an admin can work in a focused management or
reporting console without logging out. The choice persists in `localStorage`.

### Menu search

The sidebar search box filters pages by name, href, group label, parent name
and per-item `keywords` (e.g. "pam", "ldap", "passkey", "reporter"). While
searching, collapsed groups are ignored so results are always visible.

## Adding a menu item

1. Add the page + `<Route>` in `src/App.tsx` (lazy export in `src/pages/index.ts`).
2. Add one entry in `src/config/navigation.ts` with an icon, a `minRole`,
   and search `keywords` — as a child of the page it belongs under, unless
   it is a daily stop that earns one of the top-level slots.
3. Done — `src/config/navigation.test.ts` fails CI if the href has no matching
   route (or is duplicated), which is what previously let unreachable pages
   accumulate.
