# OpenIDX "Dark Platform" — Ziti-first public surface (design)

**Date:** 2026-07-17
**Status:** design (approved via brainstorming; not yet planned/implemented)
**Owner:** platform / access
**Related:**
[`docs/OPENIDX_ZITI_ARCHITECTURE.md`](../../OPENIDX_ZITI_ARCHITECTURE.md) §12 (dark services),
[`docs/OPENIDX_CLIENTLESS_EDGE_ARCHITECTURE.md`](../../OPENIDX_CLIENTLESS_EDGE_ARCHITECTURE.md),
[`docs/remote-access-lifecycle-scenarios.md`](../../remote-access-lifecycle-scenarios.md),
[`docs/mobile-authenticator-developer-guide.md`](../../mobile-authenticator-developer-guide.md).

---

## 1. Goal

Make the OpenIDX **platform itself** "dark": remove its management and data surfaces
from the public internet so it is invisible to scanners, and require an **enrolled
OpenZiti identity** to reach anything beyond a single hardened front door. Access is
**Ziti-first by design**: the overlay is the primary network path, not an add-on.

OpenIDX already darkens *target apps* (BrowZer WASM + native Ziti clients, see
`OPENIDX_ZITI_ARCHITECTURE.md §12`). This design turns that capability on **OpenIDX's own
services**, and OpenIDX dogfoods its own product.

### Non-goals
- Not air-gapping or a hardware appliance. "Dark" here = **loopback-bound services +
  overlay-only reach + policy on the overlay + forward-auth on the management tier**. A
  network firewall is a complementary belt for prod (§7), not the enforcement mechanism.
- Not changing the identity/OAuth/MFA semantics. The token you get is the same; only the
  *network reachability* of the surfaces changes.
- Not a rewrite. No new enforcement engine — this reuses the existing
  `ziti_reconciler`, access-proxy forward-auth, and loopback-bind pattern.

---

## 2. The bootstrap paradox (why a naive "make everything dark" fails)

OpenIDX **is** the identity provider. To join the overlay a device needs an **enrollment
JWT**, which OpenIDX mints. So "you must authenticate to OpenIDX to get on the overlay
that lets you reach OpenIDX" is circular. Something must stay reachable to break the
circle. The design resolves this with **progressive darkness (tier C)**: a tiny,
data-free public bootstrap tier, everything else dark.

---

## 3. The three tiers

The organizing principle: **authenticating to get a token is public; *using* your
identity is overlay+identity; *managing the platform or touching privileged data* is
overlay+trusted-device.**

### Tier 0 — Public (raw internet, hardened, carries no data)
The only listeners on `:443`. Minimal, rate-limited, audited, no DB browsing.
- **`enroll` front door** — the token → Ziti-enrollment-JWT exchange (§4).
- **BrowZer bootstrapper** + WASM + service worker (the existing `:8445` bootstrapper).
- **OIDC/JWKS auth surface** the bootstrapper and native login need to complete a login:
  `/.well-known/*`, `/oauth/authorize[/v2]`, `/oauth/token`, `/oauth/native/login-init`,
  `/oauth/login`, `/oauth/passkey-begin|finish`, `/oauth/mfa-*` (login-time MFA).
- **Public login-page branding** endpoint (`/api/v1/identity/branding`, already public
  and tenant-resolving, already a `tenantSkipPath`).

Rationale: these are exactly the surfaces required to *obtain* an identity/token. They
hold no user data, are already hardened (PKCE-only, serve-stale JWKS, rate limits), and
are the gate BrowZer itself needs. Everything else moves off `:443`.

### Tier 1 — Overlay + any enrolled identity (dark)
Reachable only over the overlay by a device holding **any** enrolled OpenIDX identity
(Ziti attribute `#enrolled-users`).
- User self-service: `GET /oauth/userinfo`, own MFA management
  (`/api/v1/identity/mfa/*`), "My Access", notifications, own sessions.
- The **admin-console SPA shell** (static assets) — served over the overlay via BrowZer
  (§5). Harmless HTML/JS, but we dark it too so the platform presents *nothing* but the
  Tier-0 gate publicly.
- Approvals inbox (a user acting on their own approvals).

### Tier 2 — Overlay + device-trust required (dark, highest value)
Reachable only over the overlay by a **trusted device** (Ziti attribute
`#device-trusted`) **and** re-checked by the access-proxy forward-auth on the HTTP data
plane (defense in depth).
- **admin-api** (`:8005`), **governance** (`:8002`), **audit** read/stream (`:8004`),
  **provisioning/SCIM** (`:8003`), **access-service admin** (`:8007`).
- OAuth **client management**, Ziti **identity/service management**, **PAM launch**,
  audit export.

> **Audit ingestion exception:** `POST /api/v1/audit/events` (internal service→audit
> ingestion) stays reachable *service-to-service on loopback*, not public, not
> user-facing — same as today. It is never a public route.

```
                    Internet
                       │
              ┌────────▼─────────┐   Tier 0 (public, data-free)
              │ enroll · BrowZer │   :443 only
              │ OIDC/JWKS gate   │
              └────────┬─────────┘
                       │ mint Ziti identity / OIDC token
              ┌────────▼─────────┐   OpenZiti overlay
              │   enrolled       │
        ┌─────┤   identity       ├─────┐
        │     └──────────────────┘     │
   #enrolled-users               #device-trusted
        │                              │
 ┌──────▼───────┐              ┌───────▼────────┐
 │ Tier 1 (dark)│              │ Tier 2 (dark)  │
 │ self-service │              │ admin/gov/audit│
 │ console shell│              │ SCIM/PAM/access│
 └──────────────┘              │ + forward-auth │
                               └────────────────┘
```

---

## 4. Enrollment front door (Tier 0) — the `enroll` service

A **new, minimal, single-purpose** public endpoint. It is the *only* new public surface.
It does exactly one thing: prove the caller is entitled, then hand back a **one-time Ziti
enrollment JWT** for their device identity. No listing, no user data, no admin surface.

Entitlement proof — any one of:
1. **Enrollment token** — an admin/MDM-issued, single-use, expiring token (reuses the
   existing `agent_tokens` + `POST /api/v1/access/agent/qr` machinery).
2. **Valid OpenIDX session** — a live access token / refresh token (self-service: an
   already-logged-in user enrolls a new device of their own).
3. **Passkey** — a platform authenticator assertion for the user (device recovery
   without an admin).

Response: `{ "ziti_enrollment_jwt": "…", "identity_name": "<user-or-device>", "expires_at": … }`.
The native client or mobile app feeds this to the Ziti SDK (`OidxZiti.enroll(jwt)`), and
the desktop tunnel enrolls the same way.

Properties:
- Aggressively **rate-limited + audited** (every issuance is an audit event).
- **No database browse path** — it only writes an enrollment record and returns a JWT.
- Runs as its own tiny handler (can live in access-service behind a distinct route
  guarded so it is the *only* `/api/v1/access/*` path public; everything else access-side
  goes dark). Alternatively a separate `cmd/enroll-service` if we want a separate blast
  radius — **decided: keep it in access-service** as a dedicated public route to avoid a
  new deployable, but it is the single access-service route left on `:443`.

Out-of-band paths remain first-class (zero-public enrollment for a managed fleet):
- **Android QR/MDM** — existing `POST /api/v1/access/agent/qr` provisioning payload.
- **Admin-issued `.jwt`** — existing Ziti identity enrollment JWT download.

---

## 5. Browser access — BrowZer-gate the admin console

A browser has no Ziti identity. Rather than force every admin onto a native tunnel, the
**admin console becomes a dark BrowZer app**, exactly like `psm.tdv.org` /
`netgraph.tdv.org` today:

1. Browser → `console.tdv.org` (`:443`, Tier 0 edge).
2. Edge forwards to the **BrowZer bootstrapper**, which serves the WASM + service worker
   and runs an **OIDC login against OpenIDX's own OAuth** (Tier-0 auth surface).
3. On login, the service worker tunnels the console's `/api/*` and `/oauth/*` calls **over
   the overlay** to the dark backends (Tier 1/2 services).
4. The console SPA shell + its API calls are thus never reachable publicly — only the
   BrowZer bootstrap + OIDC login are.

This reuses the existing `ziti_reconciler` + APISIX BrowZer route machinery. The console
is registered as a published BrowZer app with a **Tier-2 dial policy** (its API calls hit
admin-api, which requires `#device-trusted`), so a browser on an untrusted device can load
the shell but management calls are refused — matching the tier model.

**Native path (stronger, optional):** admins who run Ziti Desktop Edge / `ziti-edge-tunnel`
skip BrowZer entirely; `console.tdv.org` and the APIs resolve only through their tunnel.
Both paths coexist; BrowZer is the low-friction default, native is the maximal posture.

---

## 6. Enforcement mechanism (no new engine)

Three existing pieces, composed:

### 6.1 The network cut — loopback-bind + drop public routes
- Each backend service already listens on `:800x`. **Dark = bind to `127.0.0.1` only**
  (the exact `OPENIDX_ZITI_ARCHITECTURE.md §12.1` netgraph pattern) via a
  `SERVICE_BIND_ADDR` (default `0.0.0.0`; dark mode sets `127.0.0.1`).
- **Remove the service's public APISIX route** (`deployments/apisix-edge/seed-edge-routes.sh`):
  in dark mode only the Tier-0 routes (`enroll`, BrowZer hosts, `/oauth/*` auth subset,
  `/.well-known/*`, branding) remain. All `/api/v1/{admin,governance,audit,provisioning,
  scim,access}` public routes are **not seeded**.
- The access-proxy / BrowZer router reach `127.0.0.1:800x` over the overlay — the same way
  dark target apps already work.

### 6.2 The identity check — extend the `ziti_reconciler` attribute groups
- The reconciler already owns all Ziti mutations (Bind→`#ziti-routers`,
  Dial→`#browzer-users`). Add two **dial-policy attribute groups**:
  - `#enrolled-users` → Tier 1 services.
  - `#device-trusted` → Tier 2 services.
- `ziti_user_sync.go` already computes per-user attributes (group names + `#device-trusted`
  + `#browzer-users`). Add `#enrolled-users` to every synced identity, and gate
  `#device-trusted` on `known_devices.trusted` (already tracked). No new sync engine.
- Each dark OpenIDX surface is modeled as a **managed Ziti service** with a dial policy
  bound to its tier's attribute — reconciled from config/DB, not hand-wired.

### 6.3 Defense in depth on Tier 2 — keep proxy forward-auth
- Tier 2 traffic still passes the access-proxy forward-auth
  (`POST /api/v1/access/auth/decide`), which already enforces `require_device_trust` /
  `allowed_roles` / posture per route. So even inside the overlay, a Tier-2 request
  **re-checks device trust on the HTTP data plane** — this deliberately closes the
  documented "BrowZer clientless bypasses forward-auth" gap **for the management surface**
  (`remote-access-lifecycle-scenarios.md:50`), because we require it there.

### 6.4 Complementary prod belt (out of scope to implement here)
On a real deployment, add a host/security-group firewall that drops all inbound except
`:443` to the Tier-0 front door. Loopback-bind already achieves dark on a single box / one
K8s pod-network; the firewall is belt-and-suspenders and is documented, not coded.

---

## 7. Rollout — feature-flagged, staged, reversible, with break-glass

Darkening an IdP is a one-way door if botched (a bad overlay policy locks admins out of
the thing that manages the overlay). Mirror the availability/DR discipline: reversible
flags, verify-before-cutover, break-glass.

### 7.1 Config surface (`DARK_MODE`)
- `DARK_MODE_TIER2` (bool, default false) — dark the management plane.
- `DARK_MODE_TIER1` (bool, default false) — dark self-service + console shell.
- `SERVICE_BIND_ADDR` (per service, default `0.0.0.0`) — set `127.0.0.1` when its tier is
  dark.
- Tier 0 is **always public** — there is no flag to dark it (that would brick bootstrap).
- All flags are read at startup + surfaced in `/api/v1/system/health` so an operator can
  see the live posture.

### 7.2 Staged cutover (Tier 2 first — least risky)
Admins already have trusted devices, so Tier 2 is the safest to dark first:
1. Enroll the admin fleet (native tunnel or BrowZer) and confirm `#device-trusted`.
2. Reconcile the Tier-2 dial policies (`#device-trusted`).
3. Flip `DARK_MODE_TIER2=true`, loopback-bind admin/gov/audit/scim/access, **drop their
   public routes**.
4. **Verify** with the cutover script (§7.4). Only then proceed to Tier 1.
5. Repeat for Tier 1 (`#enrolled-users`, console shell via BrowZer).

### 7.3 Break-glass (must always exist)
- A sealed, documented **admin enrollment token** kept out-of-band (password manager /
  vault) that always mints a working Ziti identity via the Tier-0 `enroll` door.
- A **host-shell escape**: `DARK_MODE_*=false` + re-seed public routes
  (`scripts/dark-mode.sh --undark`) restores the prior public posture in one command from
  the box. This is the guaranteed recovery path and is part of the runbook.
- The Tier-0 door itself is the break-glass for enrollment: as long as `:443` answers, an
  authorized human can always get back on the overlay.

### 7.4 Verification (`make dark-drill` / `scripts/dark-mode.sh --verify`)
For each darked surface, assert the two-sided invariant, and fail loudly otherwise:
- **Public = refused:** `curl https://<edge>/api/v1/admin/...` → `404`/connection-refused
  (route gone), and `curl http://<host>:8005/health/live` from off-box → refused
  (loopback-bound).
- **Overlay = reachable:** the same call over an enrolled+trusted identity → `200`.
- **Tier gate holds:** an `#enrolled-users`-only identity is **refused** Tier 2 (dial
  policy + forward-auth both say no).
- Self-test mode (like `dr-game-day.sh`) that stands up a mock overlay/loopback to
  exercise the verdict logic with no infra, so the drill can't silently rot.

---

## 8. Components & files (where the work lands)

| Piece | Location | Change |
|---|---|---|
| Loopback bind flag | each `cmd/*-service/main.go` + `internal/common/config` | new `SERVICE_BIND_ADDR`, default `0.0.0.0`; listen on it |
| Public route set | `deployments/apisix-edge/seed-edge-routes.sh` | dark-mode variant seeds only Tier-0 routes |
| `enroll` front door | `internal/access/` (new dedicated public route) | token/session/passkey → Ziti enrollment JWT; rate-limited + audited |
| Attribute groups | `internal/access/ziti_user_sync.go` | add `#enrolled-users` to all identities; keep `#device-trusted` gated on trust |
| Tier dial policies | `internal/access/ziti_reconciler.go` | model each dark OpenIDX surface as a managed service + tier dial policy |
| Console as dark app | `proxy_routes` seed + reconciler | register `console.tdv.org` as a BrowZer app with a Tier-2 dial policy |
| Forward-auth on Tier 2 | `internal/access/` (existing decide endpoint) | ensure management routes carry `require_device_trust` |
| Config surface + health | `internal/common/config`, `internal/admin/system_health.go` | `DARK_MODE_*` flags; report live posture |
| Cutover tooling | `scripts/dark-mode.sh`, `Makefile` (`dark-drill`) | `--undark`, `--verify`, self-test; wired into `make` |
| Docs | this spec + `OPENIDX_ZITI_ARCHITECTURE.md` | operator runbook + tier table |

---

## 9. Data flow — a browser admin after dark

1. Admin → `https://console.tdv.org` (Tier 0 edge, `:443`).
2. Edge → BrowZer bootstrapper → WASM + service worker; OIDC login against OpenIDX's
   Tier-0 auth surface (`/oauth/authorize` → login → `/oauth/token`).
3. Service worker holds the session; console SPA loads (Tier 1, over the overlay).
4. Admin opens Users → console calls `GET /api/v1/admin/...` → tunneled over the overlay
   to dark admin-api (`127.0.0.1:8005`).
5. Dial policy checks `#device-trusted` (Tier 2). Forward-auth re-checks device trust +
   role. Trusted admin device → `200`. Untrusted device → refused at both layers; the
   shell loads but management calls fail closed.
6. A port scan of the public IP sees **only `:443`** answering the Tier-0 gate — no admin,
   governance, audit, SCIM, or access ports exist publicly.

---

## 10. Error handling & failure modes

- **Overlay/controller down:** Tier 1/2 unreachable (by design — no public fallback). Tier
  0 (login/JWKS/enroll) stays up, and JWKS serve-stale keeps *token verification* working
  (existing availability guarantee). Break-glass `--undark` restores public routes if the
  overlay is durably broken.
- **Device loses trust:** Tier 2 fails closed at dial-policy + forward-auth; the user keeps
  Tier 1. Re-establish trust to regain Tier 2.
- **New/lost device:** self-service via the Tier-0 `enroll` door (session or passkey),
  else admin/MDM token. No admin lockout as long as `:443` answers.
- **Misconfigured dial policy:** caught by `--verify` *before* the public route is
  dropped; cutover is gated on the verify passing.

---

## 11. Testing

- **Unit:** dial-policy/attribute computation in `ziti_user_sync`/`ziti_reconciler`
  (fake reconciler); `enroll` entitlement checks (token/session/passkey) with a fake
  store; config flag parsing.
- **Invariant guards (mutation-tested, wired into `make dark-drill`):** Tier-2 services
  require `#device-trusted`; Tier-0 route set never includes a management path; loopback
  bind is applied when a tier flag is on.
- **Cutover self-test:** `scripts/dark-mode.sh --verify --self-test` mocks the
  overlay/loopback and proves the "public refused / overlay 200 / tier gate holds" verdict
  logic without infra (mirrors `dr-game-day.sh`).
- **Live drill (staging):** enroll a device, dark Tier 2, assert the two-sided invariant,
  then `--undark` and re-assert public restored.

---

## 12. Open questions / decisions deferred to the plan

- Exact per-route Tier-1 vs Tier-2 assignment for a few dual-use endpoints (e.g. approvals
  a user acts on vs approvals an approver-admin acts on) — enumerate during planning.
- Whether the `enroll` door lives as a dedicated route in access-service (**current
  decision: yes**) or a separate `cmd/enroll-service` (smaller blast radius, extra
  deployable) — revisit if the route guard proves awkward.
- K8s deployment shape: on K8s "loopback" becomes "ClusterIP with no Ingress + Network
  policy"; the tier model is identical but the network cut is a NetworkPolicy, not a bind
  address. Plan a K8s variant of §6.1.

---

## 13. Why this is the right shape

- **Resolves the bootstrap paradox** instead of hand-waving it: a tiny, data-free Tier-0
  door is the minimum that must exist, and it is already hardened.
- **Reuses everything:** BrowZer dark-app pattern, `ziti_reconciler` policy ownership,
  access-proxy forward-auth, loopback-bind, agent QR/MDM enrollment, serve-stale JWKS. No
  new enforcement engine, no rearchitecture.
- **Dogfoods the product:** OpenIDX's own console becomes a dark BrowZer app — the exact
  thing the platform sells.
- **Reversible and safe:** feature-flagged, staged Tier-2→1, verify-before-cutover,
  break-glass — the same discipline as the availability/DR work.
- **Ziti-first by design:** after cutover the overlay is the *only* way in beyond the
  bootstrap gate; the public internet sees one `:443` door and nothing else.
