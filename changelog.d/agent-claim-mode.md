### Added
- **Claim a fleet-enrolled device by signing in on the tray.** A device enrolled with a fleet token names no one;
  the tray's "Sign in" now calls `POST /api/v1/access/agent/claim` with the device and user credentials, which
  makes an active, ownerless device in the same organization the person's, links its known device and binds the
  session to it (audit `agent.claimed`). A device someone else owns is refused 409, another org's user 403.
- **`claim_mode` per organization** (`GET/PUT /api/v1/access/agent/settings`, admin, fresh MFA for writes).
  `logged_on_user` lets the Windows service report the console session user; an ownerless device becomes theirs
  only when the name matches exactly one enabled directory- or federation-sourced user.

### Upgrade notes
- Migration 252 (`org_agent_settings`, org-scoped under FORCE RLS). 251 is reserved for agent identity
  continuity. `RegisterAgentAdminRoutes` takes an admin gate as its third argument.
