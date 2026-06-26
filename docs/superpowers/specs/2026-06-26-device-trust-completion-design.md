# Complete the device-trust workflow (devices slice D3) — design

## Context

The D3 audit found the device-trust approval workflow is ~80% built but **inert**, because its entry point is missing:

- **Backend**: 8 routes wired in `identity/service.go:3193-3200` (list / approve / reject / bulk-approve / bulk-reject / pending-count / get-settings / update-settings), all with handlers; `ApproveDeviceTrustRequest → trustDevice → UPDATE known_devices SET trusted=true` (exactly the flag D2 reads); dedup, auto-expiry, settings-driven auto-approval all implemented.
- **Frontend**: `web/admin-console/src/pages/device-trust-approval.tsx` (list/approve/reject/bulk/pending-count badge) registered at `/device-trust-approval`.
- **The gap**: `CreateDeviceTrustRequest` has **zero callers** and there is **no create route** — nothing ever puts a row in `device_trust_requests` (confirmed: 0 rows). The admin queue can never populate, so the loop *untrusted device → request → approve → `known_devices.trusted=true` → D2 trusts it* is broken at hop 1. Additionally, `notifyAdminsOfTrustRequest` and `notifyUserOfTrustDecision` are empty stubs.

D3 completion = give the queue an entry point and wire the notifications. Settled in brainstorming: the entry point is the **access proxy**, triggered when an untrusted device is blocked by a device-trust-requiring route. This closes the D2 loop end-to-end and is the most coherent narrative (the same proxy that reads `known_devices` for trust now files the request when trust is the blocker).

## Design

### Component 1 — auto-create trust requests from the access proxy (`internal/access`)

A best-effort helper in `internal/access/device_trust.go`:

```go
func (s *Service) ensureDeviceTrustRequest(ctx context.Context, userID, ip, userAgent string)
```

Behaviour:
1. Return immediately if `userID` is empty.
2. `fp := risk.ComputeDeviceFingerprint(ip, userAgent)`.
3. Look up the device: `SELECT id, COALESCE(name,'') FROM known_devices WHERE user_id=$1 AND fingerprint=$2 LIMIT 1`. If no row, return (the device isn't registered yet — nothing to request against; the login/risk path registers devices). `//orgscope:ignore` data-plane, consistent with the D2 reader.
4. Dedup: `SELECT 1 FROM device_trust_requests WHERE user_id=$1 AND device_fingerprint=$2 AND status='pending' LIMIT 1`. If a pending request exists, return (idempotent).
5. Insert a pending request mirroring identity's column set (`device_trust_requests` has **no** `org_id`):
   ```sql
   INSERT INTO device_trust_requests
     (id, user_id, device_id, device_fingerprint, device_name, device_type,
      ip_address, user_agent, justification, status, created_at)
   VALUES (gen_random_uuid(), $1, $2, $3, $4, 'unknown', $5, $6,
      'Untrusted device attempted access to a device-trust-protected resource', 'pending', NOW())
   ```
6. Every error is logged at `Warn` and swallowed — this never blocks or fails the proxied request.

**Trigger** — in `buildAccessContext` (`context_evaluator.go`), immediately after the D2 `trusted` computation:

```go
trusted := s.deviceTrusted(ctx, session.UserID, ac.ClientIP, ac.UserAgent)
ac.DeviceTrusted = trusted
session.DeviceTrusted = trusted
if !trusted && route.RequireDeviceTrust {
    s.ensureDeviceTrustRequest(ctx, session.UserID, ac.ClientIP, ac.UserAgent)
}
```

Gating on `route.RequireDeviceTrust` means a request is filed **only** when an untrusted device hits a route that actually requires trust — i.e. exactly when approval would unblock the user. This keeps it off the hot path for ordinary routes, keeps `evaluateAccessContext` a pure decision function, and the dedup makes repeated hits idempotent.

### Component 2 — wire the two notification stubs (`internal/identity`)

The real `internal/notifications` service (`CreateMultiChannelNotification(ctx, userID, orgID, type, title, body, link, metadata)`) is used to replace the empty bodies in `device_trust_approval.go`. Both already fire only when their settings flag is set (`NotifyUserOnDecision` / `NotifyAdmins`).

- **`notifyUserOfTrustDecision(ctx, userID, decision, notes)`** (fires on approve/reject) — resolve the org via `orgctx.From(ctx)`, then:
  ```go
  notifications.NewService(s.db, s.logger).CreateMultiChannelNotification(
      ctx, userID, org.ID, "device_trust",
      "Device trust "+decision,
      "Your device trust request was "+decision+"."+notesSuffix,
      "/devices", nil)
  ```
  (`notesSuffix` appends `" Note: "+notes` when `notes != ""`.) This is the high-value notification — the user is waiting on the decision.

- **`notifyAdminsOfTrustRequest(ctx, userID, deviceName)`** (fires on the identity/self-service creation path) — notify org admins via a role-targeted insert mirroring `admin/notification_management`'s role case, targeting the well-known admin role (`roles.name = 'admin'`):
  ```sql
  INSERT INTO notifications (user_id, channel, type, title, body, metadata, org_id)
  SELECT DISTINCT ur.user_id, 'in_app', 'device_trust',
         'New device trust request',
         'A device ("'||$1||'") is awaiting trust approval.',
         jsonb_build_object('requesting_user', $2::text), r.org_id
  FROM user_roles ur JOIN roles r ON r.id = ur.role_id
  WHERE r.name = 'admin' AND r.org_id = $3
  ```
  with `$1=deviceName, $2=userID, $3=org.ID`.

**Deliberate boundary:** proxy-created requests (Component 1) do **not** route through identity, so admins learn of those via the existing **pending-count badge** in the console — not a push notification. This keeps the access service free of notification concerns. `notifyAdminsOfTrustRequest` therefore covers only the identity creation path (`CreateDeviceTrustRequest`, used by future self-service); it is wired now for completeness since the stub and its settings gate already exist.

## Testing

- **`internal/access`** (testcontainers, reuse the `setupTestDB` harness from D2): create minimal `known_devices` + `device_trust_requests` tables, then assert `ensureDeviceTrustRequest`:
  - untrusted, registered device, no existing request → exactly one `pending` row inserted;
  - called again → still exactly one row (dedup);
  - empty `userID` → no row;
  - no `known_devices` row for the fingerprint → no row.
- **`internal/identity`** (testcontainers): after `ApproveDeviceTrustRequest` / `RejectDeviceTrustRequest` on a seeded pending request (with `NotifyUserOnDecision=true`), a `notifications` row exists for the request's user with `type='device_trust'`. (Schema: create `device_trust_requests`, `device_trust_settings`, `known_devices`, `notifications` minimally in the test.)

## Live verification (on the box)

1. Rebuild + restart `oidx-access` and `oidx-identity` (identity restart also picks up `INTERNAL_SERVICE_TOKEN` from `common.env`, harmless here).
2. Create a `proxy_routes` row with `require_device_trust=true` for a throwaway host; ensure a `known_devices` row exists (`trusted=false`) whose fingerprint matches a test (ip, ua).
3. Drive an untrusted request at that route (or call `buildAccessContext`'s path) → assert a `pending` `device_trust_requests` row appears; repeat → still one (dedup).
4. `POST /api/v1/identity/device-trust-requests/:id/approve` → `known_devices.trusted` flips to `true`, and a `notifications` row for the user exists.
5. Re-drive the request → now trusted (D2). Remove the test route/request/policy and revert any flipped `known_devices` row.

## Out of scope (follow-on)

- Self-service portal "request trust for this device" button + a `POST /device-trust-requests` create endpoint (the access auto-trigger already closes the loop; the endpoint can be added when the portal action is built).
- Admin push-notifications for proxy-created requests (covered by the pending-count badge by design).
- `conditional_access` policy denials (in governance) as an additional trigger — only the `route.RequireDeviceTrust` flag is used.
- The `proxy_sessions`-column persistence for `continuous_verify` (separate D2 follow-on).

## Verification checklist

- `go build ./...`, `go vet ./internal/access/... ./internal/identity/...` clean; `gofmt`.
- `go test ./internal/access/ ./internal/identity/` green, including the new `ensureDeviceTrustRequest` and decision-notification tests.
- Live: an untrusted device on a `require_device_trust` route files exactly one pending request; approving it trusts the device (D2 loop closes) and notifies the user.
