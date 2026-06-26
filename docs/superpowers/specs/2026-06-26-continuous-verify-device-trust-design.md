# Close the continuous-verify device-trust gap — design

## Context

The D2/D3 work made `DeviceTrusted` real on the forward-auth path, but left one deferred loose end: the **continuous verifier** (`internal/access/continuous_verify.go`), a background ticker that periodically re-evaluates active sessions against their route's `reverify_interval`.

Investigation found the loose end is more than "a stale column" — **continuous-verify is broken on this box (and any migrate-based install)**:

- Its driver query selects `s.device_trusted` and filters on `s.last_verified_at`, but **those columns exist only in `deployments/docker/init-db.sql` (lines 1614, 1619), never in any migration** (`internal/migrations/*.go` defines neither). On installs provisioned by the migration runner rather than `init-db.sql`, the columns are absent and the query errors every run ("column does not exist" → logged → returns early). Confirmed on the box: `proxy_sessions` is missing `last_verified_at, verification_failures, geo_country, geo_city, device_trusted` (only `idp_id` of the six init-db continuous-verify columns is present); `user_sessions.device_trusted` is also missing.
- Even if the columns existed, `proxy_sessions.device_trusted` is never written by the forward-auth path (D2 sets the in-memory `session.DeviceTrusted` per request but doesn't persist it), so the verifier would read a stale/default `false`.

The feature is also currently dormant (0 routes have `reverify_interval > 0`), so this is a latent break, not a live outage — but attaching `reverify_interval` to any route today would surface the column error.

This is the same init-db↔migrations gap reconciled for other tables in migrations v42–v45.

## Design

### Component 1 — migration v52: reconcile the init-db-only continuous-verify columns

A new idempotent migration mirroring `init-db.sql`, following the v42–v45 reconcile pattern.

`proxy_sessions` (init-db.sql:1614-1619):
```sql
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS verification_failures INTEGER DEFAULT 0;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS geo_country VARCHAR(10);
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS geo_city VARCHAR(255);
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS idp_id UUID;
ALTER TABLE proxy_sessions ADD COLUMN IF NOT EXISTS device_trusted BOOLEAN DEFAULT false;
```
`user_sessions` (init-db.sql:2153, 2160):
```sql
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_trusted BOOLEAN DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_user_sessions_device_trusted ON user_sessions(device_trusted);
```

All six `proxy_sessions` columns are included (not just the two the verifier reads) for faithful init-db parity; `idp_id` is already present on the box, so `IF NOT EXISTS` makes it a no-op. Registered in `loader.go` after v51.

**DownSQL: intentionally a no-op** (a comment only). The Up is `ADD COLUMN IF NOT EXISTS`, so on an init-db-provisioned install the columns already existed before this migration ran — the migration cannot know whether it created them or they pre-existed. Dropping them on rollback would re-break continuous-verify on exactly those installs (and `idp_id` is depended on across `service.go`). Reconcile migrations that close an init-db↔migrations gap are not faithfully reversible by column-drop, so Down does nothing; the columns are harmless to leave and re-addable.

This component alone unbreaks the continuous-verify query everywhere.

### Component 2 — continuous-verify uses the fresh trust signal

In `internal/access/continuous_verify.go`'s per-session loop, replace use of the scanned `s.device_trusted` (which the forward-auth path doesn't persist, so it is stale/`false`) with a live recomputation via the D2 reader, applied to both the rebuilt `ProxySession` and the `AccessContext`:

```go
trusted := cv.svc.deviceTrusted(ctx, sess.UserID, sess.IPAddress, sess.UserAgent)
proxySession.DeviceTrusted = trusted
ac.DeviceTrusted = trusted
```

This matches D2's "compute per request, don't store stale" principle (the reason a persisted column was deferred), needs no hot-path write, and additionally catches a device that was **un-trusted since login**. The scanned `s.device_trusted` value is no longer used to populate the session/context; whether to keep selecting the column in the driver query or drop it is an implementation detail (keeping it is harmless now that the column exists; dropping it avoids reading an unused value — the plan picks one). `last_verified_at` remains essential to the due-filter and the post-verify write-back, which are unchanged.

**Settled:** recompute-live over persisting `device_trusted` on the forward-auth path — fresher, no extra write on every proxied request, consistent with D2/D3.

## Testing

- **Migration**: registration/build is covered by the existing migration loader compilation; no bespoke unit test (matches how v42–v51 were handled). Correctness is verified live (Component below).
- **Access**: `go build` + `go vet` + the existing `internal/access` suite stay green. A standalone unit test of the verify loop would require a full session+route+ticker fixture and isn't warranted for a one-line trust-source change; the D2 reader (`deviceTrusted`) is already unit-tested, and the end-to-end behaviour is verified live.

## Live verification (on the box)

1. Apply v52 manually (AUTO_MIGRATE is off) and confirm the five missing `proxy_sessions` columns + `user_sessions.device_trusted` now exist.
2. Rebuild + restart `oidx-access`.
3. Create a throwaway route with `reverify_interval > 0` and an active `proxy_sessions` row for it; confirm the verifier runs **without** the previous "column does not exist" error (check `/tmp/oidx-logs/access.log`) and advances `last_verified_at`.
4. Remove the throwaway route/session, restoring the box to as-found.

## Out of scope (follow-on)

- Persisting `geo_country`/`geo_city`/`verification_failures` writes from the verifier (columns added for parity; the verifier already writes only `last_verified_at`/`risk_score`).
- Any change to the verifier's decision/revocation logic.
- Enabling continuous verification on real routes (an operator opt-in via `reverify_interval`).

## Verification checklist

- `go build ./...`, `go vet ./internal/access/... ./internal/migrations/...` clean; `gofmt`.
- `go test ./internal/access/ ./internal/migrations/` green.
- Live: v52 adds the missing columns; the continuous verifier runs without the column error and re-derives device trust from the live signal.
