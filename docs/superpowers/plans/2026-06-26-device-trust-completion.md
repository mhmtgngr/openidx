# Complete the device-trust workflow (D3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Feed the existing (but never-populated) device-trust approval queue by auto-creating a request when an untrusted device hits a device-trust-required route, and wire the two empty notification stubs to the real notifications service.

**Architecture:** The access proxy gains a best-effort `ensureDeviceTrustRequest` that inserts a deduped `pending` row into `device_trust_requests`, triggered in `buildAccessContext` only when `!trusted && route.RequireDeviceTrust`. The identity service's `notifyUserOfTrustDecision` / `notifyAdminsOfTrustRequest` stubs are wired to `internal/notifications`. Everything else (approve/reject/list/settings, the admin UI, the `known_devices.trusted` flip that D2 reads) already exists.

**Tech Stack:** Go 1.22, pgx v5, testcontainers-go, `internal/notifications`, zap.

---

### Task 1: `ensureDeviceTrustRequest` reader/writer (access)

Add the helper that files a deduped pending trust request. The access package already has the `setupTestDB` harness and a `device_trust_test.go` (from D2) — extend them.

**Files:**
- Modify: `internal/access/device_trust.go` (add the helper)
- Test: `internal/access/device_trust_test.go` (add a test function)

- [ ] **Step 1: Write the failing test**

Append to `internal/access/device_trust_test.go`:

```go
func TestEnsureDeviceTrustRequest(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE known_devices (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			fingerprint VARCHAR(255),
			name VARCHAR(255),
			trusted BOOLEAN DEFAULT false,
			org_id UUID
		);
		CREATE TABLE device_trust_requests (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			device_id UUID,
			device_fingerprint VARCHAR(255),
			device_name VARCHAR(255),
			device_type VARCHAR(50),
			ip_address VARCHAR(64),
			user_agent TEXT,
			justification TEXT,
			status VARCHAR(20),
			reviewed_by UUID,
			reviewed_at TIMESTAMPTZ,
			review_notes TEXT,
			auto_expire_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}

	const userID = "00000000-0000-0000-0000-000000000001"
	const ip = "192.168.1.50"
	const ua = "Mozilla/5.0 (TestAgent)"
	fp := risk.ComputeDeviceFingerprint(ip, ua)

	pending := func() int {
		var n int
		db.Pool.QueryRow(ctx, `SELECT count(*) FROM device_trust_requests WHERE user_id=$1 AND status='pending'`, userID).Scan(&n)
		return n
	}

	// No known_devices row → no request created.
	s.ensureDeviceTrustRequest(ctx, userID, ip, ua)
	if pending() != 0 {
		t.Fatalf("expected 0 requests with no known_devices row, got %d", pending())
	}

	// Register the (untrusted) device.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO known_devices (user_id, fingerprint, name, trusted) VALUES ($1,$2,'Test Laptop',false)`,
		userID, fp); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// First call → exactly one pending request.
	s.ensureDeviceTrustRequest(ctx, userID, ip, ua)
	if pending() != 1 {
		t.Fatalf("expected 1 request after first call, got %d", pending())
	}

	// Second call → still one (dedup).
	s.ensureDeviceTrustRequest(ctx, userID, ip, ua)
	if pending() != 1 {
		t.Fatalf("expected dedup to keep 1 request, got %d", pending())
	}

	// Empty userID → no-op.
	before := pending()
	s.ensureDeviceTrustRequest(ctx, "", ip, ua)
	if pending() != before {
		t.Fatalf("empty userID should not create a request")
	}
}
```

(`context`, `zap`, and `risk` are already imported by `device_trust_test.go` from D2 — no import changes.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/cmit/openidx && go test ./internal/access/ -run TestEnsureDeviceTrustRequest -count=1 2>&1 | tail -5`
Expected: compile failure — `s.ensureDeviceTrustRequest undefined`.

- [ ] **Step 3: Implement the helper**

Append to `internal/access/device_trust.go` (the file already imports `context`, `errors`, `github.com/jackc/pgx/v5`, `go.uber.org/zap`, and `github.com/openidx/openidx/internal/risk` from D2):

```go
// ensureDeviceTrustRequest files a pending device-trust request for an untrusted
// device that attempted access, so an admin can approve it (which flips
// known_devices.trusted=true, after which deviceTrusted returns true). Best-effort:
// every error is logged and swallowed so it never blocks the proxied request.
// Idempotent — a device with an existing pending request is not re-filed.
func (s *Service) ensureDeviceTrustRequest(ctx context.Context, userID, ip, userAgent string) {
	if userID == "" {
		return
	}
	fp := risk.ComputeDeviceFingerprint(ip, userAgent)

	// The device must already be registered (the login/risk path creates the
	// known_devices row). Pull its id + name for the request.
	var deviceID, deviceName string
	err := s.db.Pool.QueryRow(ctx,
		//orgscope:ignore proxy data-plane device-trust write; the already-authenticated session user's device by user_id + fingerprint
		`SELECT id, COALESCE(name,'') FROM known_devices WHERE user_id=$1 AND fingerprint=$2 LIMIT 1`,
		userID, fp).Scan(&deviceID, &deviceName)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Warn("device-trust request: known_devices lookup failed", zap.String("user_id", userID), zap.Error(err))
		}
		return
	}

	// Dedup: one pending request per (user, device).
	var exists int
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT 1 FROM device_trust_requests WHERE user_id=$1 AND device_fingerprint=$2 AND status='pending' LIMIT 1`,
		userID, fp).Scan(&exists); err == nil {
		return // already pending
	} else if !errors.Is(err, pgx.ErrNoRows) {
		s.logger.Warn("device-trust request: dedup check failed", zap.String("user_id", userID), zap.Error(err))
		return
	}

	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO device_trust_requests
			(id, user_id, device_id, device_fingerprint, device_name, device_type,
			 ip_address, user_agent, justification, status, created_at)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, 'unknown', $5, $6,
			'Untrusted device attempted access to a device-trust-protected resource', 'pending', NOW())`,
		userID, deviceID, fp, deviceName, ip, userAgent); err != nil {
		s.logger.Warn("device-trust request: insert failed", zap.String("user_id", userID), zap.Error(err))
	}
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/cmit/openidx && go test ./internal/access/ -run TestEnsureDeviceTrustRequest -count=1 -v 2>&1 | tail -8`
Expected: `--- PASS: TestEnsureDeviceTrustRequest` (testcontainers, ~10s; SKIP acceptable only if Docker unavailable).

- [ ] **Step 5: Build, vet, commit**

```bash
cd /home/cmit/openidx
gofmt -w internal/access/device_trust.go internal/access/device_trust_test.go
go build ./internal/access/... && go vet ./internal/access/...
git add internal/access/device_trust.go internal/access/device_trust_test.go
git commit -m "feat(access): ensureDeviceTrustRequest — file a deduped pending request for untrusted devices (D3)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Trigger request creation in `buildAccessContext`

Fire the helper only when an untrusted device hits a device-trust-required route.

**Files:**
- Modify: `internal/access/context_evaluator.go`

- [ ] **Step 1: Make the edit**

In `internal/access/context_evaluator.go`, the D2 block currently reads:

```go
	trusted := s.deviceTrusted(ctx, session.UserID, ac.ClientIP, ac.UserAgent)
	ac.DeviceTrusted = trusted
	session.DeviceTrusted = trusted
```

Append one conditional so it becomes:

```go
	trusted := s.deviceTrusted(ctx, session.UserID, ac.ClientIP, ac.UserAgent)
	ac.DeviceTrusted = trusted
	session.DeviceTrusted = trusted
	// If an untrusted device is hitting a route that requires device trust, file a
	// pending trust request (best-effort, deduped) so an admin can approve it.
	if !trusted && route.RequireDeviceTrust {
		s.ensureDeviceTrustRequest(ctx, session.UserID, ac.ClientIP, ac.UserAgent)
	}
```

- [ ] **Step 2: Build and vet**

Run: `cd /home/cmit/openidx && gofmt -w internal/access/context_evaluator.go && go build ./... && go vet ./internal/access/...`
Expected: no output (clean).

- [ ] **Step 3: Run the full access suite**

Run: `cd /home/cmit/openidx && go test ./internal/access/ -count=1 2>&1 | tail -5`
Expected: `ok github.com/openidx/openidx/internal/access` (includes `TestDeviceTrusted`, `TestEnsureDeviceTrustRequest`). Testcontainers; may take ~30-90s.

- [ ] **Step 4: Commit**

```bash
cd /home/cmit/openidx
git add internal/access/context_evaluator.go
git commit -m "feat(access): file a device-trust request when an untrusted device hits a trust-required route (D3)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Wire the two notification stubs (identity)

Replace the empty `notifyUserOfTrustDecision` / `notifyAdminsOfTrustRequest` bodies with real notifications, and add a test DB harness + tests.

**Files:**
- Modify: `internal/identity/device_trust_approval.go` (imports + the two stub bodies at ~416-424)
- Create: `internal/identity/testdb_test.go` (testcontainers harness)
- Test: `internal/identity/device_trust_notify_test.go`

- [ ] **Step 1: Create the identity test DB harness**

First confirm it doesn't already exist: `grep -rn 'func setupTestDB' internal/identity/` — if present, STOP and reuse it instead of creating a duplicate. Otherwise create `internal/identity/testdb_test.go`:

```go
// Package identity test helpers shared across the identity test suite.
package identity

import (
	"context"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/openidx/openidx/internal/common/database"
)

// setupTestDB creates a throwaway PostgreSQL container for DB-backed tests.
func setupTestDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()

	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(30 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("Failed to start test container: %v", err)
		return nil, func() {}
	}

	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get container host: %v", err)
		return nil, func() {}
	}

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get container port: %v", err)
		return nil, func() {}
	}

	connString := "postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable"

	db, err := database.NewPostgres(connString)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to connect to test database: %v", err)
		return nil, func() {}
	}

	cleanup := func() {
		db.Close()
		container.Terminate(ctx)
	}

	return db, cleanup
}
```

- [ ] **Step 2: Write the failing tests**

Create `internal/identity/device_trust_notify_test.go`:

```go
package identity

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

const notifyTestOrg = "00000000-0000-0000-0000-000000000010"

func TestNotifyUserOfTrustDecision(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: notifyTestOrg})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE notifications (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			org_id UUID,
			channel VARCHAR(32),
			type VARCHAR(64),
			title TEXT,
			body TEXT,
			link TEXT,
			read BOOLEAN DEFAULT false,
			metadata JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}
	const userID = "00000000-0000-0000-0000-000000000001"

	s.notifyUserOfTrustDecision(ctx, userID, "approved", "looks good")

	var n int
	db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE user_id=$1 AND type='device_trust'`, userID).Scan(&n)
	if n != 1 {
		t.Fatalf("expected 1 device_trust notification for the user, got %d", n)
	}
}

func TestNotifyAdminsOfTrustRequest(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: notifyTestOrg})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE notifications (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL, org_id UUID, channel VARCHAR(32), type VARCHAR(64),
			title TEXT, body TEXT, link TEXT, read BOOLEAN DEFAULT false, metadata JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE TABLE roles (id UUID PRIMARY KEY, name VARCHAR(64), org_id UUID);
		CREATE TABLE user_roles (user_id UUID, role_id UUID, org_id UUID);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	const adminUser = "00000000-0000-0000-0000-0000000000aa"
	const adminRole = "60000000-0000-0000-0000-000000000001"
	// Two separate Exec calls: pgx's extended protocol rejects multiple
	// parameterized commands in a single query string.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO roles (id, name, org_id) VALUES ($1,'admin',$2)`, adminRole, notifyTestOrg); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`, adminUser, adminRole, notifyTestOrg); err != nil {
		t.Fatalf("seed user_role: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}
	s.notifyAdminsOfTrustRequest(ctx, "00000000-0000-0000-0000-000000000001", "My Laptop")

	var n int
	db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE user_id=$1 AND type='device_trust'`, adminUser).Scan(&n)
	if n != 1 {
		t.Fatalf("expected the admin to get 1 device_trust notification, got %d", n)
	}
}
```

- [ ] **Step 3: Run to verify they fail**

Run: `cd /home/cmit/openidx && go test ./internal/identity/ -run 'TestNotify(User|Admins)' -count=1 2>&1 | tail -8`
Expected: the tests run but FAIL the count assertion (the stubs are empty, so 0 notifications) — or PASS-with-0 if assertions are wrong; either way they must not pass until Step 4. (Not a compile error — the stub functions already exist.)

- [ ] **Step 4: Wire the stubs**

In `internal/identity/device_trust_approval.go`, add two imports to the existing import block:

```go
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/notifications"
```

(Place `"go.uber.org/zap"` with the third-party imports and the `notifications` import with the other `github.com/openidx/openidx/...` imports.)

Replace the two stub bodies (currently at ~416-424):

```go
func (s *Service) notifyAdminsOfTrustRequest(ctx context.Context, userID, deviceName string) {
	// Send notification to admins
	// This would integrate with the notification system
}

func (s *Service) notifyUserOfTrustDecision(ctx context.Context, userID, decision, notes string) {
	// Send notification to user about decision
	// This would integrate with the notification system
}
```

with:

```go
// notifyAdminsOfTrustRequest notifies org admins (the well-known "admin" role)
// that a device is awaiting trust approval. Best-effort.
func (s *Service) notifyAdminsOfTrustRequest(ctx context.Context, userID, deviceName string) {
	org, err := orgctx.From(ctx)
	if err != nil {
		s.logger.Warn("device-trust admin notify: no org in context", zap.Error(err))
		return
	}
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO notifications (user_id, channel, type, title, body, metadata, org_id)
		SELECT DISTINCT ur.user_id, 'in_app', 'device_trust',
			'New device trust request',
			'A device ("' || $1 || '") is awaiting trust approval.',
			jsonb_build_object('requesting_user', $2::text), r.org_id
		FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		WHERE r.name = 'admin' AND r.org_id = $3`,
		deviceName, userID, org.ID); err != nil {
		s.logger.Warn("failed to notify admins of device-trust request", zap.Error(err))
	}
}

// notifyUserOfTrustDecision notifies the requesting user that their device-trust
// request was approved or rejected. Best-effort.
func (s *Service) notifyUserOfTrustDecision(ctx context.Context, userID, decision, notes string) {
	org, err := orgctx.From(ctx)
	if err != nil {
		s.logger.Warn("device-trust decision notify: no org in context", zap.Error(err))
		return
	}
	body := "Your device trust request was " + decision + "."
	if notes != "" {
		body += " Note: " + notes
	}
	notif := notifications.NewService(s.db, s.logger)
	if err := notif.CreateMultiChannelNotification(ctx, userID, org.ID, "device_trust",
		"Device trust "+decision, body, "/devices", nil); err != nil {
		s.logger.Warn("failed to notify user of device-trust decision", zap.String("user_id", userID), zap.Error(err))
	}
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd /home/cmit/openidx && go test ./internal/identity/ -run 'TestNotify(User|Admins)' -count=1 -v 2>&1 | tail -10`
Expected: both `--- PASS` (testcontainers; ~15s).

- [ ] **Step 6: Build, vet, commit**

```bash
cd /home/cmit/openidx
gofmt -w internal/identity/device_trust_approval.go internal/identity/testdb_test.go internal/identity/device_trust_notify_test.go
go build ./... && go vet ./internal/identity/...
git add internal/identity/device_trust_approval.go internal/identity/testdb_test.go internal/identity/device_trust_notify_test.go
git commit -m "feat(identity): wire device-trust notifications (decision→user, request→admins) (D3)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Live verification on the box

Deploy and prove the full loop. No commit.

**Files:** none (deployment only).

- [ ] **Step 1: Rebuild + restart access and identity**

```bash
cd /home/cmit/openidx
go build -o /tmp/oidx-access-service.new ./cmd/access-service && \
go build -o /tmp/oidx-identity-service.new ./cmd/identity-service && \
systemctl --user stop oidx-access.service oidx-identity.service && \
cp /tmp/oidx-access-service.new /home/cmit/oidx-runtime/bin/oidx-access-service && \
cp /tmp/oidx-identity-service.new /home/cmit/oidx-runtime/bin/oidx-identity-service && \
systemctl --user start oidx-identity.service oidx-access.service && sleep 3 && \
systemctl --user is-active oidx-identity.service oidx-access.service && \
ss -ltnp 2>/dev/null | grep -E ':8001|:8007'
```
Expected: both `active`, listeners on :8001 and :8007.

- [ ] **Step 2: Confirm the queue starts empty**

```bash
docker exec oidx-pg psql -U openidx -d openidx -tA -c "SELECT count(*) FROM device_trust_requests;" 2>&1 | grep -v 'Emulate\|nodocker'
```
Expected: `0`.

- [ ] **Step 3: Drive the creation path directly (unit-style, on the live DB)**

The end-to-end proxy path needs an authenticated session + a `require_device_trust` route, which is heavy to stand up by hand. Instead, prove the helper's SQL against the real schema by simulating exactly what `ensureDeviceTrustRequest` does, for the existing untrusted `known_devices` row (curl device, fingerprint `9013fdc5…`, user `00000000-0000-0000-0000-000000000001`):

```bash
docker exec -i oidx-pg psql -U openidx -d openidx 2>&1 <<'SQL' | grep -v 'Emulate\|nodocker'
WITH d AS (SELECT id, COALESCE(name,'') AS name FROM known_devices WHERE fingerprint='9013fdc5380269407687a52a0b7b6d3a420271473a64de775323a43e37da65aa' AND trusted=false LIMIT 1)
INSERT INTO device_trust_requests (id,user_id,device_id,device_fingerprint,device_name,device_type,ip_address,user_agent,justification,status,created_at)
SELECT gen_random_uuid(),'00000000-0000-0000-0000-000000000001',d.id,'9013fdc5380269407687a52a0b7b6d3a420271473a64de775323a43e37da65aa',d.name,'unknown','127.0.0.1','curl/8.5.0','live test','pending',NOW() FROM d
RETURNING id;
SQL
```
Expected: one `RETURNING id` row — confirms the column set + the `known_devices` join work against the real schema. (This validates the SQL the deployed helper runs; the helper itself is unit-tested in Task 1.)

- [ ] **Step 4: Approve via the API and confirm the device becomes trusted**

The approve endpoint requires an admin JWT. If a token is readily available, call it; otherwise approve directly (the handler just calls `ApproveDeviceTrustRequest`, which is covered by identity logic) and verify the `known_devices.trusted` flip:

```bash
RID=$(docker exec oidx-pg psql -U openidx -d openidx -tA -c "SELECT id FROM device_trust_requests WHERE status='pending' ORDER BY created_at DESC LIMIT 1;" 2>&1 | grep -v 'Emulate\|nodocker')
docker exec oidx-pg psql -U openidx -d openidx -c "UPDATE device_trust_requests SET status='approved', reviewed_at=NOW() WHERE id='$RID'; UPDATE known_devices SET trusted=true WHERE fingerprint='9013fdc5380269407687a52a0b7b6d3a420271473a64de775323a43e37da65aa';" 2>&1 | grep -v 'Emulate\|nodocker'
docker exec oidx-pg psql -U openidx -d openidx -tA -c "SELECT 'trusted='||trusted FROM known_devices WHERE fingerprint='9013fdc5380269407687a52a0b7b6d3a420271473a64de775323a43e37da65aa';" 2>&1 | grep -v 'Emulate\|nodocker'
```
Expected: `trusted=true` — the curl device is now trusted, which the deployed D2 reader will honor on the next request.

- [ ] **Step 5: Clean up — restore the box to as-found**

```bash
docker exec oidx-pg psql -U openidx -d openidx -c "DELETE FROM device_trust_requests WHERE justification IN ('live test','Untrusted device attempted access to a device-trust-protected resource'); UPDATE known_devices SET trusted=false WHERE fingerprint='9013fdc5380269407687a52a0b7b6d3a420271473a64de775323a43e37da65aa';" 2>&1 | grep -v 'Emulate\|nodocker'
docker exec oidx-pg psql -U openidx -d openidx -tA -c "SELECT count(*) FROM device_trust_requests;" 2>&1 | grep -v 'Emulate\|nodocker'
```
Expected: `0` (queue empty again; the two `known_devices` rows back to `trusted=false`).

- [ ] **Step 6: No commit** — report outcomes (services healthy, request SQL valid against the real schema, approve→`trusted=true` flip, box restored).

---

## Notes for the executor
- Dependency order **1 → 2 → 3 → 4**. Task 2 depends on Task 1's `ensureDeviceTrustRequest`. Task 3 is independent of 1/2 (different service) but keep the order for clean commits.
- Tasks 1 and 3 are TDD with testcontainers (~10-15s each). Task 2 is an integration edit verified by build + the full access suite; the live loop is Task 4.
- Best-effort discipline: `ensureDeviceTrustRequest` and both notify functions must never return errors up the stack or block their callers — they log and move on.
- Out of scope (do NOT implement): a `POST /device-trust-requests` self-service endpoint or portal button; admin push-notifications for proxy-created requests (the pending-count badge covers that); `conditional_access`-policy denials as a trigger; the `proxy_sessions` column persistence.
- Never commit a red build.
