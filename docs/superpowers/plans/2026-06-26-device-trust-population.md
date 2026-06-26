# Populate ProxySession.DeviceTrusted from known_devices (D2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `DeviceTrusted` real on the access proxy's forward-auth path by computing the request's device fingerprint and reading the authoritative `known_devices.trusted` flag, instead of the never-populated session field.

**Architecture:** The device fingerprint logic is extracted into a shared package-level `risk.ComputeDeviceFingerprint`. The access service gains a `deviceTrusted(userID, ip, ua)` reader that matches `known_devices`. `buildAccessContext` calls it per-request and writes the result back to the in-memory `session`, so one value feeds the context checks, the inline DSL, and the G1 policy `/evaluate` call.

**Tech Stack:** Go 1.22, pgx v5 (`github.com/jackc/pgx/v5`), testcontainers-go, zap.

---

### Task 1: Share the fingerprint function (`internal/risk`)

Extract the body of `(*Service).ComputeDeviceFingerprint` into a package-level function so the access service can compute an identical fingerprint without constructing a `risk.Service`. No behavior change.

**Files:**
- Modify: `internal/risk/service.go:77-92` (the method)
- Test: `internal/risk/device_fingerprint_test.go` (new)

- [ ] **Step 1: Write the failing test**

Create `internal/risk/device_fingerprint_test.go`:

```go
package risk

import "testing"

func TestComputeDeviceFingerprint_FreeFuncMatchesMethod(t *testing.T) {
	cases := []struct{ ip, ua string }{
		{"192.168.1.10", "Mozilla/5.0 (X11; Linux x86_64)"},
		{"10.0.0.5", "curl/8.0"},
		{"", ""},
		{"not-an-ip", "UA"},
	}
	var s Service
	for _, c := range cases {
		free := ComputeDeviceFingerprint(c.ip, c.ua)
		method := s.ComputeDeviceFingerprint(c.ip, c.ua)
		if free != method {
			t.Errorf("free(%q,%q)=%s != method=%s", c.ip, c.ua, free, method)
		}
		if len(free) != 64 {
			t.Errorf("expected 64-hex sha256, got %d chars: %s", len(free), free)
		}
	}
}

func TestComputeDeviceFingerprint_Subnet(t *testing.T) {
	// Same /24 → same fingerprint (subnet is collapsed to x.y.z.0/24).
	a := ComputeDeviceFingerprint("192.168.1.10", "UA")
	b := ComputeDeviceFingerprint("192.168.1.250", "UA")
	if a != b {
		t.Errorf("same /24 should match: %s != %s", a, b)
	}
	// Different /24 → different.
	if c := ComputeDeviceFingerprint("192.168.2.10", "UA"); a == c {
		t.Error("different /24 should differ")
	}
	// Different UA → different.
	if d := ComputeDeviceFingerprint("192.168.1.10", "OtherUA"); a == d {
		t.Error("different UA should differ")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/cmit/openidx && go test ./internal/risk/ -run TestComputeDeviceFingerprint -count=1 2>&1 | tail -5`
Expected: compile failure — `undefined: ComputeDeviceFingerprint` (the package-level function doesn't exist yet).

- [ ] **Step 3: Extract the package-level function; method delegates**

In `internal/risk/service.go`, replace the method (currently at lines 77-92):

```go
// ComputeDeviceFingerprint generates a SHA256 fingerprint from IP subnet and User-Agent
func (s *Service) ComputeDeviceFingerprint(ipAddress, userAgent string) string {
	// Extract /24 subnet from IP
	subnet := ipAddress
	ip := net.ParseIP(ipAddress)
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			subnet = fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
		}
	}

	hash := sha256.Sum256([]byte(subnet + "|" + userAgent))
	return fmt.Sprintf("%x", hash)
}
```

with:

```go
// ComputeDeviceFingerprint generates a SHA256 fingerprint from IP subnet and User-Agent.
// Method form retained for existing callers; delegates to the package-level function
// so other services (e.g. the access proxy) can compute an identical fingerprint
// without constructing a risk.Service.
func (s *Service) ComputeDeviceFingerprint(ipAddress, userAgent string) string {
	return ComputeDeviceFingerprint(ipAddress, userAgent)
}

// ComputeDeviceFingerprint generates a SHA256 fingerprint from the IP's /24 subnet
// and the User-Agent: sha256("<x.y.z.0/24>|<userAgent>"). Pure and deterministic.
func ComputeDeviceFingerprint(ipAddress, userAgent string) string {
	// Extract /24 subnet from IP
	subnet := ipAddress
	ip := net.ParseIP(ipAddress)
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			subnet = fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
		}
	}

	hash := sha256.Sum256([]byte(subnet + "|" + userAgent))
	return fmt.Sprintf("%x", hash)
}
```

(The `crypto/sha256`, `fmt`, and `net` imports are already present in the file — no import changes.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/cmit/openidx && go test ./internal/risk/ -run TestComputeDeviceFingerprint -count=1 2>&1 | tail -5`
Expected: `ok  github.com/openidx/openidx/internal/risk` (both tests PASS).

- [ ] **Step 5: Confirm the whole risk package still builds/tests**

Run: `cd /home/cmit/openidx && go build ./internal/risk/... && go vet ./internal/risk/... && go test ./internal/risk/ -count=1 2>&1 | tail -3`
Expected: clean build/vet; `ok github.com/openidx/openidx/internal/risk`.

- [ ] **Step 6: Commit**

```bash
cd /home/cmit/openidx
gofmt -w internal/risk/service.go internal/risk/device_fingerprint_test.go
git add internal/risk/service.go internal/risk/device_fingerprint_test.go
git commit -m "refactor(risk): extract package-level ComputeDeviceFingerprint (D2 prep)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Add the `deviceTrusted` reader + a test DB harness (access)

The access package has no testcontainers harness yet, so this task adds one (mirroring `internal/governance/testdb_test.go`) and the reader, with a DB-backed test.

**Files:**
- Create: `internal/access/testdb_test.go` (shared harness for access DB tests)
- Create: `internal/access/device_trust.go` (the reader)
- Test: `internal/access/device_trust_test.go`

- [ ] **Step 1: Create the test DB harness**

Create `internal/access/testdb_test.go`:

```go
// Package access test helpers shared across the access test suite.
package access

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

- [ ] **Step 2: Write the failing test for `deviceTrusted`**

Create `internal/access/device_trust_test.go`:

```go
package access

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/risk"
)

func TestDeviceTrusted(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	// Minimal known_devices table (columns the reader uses).
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE known_devices (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			fingerprint VARCHAR(255),
			trusted BOOLEAN DEFAULT false,
			org_id UUID
		);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}

	const userID = "00000000-0000-0000-0000-000000000001"
	const ip = "192.168.1.50"
	const ua = "Mozilla/5.0 (TestAgent)"
	fp := risk.ComputeDeviceFingerprint(ip, ua)

	// No row yet → not trusted.
	if s.deviceTrusted(ctx, userID, ip, ua) {
		t.Error("expected false with no known_devices row")
	}

	// Seed a row for this fingerprint, trusted=false → still not trusted.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO known_devices (user_id, fingerprint, trusted, org_id) VALUES ($1,$2,false,$3)`,
		userID, fp, "00000000-0000-0000-0000-000000000010"); err != nil {
		t.Fatalf("seed untrusted: %v", err)
	}
	if s.deviceTrusted(ctx, userID, ip, ua) {
		t.Error("expected false when row exists but trusted=false")
	}

	// Flip to trusted=true → trusted.
	if _, err := db.Pool.Exec(ctx,
		`UPDATE known_devices SET trusted=true WHERE user_id=$1 AND fingerprint=$2`, userID, fp); err != nil {
		t.Fatalf("flip trusted: %v", err)
	}
	if !s.deviceTrusted(ctx, userID, ip, ua) {
		t.Error("expected true when matching row has trusted=true")
	}

	// Different UA (different fingerprint) → no match → not trusted.
	if s.deviceTrusted(ctx, userID, ip, "Different UA") {
		t.Error("expected false for a non-matching fingerprint")
	}

	// Empty userID → not trusted, no query.
	if s.deviceTrusted(ctx, "", ip, ua) {
		t.Error("expected false for empty userID")
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd /home/cmit/openidx && go test ./internal/access/ -run TestDeviceTrusted -count=1 2>&1 | tail -5`
Expected: compile failure — `s.deviceTrusted undefined` (method not implemented yet).

- [ ] **Step 4: Implement the reader**

Create `internal/access/device_trust.go`:

```go
package access

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/risk"
)

// deviceTrusted reports whether the request's device is a trusted known_device.
// Trust is per-device: it matches the authoritative known_devices.trusted flag by
// (user_id, fingerprint), where the fingerprint is computed the same way the risk
// service writes it (sha256 of the IP's /24 subnet + User-Agent). Absence of a row,
// an untrusted row, or any error all yield false (a missing device is not trusted).
func (s *Service) deviceTrusted(ctx context.Context, userID, ip, userAgent string) bool {
	if userID == "" {
		return false
	}
	fp := risk.ComputeDeviceFingerprint(ip, userAgent)

	var trusted bool
	err := s.db.Pool.QueryRow(ctx,
		//orgscope:ignore proxy data-plane device-trust read; resolves the already-authenticated session user's device by user_id + fingerprint (user_id is globally unique)
		`SELECT trusted FROM known_devices WHERE user_id=$1 AND fingerprint=$2 LIMIT 1`,
		userID, fp).Scan(&trusted)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Warn("device-trust lookup failed", zap.String("user_id", userID), zap.Error(err))
		}
		return false
	}
	return trusted
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd /home/cmit/openidx && go test ./internal/access/ -run TestDeviceTrusted -count=1 -v 2>&1 | tail -8`
Expected: `--- PASS: TestDeviceTrusted` and `ok github.com/openidx/openidx/internal/access`. (Uses testcontainers/Docker, ~10s. A SKIP is acceptable only if Docker is unavailable; a FAIL or compile error is not.)

- [ ] **Step 6: Confirm the package builds and vets**

Run: `cd /home/cmit/openidx && gofmt -w internal/access/device_trust.go internal/access/device_trust_test.go internal/access/testdb_test.go && go build ./internal/access/... && go vet ./internal/access/...`
Expected: no output (clean).

- [ ] **Step 7: Commit**

```bash
cd /home/cmit/openidx
git add internal/access/device_trust.go internal/access/device_trust_test.go internal/access/testdb_test.go
git commit -m "feat(access): deviceTrusted reader — match known_devices.trusted by fingerprint (D2)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Wire `deviceTrusted` into `buildAccessContext`

Replace the always-false read with the live lookup, writing the result back to `session` so it reaches the inline DSL and the G1 `/evaluate` call (which both read `session.DeviceTrusted`).

**Files:**
- Modify: `internal/access/context_evaluator.go:64-65`

- [ ] **Step 1: Make the edit**

In `internal/access/context_evaluator.go`, replace:

```go
	// Device trust from session
	ac.DeviceTrusted = session.DeviceTrusted
```

with:

```go
	// Device trust: is the request's device a trusted known_device? Computed per
	// request and written back to the session so the value also reaches the inline
	// policy DSL and the governance /evaluate call (both read session.DeviceTrusted).
	trusted := s.deviceTrusted(ctx, session.UserID, ac.ClientIP, ac.UserAgent)
	ac.DeviceTrusted = trusted
	session.DeviceTrusted = trusted
```

(`ctx`, `ac.ClientIP`, and `ac.UserAgent` are all already in scope at this point in `buildAccessContext`.)

- [ ] **Step 2: Build and vet**

Run: `cd /home/cmit/openidx && gofmt -w internal/access/context_evaluator.go && go build ./... && go vet ./internal/access/...`
Expected: no output (clean build across the whole module).

- [ ] **Step 3: Run the full access suite (no regressions)**

Run: `cd /home/cmit/openidx && go test ./internal/access/ -count=1 2>&1 | tail -5`
Expected: `ok github.com/openidx/openidx/internal/access` (includes `TestDeviceTrusted`).

- [ ] **Step 4: Commit**

```bash
cd /home/cmit/openidx
git add internal/access/context_evaluator.go
git commit -m "feat(access): populate DeviceTrusted from known_devices in buildAccessContext (D2)

buildAccessContext now computes the device's trust per request and writes it back
to the session, so the value feeds the context device-trust/risk checks, the inline
policy DSL, and the G1 governance /evaluate call (which sends session.DeviceTrusted).
Previously DeviceTrusted was never populated (always false): every request took a
+15 risk penalty, RequireDeviceTrust routes always denied, and the conditional_access
device_trust_required rule could never pass.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Live verification on the box

Deploy the rebuilt access binary and prove a trusted device is now recognized end-to-end. No commit.

**Files:** none (deployment only).

- [ ] **Step 1: Rebuild and restart the access service**

```bash
cd /home/cmit/openidx
go build -o /tmp/oidx-access-service.new ./cmd/access-service && \
systemctl --user stop oidx-access.service && \
cp /tmp/oidx-access-service.new /home/cmit/oidx-runtime/bin/oidx-access-service && \
systemctl --user start oidx-access.service && \
sleep 3 && systemctl --user is-active oidx-access.service && \
ss -ltnp 2>/dev/null | grep ':8007' | head -1
```
Expected: `active` and a listener on `:8007`.

- [ ] **Step 2: Confirm the reader matches a real known_devices row**

There are two `known_devices` rows for the default admin user (`00000000-0000-0000-0000-000000000001`), both `trusted=false`. Flip one to trusted and confirm the stored fingerprint is what the access reader would compute for some (ip, ua). Inspect the existing rows:

```bash
docker exec oidx-pg psql -U openidx -d openidx -tA -c "SELECT id, user_id, trusted, fingerprint, ip_address, user_agent FROM known_devices;" 2>&1 | grep -v 'Emulate\|nodocker'
```
The stored `fingerprint` should equal `sha256("<ip_address /24>|<user_agent>")` for that row's `ip_address`/`user_agent` — confirming the reader (which recomputes from the live request's IP+UA) will match a real browser session from the same /24 + UA.

- [ ] **Step 3: Prove trust flips the decision via the governance engine**

Seed a `conditional_access` policy whose rule requires device trust, attach it to a throwaway route, and evaluate with the internal token (reusing the G1 path) — once as untrusted, once as trusted. Concretely, evaluate the policy directly (the `/evaluate` contract reads `device_trusted` from the request body, which on the live proxy path is fed by `session.DeviceTrusted`):

```bash
TOKEN=$(cat /tmp/oidx-internal-token)
# create policy + rule (bypass_rls), capturing the policy id
PID='22222222-2222-2222-2222-2222222222dd'
ORG='00000000-0000-0000-0000-000000000010'
docker exec -i oidx-pg psql -U openidx -d openidx <<SQL 2>&1 | grep -v 'Emulate\|nodocker'
SET app.bypass_rls='on';
DELETE FROM policy_rules WHERE policy_id='$PID'; DELETE FROM policies WHERE id='$PID';
INSERT INTO policies (id,name,description,type,enabled,priority,created_at,updated_at,org_id)
VALUES ('$PID','D2 live test','device trust required','conditional_access',true,10,now(),now(),'$ORG');
INSERT INTO policy_rules (id,policy_id,rule_type,conditions,actions,created_at,org_id)
VALUES (gen_random_uuid(),'$PID','deny','{"device_trust_required":true}'::jsonb,'{"effect":"deny","priority":10}'::jsonb,now(),'$ORG');
SQL
# untrusted device → deny
curl -s -w "\n%{http_code}\n" -X POST "http://localhost:8002/api/v1/governance/policies/$PID/evaluate" \
  -H 'Content-Type: application/json' -H "X-Internal-Token: $TOKEN" -d '{"device_trusted":false}'
# trusted device → allow
curl -s -w "\n%{http_code}\n" -X POST "http://localhost:8002/api/v1/governance/policies/$PID/evaluate" \
  -H 'Content-Type: application/json' -H "X-Internal-Token: $TOKEN" -d '{"device_trusted":true}'
```
Expected: first call `{"allowed":false,...}`, second `{"allowed":true}`. This confirms the engine honors `device_trusted` — the value D2 now supplies from `known_devices` on the proxy path.

- [ ] **Step 4: Clean up the live test artifacts**

```bash
PID='22222222-2222-2222-2222-2222222222dd'
docker exec oidx-pg psql -U openidx -d openidx -c "SET app.bypass_rls='on'; DELETE FROM policy_rules WHERE policy_id='$PID'; DELETE FROM policies WHERE id='$PID';" 2>&1 | grep -v 'Emulate\|nodocker'
```
And if you flipped a `known_devices` row to `trusted=true` in Step 2, flip it back to its original value (leave the box's data as found). Expected: DB back to 0 policies.

- [ ] **Step 5: No commit** — report outcomes (service healthy, deny→allow flip on `device_trusted`, artifacts removed).

---

## Notes for the executor
- Tasks are dependency-ordered **1 → 2 → 3 → 4**. Task 2 depends on Task 1's package-level `risk.ComputeDeviceFingerprint`; Task 3 depends on Task 2's `deviceTrusted`.
- Task 1 is real TDD. Task 2 is TDD with a container-backed test. Task 3 is an integration edit verified by build + the full access suite (a standalone unit test of `buildAccessContext` would require a full gin request + route + ZitiManager and isn't worth the scaffolding; the live verification in Task 4 covers the end-to-end behavior).
- Never commit a red build: if any `go build`/`go vet`/`go test` step produces unexpected output, fix before committing.
- Out of scope (do NOT implement): persisting `DeviceTrusted` to the `proxy_sessions` column for `continuous_verify`; device auto-registration; combining trust with posture.
