package access

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/risk"
)

// deviceTrustReqSchema mirrors the real tables at the point that matters:
// device_trust_requests.org_id is NOT NULL with no default, exactly as v72 left
// it. That single constraint is what this test is about.
const deviceTrustReqSchema = `
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true, org_id UUID NOT NULL);
CREATE TABLE IF NOT EXISTS known_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL,
    fingerprint VARCHAR(255) NOT NULL, name VARCHAR(255),
    trusted BOOLEAN NOT NULL DEFAULT false);
CREATE TABLE IF NOT EXISTS device_trust_requests (
    id UUID PRIMARY KEY, user_id UUID NOT NULL, device_id UUID NOT NULL,
    device_fingerprint VARCHAR(255) NOT NULL, device_name VARCHAR(255),
    device_type VARCHAR(50), ip_address VARCHAR(64), user_agent TEXT,
    justification TEXT, status VARCHAR(32) NOT NULL,
    org_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`

// TestDeviceTrustRequestIsActuallyFiled is the assertion that turns a warning
// line into a test failure.
//
// When an untrusted device reaches a device-trust-protected resource, the proxy
// refuses it and — in the words of ensureDeviceTrustRequest's own doc comment —
// "files a pending device-trust request for an untrusted device that attempted
// access, so an admin can approve it".
//
// v72 gave device_trust_requests an org_id and made it NOT NULL with no
// default. The INSERT in this file was never updated. So since v72 that
// statement has failed on every call with
//
//	null value in column "org_id" ... violates not-null constraint (23502)
//
// and the error was logged at WARN and swallowed, because the whole function is
// best-effort so it can never block the proxied request. The enforcement path
// refused the device, said it was raising a request, and raised nothing.
//
// A user locked out by device trust waited for an approval that was never in
// anybody's queue. The identity-side writer next door always wrote the tenant.
//
// Nothing was watching, which is exactly why this test reads the row back
// rather than asserting the call returned.
func TestDeviceTrustRequestIsActuallyFiled(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	if _, err := db.Pool.Exec(ctx, deviceTrustReqSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const org = "00000000-0000-0000-0000-0000000000f1"
	var userID string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO users (username, email, org_id) VALUES ('dt','dt@example.test',$1) RETURNING id::text`,
		org).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}
	const ip, ua = "203.0.113.9", "Mozilla/5.0 (test)"

	// The device must already be known; the login/risk path creates that row.
	fp := risk.ComputeDeviceFingerprint(ip, ua)
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO known_devices (user_id, fingerprint, name) VALUES ($1,$2,'laptop')`,
		userID, fp); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	s.ensureDeviceTrustRequest(ctx, userID, ip, ua)

	var n int
	var gotOrg, status string
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*), COALESCE(max(org_id::text),''), COALESCE(max(status),'')
		 FROM device_trust_requests WHERE user_id = $1`, userID).Scan(&n, &gotOrg, &status); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if n != 1 {
		t.Fatalf("the proxy filed %d device-trust requests, want 1. The insert omitted "+
			"org_id, which v72 made NOT NULL, so it failed with 23502 and the error was "+
			"logged and swallowed — the enforcement path refused the device and raised "+
			"nothing for anyone to approve", n)
	}
	if gotOrg != org {
		t.Errorf("request filed under org %q, want %q — the approval queue is org-scoped "+
			"on every read, so a request in the wrong tenant is a request nobody sees", gotOrg, org)
	}
	if status != "pending" {
		t.Errorf("request status %q, want pending", status)
	}

	// Idempotent: a second attempt on the same device must not re-file.
	s.ensureDeviceTrustRequest(ctx, userID, ip, ua)
	db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM device_trust_requests WHERE user_id = $1`, userID).Scan(&n)
	if n != 1 {
		t.Errorf("a second attempt filed a duplicate request (%d rows); the dedup check "+
			"must match within the tenant", n)
	}
}
