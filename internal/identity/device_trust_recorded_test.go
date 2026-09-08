package identity

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// A device the console says is trusted must be trusted.
//
// trustDevice ran two statements. The second — a nudge that marks the user's
// Ziti identity attributes stale so the sync poller recomputes #device-trusted
// sooner — checked its error and logged a warning. The first, the UPDATE that
// actually sets known_devices.trusted, discarded its error entirely.
//
// So the belt-and-braces statement was the checked one and the load-bearing
// statement was not. An administrator could approve a trust request, the
// request row would say approved, the user would be notified that their device
// was approved, and the posture gate would go on refusing the device — for a
// reason visible nowhere in the console.
//
// Nought rows matters as much as an error: it means no known_devices row
// matched this user and fingerprint in this org, so nothing was trusted.

func TestTrustingADeviceThatIsNotThereIsReported(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const orgID = "00000000-0000-0000-0000-000000000070"
	const userID = "aaaaaaaa-0000-0000-0000-000000000070"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE known_devices (
			user_id UUID NOT NULL,
			fingerprint TEXT NOT NULL,
			trusted BOOLEAN NOT NULL DEFAULT false,
			org_id UUID NOT NULL);
		CREATE TABLE ziti_identities (
			user_id UUID NOT NULL,
			group_attrs_synced_at TIMESTAMPTZ,
			org_id UUID NOT NULL);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}

	// Nothing to trust: the caller must hear about it rather than reporting an
	// approval the device never received.
	if err := s.trustDevice(ctx, userID, "a-fingerprint"); err == nil {
		t.Error("trusting a device with no known_devices row reported success. The trust request is marked " +
			"approved, the user is told their device was approved, and the posture gate keeps refusing it.")
	}

	// With the row there, it works and the device really is trusted.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO known_devices (user_id, fingerprint, trusted, org_id) VALUES ($1, $2, false, $3)`,
		userID, "a-fingerprint", orgID); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if err := s.trustDevice(ctx, userID, "a-fingerprint"); err != nil {
		t.Fatalf("trusting a device that is there must succeed: %v", err)
	}
	var trusted bool
	if err := db.Pool.QueryRow(ctx,
		`SELECT trusted FROM known_devices WHERE user_id = $1 AND fingerprint = $2 AND org_id = $3`,
		userID, "a-fingerprint", orgID).Scan(&trusted); err != nil {
		t.Fatalf("read the device back: %v", err)
	}
	if !trusted {
		t.Error("trustDevice returned success and the device is not trusted")
	}
}

func TestTrustingADeviceTheDatabaseRefusesIsReported(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const orgID = "00000000-0000-0000-0000-000000000071"
	const userID = "aaaaaaaa-0000-0000-0000-000000000071"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE known_devices (
			user_id UUID NOT NULL,
			fingerprint TEXT NOT NULL,
			trusted BOOLEAN NOT NULL DEFAULT false,
			org_id UUID NOT NULL);
		CREATE TABLE ziti_identities (
			user_id UUID NOT NULL,
			group_attrs_synced_at TIMESTAMPTZ,
			org_id UUID NOT NULL);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO known_devices (user_id, fingerprint, trusted, org_id) VALUES ($1, $2, false, $3)`,
		userID, "a-fingerprint", orgID); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		CREATE FUNCTION refuse_trust() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refusing the trust write'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER refuse_trust BEFORE UPDATE ON known_devices
		FOR EACH ROW EXECUTE FUNCTION refuse_trust();`); err != nil {
		t.Fatalf("install the failure: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}
	if err := s.trustDevice(ctx, userID, "a-fingerprint"); err == nil {
		t.Fatal("a trust write the database refused reported success")
	}

	var trusted bool
	if err := db.Pool.QueryRow(ctx,
		`SELECT trusted FROM known_devices WHERE user_id = $1 AND org_id = $2`, userID, orgID).Scan(&trusted); err != nil {
		t.Fatalf("read the device back: %v", err)
	}
	if trusted {
		t.Error("the failure injection did not take — the device is trusted, so this test is not exercising " +
			"the path it claims")
	}
}
