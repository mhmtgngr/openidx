package governance

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/externalid"
	"github.com/openidx/openidx/internal/migrations"
)

// Invariant I4 of the third-party access framework at fulfilment: an approved
// request of an external (vendor) user grants nothing until the account is
// active with a strong second factor. The test runs fulfillRequest, the one
// place every approval path (the decision handler, auto-approval) grants
// through, on the migrated schema: an external user with no factor and one
// still waiting for its first are refused and hold no membership; the same
// user with an authenticator gets it; an internal user with no factor is
// granted as before.
func TestAnExternalUsersApprovalWaitsForTheirSecondFactor(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(bg, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
		return v
	}
	sponsor := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "ful-sponsor-"+suffix)
	vendor := scalar(`INSERT INTO vendor_organizations (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "Acme "+suffix)
	external := scalar(`
		INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
		VALUES ($1, $2::text, $2::text || '@supplier.example.test', 'external', $3, $4, NOW() + interval '30 days')
		RETURNING id::text`, org, "ful-vendor-"+suffix, vendor, sponsor)
	group := scalar(`INSERT INTO groups (org_id, name, external_allowed) VALUES ($1, $2, true) RETURNING id::text`, org, "ful-vendors-"+suffix)

	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	fulfil := func(userID string) error {
		return s.fulfillRequest(ctx, &AccessRequest{ID: uuid.NewString(), RequesterID: userID, ResourceType: "group", ResourceID: group})
	}
	member := func(userID string) bool {
		var ok bool
		if err := db.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM group_memberships WHERE user_id = $1 AND group_id = $2)`,
			userID, group).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}

	if err := fulfil(external); !errors.Is(err, externalid.ErrNotActivated) {
		t.Fatalf("an external user with no second factor: %v, want ErrNotActivated", err)
	}
	if member(external) {
		t.Fatal("an external user with no second factor was given the group")
	}

	if _, err := db.Pool.Exec(ctx, `INSERT INTO mfa_totp (user_id, secret, enabled, org_id) VALUES ($1, 'JBSWY3DPEHPK3PXP', true, $2)`,
		external, org); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE users SET account_status = 'pending_mfa' WHERE id = $1`, external); err != nil {
		t.Fatal(err)
	}
	if err := fulfil(external); !errors.Is(err, externalid.ErrNotActivated) {
		t.Fatalf("an external account that is not active: %v, want ErrNotActivated", err)
	}

	if _, err := db.Pool.Exec(ctx, `UPDATE users SET account_status = 'active' WHERE id = $1`, external); err != nil {
		t.Fatal(err)
	}
	if err := fulfil(external); err != nil {
		t.Fatalf("an active external user with an authenticator: %v", err)
	}
	if !member(external) {
		t.Error("the active external user's approved request granted nothing")
	}

	if err := fulfil(sponsor); err != nil || !member(sponsor) {
		t.Errorf("an internal user with no second factor: %v, member %v; internal users are not held to I4", err, member(sponsor))
	}
}
