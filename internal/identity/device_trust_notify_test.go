package identity

import (
	"context"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

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

// The admin fan-out reaches every admin except the one who switched it off.
//
// This fixture builds its own schema rather than running the migration chain,
// and notification_preferences was not in it — so when the fan-out started
// consulting the administrator's own switch in the same statement, the INSERT
// failed on a missing relation, the best-effort contract swallowed the warning,
// and no admin was told a device was waiting. CI caught it; the table belongs
// here because this path reads it now.
//
// The opted-out admin is what makes the test cover the predicate instead of
// merely tolerating it: delete the NOT EXISTS and this goes red.
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
		CREATE TABLE notification_preferences (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL, channel VARCHAR(50) NOT NULL,
			event_type VARCHAR(100) NOT NULL, enabled BOOLEAN DEFAULT true,
			UNIQUE(user_id, channel, event_type)
		);
		CREATE TABLE roles (id UUID PRIMARY KEY, name VARCHAR(64), org_id UUID);
		CREATE TABLE user_roles (user_id UUID, role_id UUID, org_id UUID);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	const adminUser = "00000000-0000-0000-0000-0000000000aa"
	const optedOutAdmin = "00000000-0000-0000-0000-0000000000ab"
	const adminRole = "60000000-0000-0000-0000-000000000001"
	// Two separate Exec calls: pgx's extended protocol rejects multiple
	// parameterized commands in a single query string.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO roles (id, name, org_id) VALUES ($1,'admin',$2)`, adminRole, notifyTestOrg); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	for _, u := range []string{adminUser, optedOutAdmin} {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3)`, u, adminRole, notifyTestOrg); err != nil {
			t.Fatalf("seed user_role: %v", err)
		}
	}
	// One admin has turned in-app device-trust notices off on the preferences
	// page. Recording no row for the other is the product's default: a user who
	// has never touched the page is opted in.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO notification_preferences (user_id, channel, event_type, enabled)
		 VALUES ($1, 'in_app', 'device_trust', false)`, optedOutAdmin); err != nil {
		t.Fatalf("seed preference: %v", err)
	}

	// The fan-out is best-effort: it warns and returns rather than failing the
	// enrolment. That is right for the product and terrible for a test, which
	// otherwise sees only "0 notifications" and has to guess why. Reading the
	// warning back turns the next fixture drift into its own error message.
	core, logs := observer.New(zapcore.WarnLevel)
	s := &Service{db: db, logger: zap.New(core)}
	s.notifyAdminsOfTrustRequest(ctx, "00000000-0000-0000-0000-000000000001", "My Laptop")
	for _, e := range logs.All() {
		t.Errorf("the fan-out warned instead of notifying: %s %v", e.Message, e.ContextMap())
	}

	count := func(user string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx,
			`SELECT count(*) FROM notifications WHERE user_id=$1 AND type='device_trust'`, user).Scan(&n); err != nil {
			t.Fatalf("count for %s: %v", user, err)
		}
		return n
	}
	if n := count(adminUser); n != 1 {
		t.Fatalf("expected the admin to get 1 device_trust notification, got %d", n)
	}
	if n := count(optedOutAdmin); n != 0 {
		t.Fatalf("the admin who switched device-trust notices off got %d; the preferences "+
			"page promised that switch does something", n)
	}
}
