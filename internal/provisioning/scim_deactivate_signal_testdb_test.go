package provisioning

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/ssfsignal"
	"github.com/openidx/openidx/internal/migrations"
)

// A SCIM push that deactivates a user tells the SSF receivers, as a SCIM
// delete does: `active:false` is the standard IdP deprovisioning signal, and
// the receivers downstream of this product subscribed to account-disabled. On
// the migrated schema, through UpdateSCIMUser (the choke point of PUT and of
// PATCH active):
//
//   - the push that deactivates the user enqueues one account-disabled;
//   - another push of the user while inactive enqueues nothing;
//   - reactivating enqueues nothing, and deactivating again enqueues one more;
//   - another user's push is not about this one.
func TestASCIMDeactivationTellsTheReceiversOnce(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(bg, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	user := func(name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `INSERT INTO users (org_id, username, email, enabled) VALUES ($1, $2::text, $2::text || '@example.test', true) RETURNING id::text`,
			org, name+"-"+suffix).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		return id
	}
	subject, bystander := user("sd-subject"), user("sd-bystander")
	signals := func(id string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM ssf_pending_events WHERE subject_id = $1 AND event_type = $2`,
			id, ssfsignal.AccountDisabled).Scan(&n); err != nil {
			t.Fatalf("count the signals: %v", err)
		}
		return n
	}
	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	push := func(id string, active bool) {
		t.Helper()
		var name string
		if err := db.Pool.QueryRow(ctx, `SELECT username FROM users WHERE id = $1`, id).Scan(&name); err != nil {
			t.Fatal(err)
		}
		u := &SCIMUser{UserName: name, Active: active, Emails: []SCIMEmail{{Value: name + "@example.test", Primary: true}}}
		if _, err := svc.UpdateSCIMUser(ctx, id, u); err != nil {
			t.Fatalf("push active=%v for %s: %v", active, id, err)
		}
	}

	push(subject, false)
	if n := signals(subject); n != 1 {
		t.Fatalf("the push that deactivated the user enqueued %d account-disabled, want 1", n)
	}
	push(subject, false)
	if n := signals(subject); n != 1 {
		t.Errorf("a push of a user already inactive enqueued another: %d", n)
	}
	push(subject, true)
	if n := signals(subject); n != 1 {
		t.Errorf("reactivating enqueued one: %d", n)
	}
	push(subject, false)
	if n := signals(subject); n != 2 {
		t.Errorf("deactivating again enqueued %d in all, want 2", n)
	}
	push(bystander, true)
	if n := signals(bystander); n != 0 {
		t.Errorf("an active user's push enqueued %d", n)
	}
}
