package directory

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/ssfsignal"
)

// A sync that changes a synced group's members tells the tenant's SSF
// receivers (CAEP token-claims-change): the members it added and the ones it
// dropped, not the ones it kept; and deleting a synced group tells every
// member it had.
func TestASyncThatChangesAGroupTellsTheReceivers(t *testing.T) {
	db, cleanup := membershipTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()
	seedMembershipFixture(t, ctx, db)
	seedGroupRow(t, ctx, db)
	const memNew = "33333333-0000-0000-0000-000000000063"
	// The pending-signal table as v196 creates it, as far as a producer
	// writes it.
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE ssf_pending_events (
			id BIGSERIAL PRIMARY KEY, org_id UUID NOT NULL, event_type TEXT NOT NULL,
			subject_id TEXT NOT NULL, subject_email TEXT NOT NULL DEFAULT '',
			claims JSONB NOT NULL DEFAULT '{}'::jsonb);
		INSERT INTO users (id, directory_id, org_id) VALUES ('`+memNew+`', '`+memDir+`', '`+memOrg+`')`); err != nil {
		t.Fatalf("create the pending-signal table: %v", err)
	}
	signals := func(userID string) []string {
		t.Helper()
		rows, err := db.Pool.Query(ctx, `SELECT claims->>'reason' FROM ssf_pending_events
			WHERE subject_id = $1 AND event_type = $2 AND org_id = $3 ORDER BY id`, userID, ssfsignal.TokenClaimsChange, memOrg)
		if err != nil {
			t.Fatalf("read the signals: %v", err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var r string
			if err := rows.Scan(&r); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}

	e := &SyncEngine{db: db, logger: zap.NewNop()}
	if err := e.replaceDirectoryMemberships(ctx, memGroup, memDir, memOrg, []string{memKeep, memNew}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	const changed = "directory sync: group membership changed"
	for _, c := range []struct {
		who, userID string
		want        int
	}{{"a member the sync kept", memKeep, 0}, {"a member the sync dropped", memGone, 1}, {"a member the sync added", memNew, 1}} {
		if got := signals(c.userID); len(got) != c.want || (c.want == 1 && got[0] != changed) {
			t.Errorf("%s: signals %v, want %d with reason %q", c.who, got, c.want, changed)
		}
	}

	if err := e.deleteSyncedGroup(ctx, memGroup, memOrg, "directory sync: group removed"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	for _, u := range []string{memKeep, memNew} {
		got := signals(u)
		if len(got) == 0 || got[len(got)-1] != "directory sync: group removed" {
			t.Errorf("deleting the group did not tell its member %s: %v", u, got)
		}
	}
}
