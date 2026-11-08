package access

import (
	"context"
	"testing"
	"time"
)

// The disconnect sweep against the migrated schema and a broker that answers
// activeConnections: a served session is stamped and kept, an unserved one
// past the grace is ended with reason 'disconnected' and audited, one inside
// the grace is kept, a shared-account session is kept while anyone is on its
// connection, and a broker that cannot list ends nothing.
func TestDisconnectedPamSessionsEnd(t *testing.T) {
	f := newExternalPamFixture(t)
	ctx := f.octx()
	entry := f.entry("disc", "ssh", "direct", 22, `{}`)
	session := func(conn, guacUser string, age time.Duration) string {
		t.Helper()
		return f.scalar(`INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol, guac_connection_id, guac_username, started_at)
			VALUES ($1, $2, $3, 'ssh', $4, NULLIF($5,''), NOW() - make_interval(secs => $6)) RETURNING id::text`,
			f.org, entry, f.operator, conn, guacUser, age.Seconds())
	}
	status := func(id string) string {
		return f.scalar(`SELECT status FROM pam_entry_sessions WHERE id = $1`, id)
	}

	served := session("c1", "alice", time.Hour)      // on the broker as alice
	gone := session("c2", "bob", time.Hour)          // not on the broker
	fresh := session("c3", "carol", time.Minute)     // not yet on the broker, inside the grace
	shared := session("c1", "", time.Hour)           // shared account, its connection has someone on it
	sharedGone := session("c4", "", time.Hour)       // shared account, nobody on its connection
	otherUser := session("c1", "mallory", time.Hour) // same connection, but a different identity than the one served

	f.broker.mu.Lock()
	f.broker.active["a1"] = fakeBrokerActive{Conn: "c1", User: "alice"}
	f.broker.mu.Unlock()

	// A broker that cannot list ends nothing.
	broken := f.svc.guacamoleClient.baseURL
	f.svc.guacamoleClient.baseURL = "http://127.0.0.1:1"
	f.svc.reconcileDisconnectedPamSessions(ctx)
	f.svc.guacamoleClient.baseURL = broken
	for _, id := range []string{served, gone, fresh, shared, sharedGone, otherUser} {
		if status(id) != "active" {
			t.Fatalf("an unreachable broker ended session %s", id)
		}
	}

	f.svc.reconcileDisconnectedPamSessions(ctx)
	for name, tc := range map[string]struct{ id, want string }{
		"served":           {served, "active"},
		"gone":             {gone, "ended"},
		"inside the grace": {fresh, "active"},
		"shared, occupied": {shared, "active"},
		"shared, empty":    {sharedGone, "ended"},
		"another identity": {otherUser, "ended"},
	} {
		if got := status(tc.id); got != tc.want {
			t.Errorf("%s: %s, want %s", name, got, tc.want)
		}
	}
	if f.scalar(`SELECT (broker_last_seen_at IS NOT NULL)::text FROM pam_entry_sessions WHERE id = $1`, served) != "true" {
		t.Error("a served session was not stamped")
	}
	var audited int
	if err := f.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM unified_audit_events
		WHERE event_type = 'pam.session_ended' AND details->>'reason' = 'disconnected'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 3 {
		t.Errorf("%d disconnected ends audited, want 3", audited)
	}

	// Seen once, then gone: the grace runs from the last sighting, and the
	// end is dated to it.
	f.exec(`UPDATE pam_entry_sessions SET broker_last_seen_at = NOW() - interval '2 minutes' WHERE id = $1`, served)
	f.broker.mu.Lock()
	delete(f.broker.active, "a1")
	f.broker.mu.Unlock()
	f.svc.reconcileDisconnectedPamSessions(ctx)
	if status(served) != "active" {
		t.Error("a session last seen two minutes ago was ended inside the grace")
	}
	f.exec(`UPDATE pam_entry_sessions SET broker_last_seen_at = NOW() - interval '11 minutes' WHERE id = $1`, served)
	f.svc.reconcileDisconnectedPamSessions(ctx)
	if status(served) != "ended" {
		t.Error("a session gone for eleven minutes is still active")
	}
	if f.scalar(`SELECT (ended_at = broker_last_seen_at)::text FROM pam_entry_sessions WHERE id = $1`, served) != "true" {
		t.Error("the end is not dated to the last sighting")
	}
}
