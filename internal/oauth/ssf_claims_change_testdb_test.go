package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/ssfsignal"
	"github.com/openidx/openidx/internal/migrations"
)

// A token-claims-change event says what a token issued at that moment says.
// On the migrated schema, a producer's row (internal/common/ssfsignal) is
// drained into a signed SET whose event carries the subject's roles, groups
// and permissions as GenerateJWT puts them in an access token:
//
//   - a standing role, a time-bound role inside its window, a group, and the
//     permissions the roles give; not a role whose window is over, and not
//     the role a poisoned row names in its own "claims";
//   - the producer's reason rides with them;
//   - a stream of the tenant that asked only for account-disabled gets
//     nothing;
//   - a session-revoked row is signed as session-revoked;
//   - a row whose subject's claims cannot be read is not signed, and stays
//     unpublished for the retry: a SET saying "no roles" would be false.
func TestATokenClaimsChangeSaysWhatATokenSays(t *testing.T) {
	db, cleanup := ssfSetupTestDB(t)
	t.Cleanup(cleanup)
	if db == nil {
		return
	}
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(bg, orgctx.Org{ID: org})
	bypass := orgctx.WithBypassRLS(bg)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(bypass, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(bypass, q, args...); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
	}
	subject := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "cc-subject-"+suffix)
	role := func(name, expires string) string {
		id := scalar(`INSERT INTO roles (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, name+"-"+suffix)
		exec(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at) VALUES ($1, $2, $3, NOW() + $4::interval)`,
			subject, id, org, expires)
		return id
	}
	standing := role("cc-standing", "100 years")
	role("cc-window", "1 hour")
	role("cc-lapsed", "-1 minute")
	perm := scalar(`INSERT INTO permissions (name, resource, action) VALUES ($1, 'reports', 'read') RETURNING id::text`, "cc-perm-"+suffix)
	exec(`INSERT INTO role_permissions (role_id, permission_id, org_id) VALUES ($1, $2, $3)`, standing, perm, org)
	group := scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "cc-group-"+suffix)
	exec(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1, $2, $3)`, subject, group, org)

	stream := func(audience string, events ...string) string {
		ev, _ := json.Marshal(events)
		return scalar(`INSERT INTO ssf_streams (org_id, audience, delivery_endpoint, events_requested)
			VALUES ($1, $2, 'https://receiver.example.test/events', $3) RETURNING id::text`, org, audience+"-"+suffix, string(ev))
	}
	wants := stream("https://cc-wants.example.test", EventTokenClaimsChange, EventSessionRevoked)
	stream("https://cc-declines.example.test", EventAccountDisabled)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{db: db, config: &config.Config{}, logger: zap.NewNop(),
		privateKey: key, publicKey: &key.PublicKey, issuer: "https://idp.example.test"}

	// What a token issued now says.
	tok, err := svc.GenerateJWT(ctx, subject, "admin-console", "openid", 300)
	if err != nil {
		t.Fatalf("mint a token: %v", err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	tokenClaims := parsed.Claims.(jwt.MapClaims)
	strs := func(v interface{}) []string {
		out := []string{}
		items, _ := v.([]interface{})
		for _, i := range items {
			out = append(out, fmt.Sprint(i))
		}
		slices.Sort(out)
		return out
	}
	wantRoles := []string{"cc-standing-" + suffix, "cc-window-" + suffix}
	if got := strs(tokenClaims["roles"]); !slices.Equal(got, wantRoles) {
		t.Fatalf("the token's roles are %v, want %v; the fixture is wrong", got, wantRoles)
	}

	// A producer's row, poisoned with claims of its own.
	if err := ssfsignal.Enqueue(ctx, db.Pool, ssfsignal.Signal{
		OrgID: org, EventType: ssfsignal.TokenClaimsChange, SubjectID: subject,
		Claims: map[string]interface{}{"reason": "access_granted", "claims": map[string]interface{}{"roles": []string{"superadmin"}}},
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := svc.drainSSFSignals(bypass); err != nil {
		t.Fatalf("drain: %v", err)
	}
	type delivered struct{ stream, event, set string }
	deliveries := func() []delivered {
		t.Helper()
		rows, err := db.Pool.Query(bypass, `SELECT stream_id::text, event_type, set_jwt FROM ssf_stream_delivery ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []delivered
		for rows.Next() {
			var d delivered
			if err := rows.Scan(&d.stream, &d.event, &d.set); err != nil {
				t.Fatal(err)
			}
			out = append(out, d)
		}
		return out
	}
	got := deliveries()
	if len(got) != 1 || got[0].stream != wants || got[0].event != EventTokenClaimsChange {
		t.Fatalf("deliveries: %+v; want one token-claims-change, on the stream that asked for it", got)
	}
	_, events := setEvents(t, got[0].set)
	ev, _ := events[EventTokenClaimsChange].(map[string]interface{})
	if ev == nil {
		t.Fatalf("the SET carries no token-claims-change event: %v", events)
	}
	if ev["reason"] != "access_granted" {
		t.Errorf("reason = %v, want the producer's access_granted", ev["reason"])
	}
	claims, _ := ev["claims"].(map[string]interface{})
	for _, name := range []string{"roles", "groups", "permissions"} {
		if got, want := strs(claims[name]), strs(tokenClaims[name]); !slices.Equal(got, want) {
			t.Errorf("the event's %s are %v; a token issued now says %v", name, got, want)
		}
	}
	if slices.Contains(strs(claims["roles"]), "superadmin") {
		t.Error("the event asserts the role the row named")
	}
	if got := strs(claims["permissions"]); !slices.Equal(got, []string{"reports:read"}) {
		t.Errorf("the event's permissions are %v, want [reports:read]", got)
	}
	if got := strs(claims["groups"]); !slices.Equal(got, []string{"cc-group-" + suffix}) {
		t.Errorf("the event's groups are %v, want the subject's group", got)
	}

	t.Run("a session-revoked row is signed as session-revoked", func(t *testing.T) {
		exec(`DELETE FROM ssf_stream_delivery`)
		if err := ssfsignal.Enqueue(ctx, db.Pool, ssfsignal.Signal{
			OrgID: org, EventType: ssfsignal.SessionRevoked, SubjectID: subject,
			Claims: map[string]interface{}{"reason": "external_suspended"},
		}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		if _, err := svc.drainSSFSignals(bypass); err != nil {
			t.Fatalf("drain: %v", err)
		}
		got := deliveries()
		if len(got) != 1 || got[0].stream != wants || got[0].event != EventSessionRevoked {
			t.Fatalf("deliveries: %+v; want one session-revoked, on the stream that asked for it", got)
		}
		_, events := setEvents(t, got[0].set)
		if ev, _ := events[EventSessionRevoked].(map[string]interface{}); ev == nil || ev["reason"] != "external_suspended" {
			t.Errorf("the SET's events: %v", events)
		}
	})

	t.Run("a subject whose claims cannot be read is not signed", func(t *testing.T) {
		exec(`DELETE FROM ssf_stream_delivery`)
		// Not a user id: every read of the claims fails.
		id := scalar(`INSERT INTO ssf_pending_events (org_id, event_type, subject_id) VALUES ($1, $2, 'not-a-user') RETURNING id::text`,
			org, ssfsignal.TokenClaimsChange)
		if _, err := svc.drainSSFSignals(bypass); err != nil {
			t.Fatalf("drain: %v", err)
		}
		if got := deliveries(); len(got) != 0 {
			t.Errorf("signed: %+v", got)
		}
		if published := scalar(`SELECT (published_at IS NOT NULL)::text FROM ssf_pending_events WHERE id = $1`, id); published != "false" {
			t.Error("the row was retired; it must stay for the retry")
		}
	})
}
