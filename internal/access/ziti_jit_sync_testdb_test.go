package access

import (
	"context"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// The user sync keeps a live network grant's attribute and drops it with the
// window, on the migrated schema against a stand-in controller. The sync
// rewrites an identity's whole attribute set, so before this the jit-<id>
// attribute the grant worker added was stripped at the next sync, window or
// not. Now:
//
//   - a sync while the window lasts keeps the attribute, and leaves out the
//     attribute of another user's request and of a request still pending;
//   - when the window ends, the poller's next pass re-syncs the identity, with
//     nothing else having changed, and the attribute is gone.
func TestTheUserSyncFollowsANetworkServiceWindow(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	bypass := orgctx.WithBypassRLS(ctx)
	const org = "00000000-0000-0000-0000-000000000010"
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
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
	user := func(name string) string {
		return scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
			org, name+"-"+suffix)
	}
	holder, other := user("js-holder"), user("js-other")
	service := scalar(`INSERT INTO ziti_services (org_id, ziti_id, name, host, port) VALUES ($1, $2, $2, 'db.example.test', 5432) RETURNING id::text`,
		org, "zsvc-js-"+suffix)
	request := func(userID, status string) string {
		return scalar(`INSERT INTO access_requests (org_id, requester_id, resource_type, resource_id, resource_name, justification, status, expires_at)
			VALUES ($1, $2, 'network_service', $3, 'db', 'reconcile', $4, NOW() + interval '2 hours') RETURNING id::text`, org, userID, service, status)
	}
	live, othersLive, pending := request(holder, "fulfilled"), request(other, "fulfilled"), request(holder, "pending")

	overlay := &acceptanceOverlay{policies: &fakeController{}, attrs: map[string][]string{}}
	ctrl := httptest.NewServer(overlay)
	t.Cleanup(ctrl.Close)
	zcfg := MockConfig(t)
	zcfg.ZitiCtrlURL = ctrl.URL
	zm := &ZitiManager{cfg: zcfg, logger: zap.NewNop(), db: db, mgmtToken: "t", mgmtClient: ctrl.Client()}
	identity := "zid-js-" + suffix
	exec(`INSERT INTO ziti_identities (ziti_id, name, identity_type, user_id, enrolled, org_id) VALUES ($1, $1, 'User', $2, true, $3)`,
		identity, holder, org)

	if err := zm.SyncGroupAttributesForUser(bypass, holder); err != nil {
		t.Fatalf("sync: %v", err)
	}
	attrs := overlay.attributes(identity)
	if !slices.Contains(attrs, "jit-"+live) {
		t.Errorf("a sync in the window left out the request's attribute: %v", attrs)
	}
	for _, id := range []string{othersLive, pending} {
		if slices.Contains(attrs, "jit-"+id) {
			t.Errorf("the identity carries jit-%s, which is not a live request of its user's: %v", id, attrs)
		}
	}

	// Two hours and a minute pass; the identity's last sync was in the window.
	exec(`UPDATE access_requests SET expires_at = expires_at - interval '2 hours 1 minute' WHERE id = $1`, live)
	exec(`UPDATE ziti_identities SET group_attrs_synced_at = group_attrs_synced_at - interval '2 hours 1 minute' WHERE ziti_id = $1`, identity)
	zm.resyncChangedAssignments(bypass)
	if attrs := overlay.attributes(identity); slices.Contains(attrs, "jit-"+live) {
		t.Errorf("the window ended and the poller's pass kept the request's attribute: %v", attrs)
	}
}
