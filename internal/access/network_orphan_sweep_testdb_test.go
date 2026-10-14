package access

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// The orphan sweep's database half on the migrated schema: which application
// ids still own a network service (the reconciler's desired predicate), and
// the audit row a deletion writes under the application's organization.
func TestNetworkOrphanRefsOnTheMigratedSchema(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(bg, orgctx.Org{ID: org})

	seed := func(client, kind string, enabled, target bool) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `INSERT INTO applications (client_id, name, type, kind, org_id, enabled)
			VALUES ($1, $1, $2, $2, $3, $4) RETURNING id::text`, client, kind, org, enabled).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", client, err)
		}
		if target {
			if _, err := db.Pool.Exec(ctx, `INSERT INTO network_targets (application_id, org_id, cidrs)
				VALUES ($1, $2, '{10.0.0.0/24}')`, id, org); err != nil {
				t.Fatalf("seed target %s: %v", client, err)
			}
		}
		return id
	}
	owned := seed("orph-owned", "network", true, true)
	disabled := seed("orph-disabled", "network", false, true)
	noTarget := seed("orph-notarget", "network", true, false)
	web := seed("orph-web", "web", true, false)
	const deleted = "5555eeee-5555-4555-8555-555555555555"

	rec := &ZitiReconciler{db: db, logger: zap.NewNop(), status: map[string]string{}}
	refs, err := rec.loadNetworkOrphanRefs(bg, []string{owned, disabled, noTarget, web, deleted})
	if err != nil {
		t.Fatalf("loadNetworkOrphanRefs: %v", err)
	}
	if r := refs[owned]; !r.Owns || r.OrgID != org {
		t.Errorf("owned = %+v", r)
	}
	for name, id := range map[string]string{"disabled": disabled, "no target": noTarget, "web": web} {
		if r, ok := refs[id]; !ok || r.Owns || r.OrgID != org {
			t.Errorf("%s = %+v (present %v), want present and not owning", name, r, ok)
		}
	}
	if _, ok := refs[deleted]; ok {
		t.Error("a deleted application came back")
	}

	// The audit row lands under the application's organization.
	rec.auditNetworkOrphanDeletion(bg, networkOrphanObject{
		Collection: "configs", ID: "cfg-1", Name: networkServiceName(disabled) + "-host",
		AppID: disabled, CreatedAt: time.Now().Add(-time.Hour),
	}, refs[disabled])
	var n int
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM unified_audit_events
		WHERE org_id = $1 AND event_type = 'ziti_network_orphan_deleted' AND details->>'application_id' = $2`,
		org, disabled).Scan(&n); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if n != 1 {
		t.Errorf("audit rows = %d, want 1", n)
	}
}
