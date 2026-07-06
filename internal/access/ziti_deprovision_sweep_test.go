package access

import (
	"context"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/openidx/openidx/internal/migrations"
)

// TestRunDeprovisionSweep_ValidOnUUIDUserID guards the v1.16.0 regression where the
// deprovision-sweep query compared the uuid column zi.user_id to ” (`!= ”`), which
// forced an empty-string→uuid cast and failed the whole query with 22P02 on every
// poll — silently disabling the IAM→Ziti revocation sweep. The query must now execute
// cleanly (no "Deprovision sweep query failed" warning) against a real uuid schema.
func TestRunDeprovisionSweep_ValidOnUUIDUserID(t *testing.T) {
	db, cleanup := setupTestDB(t) // skips if testcontainers unavailable
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	// Capture WARN logs; the sweep reports a query failure via logger.Warn, not a return.
	core, logs := observer.New(zap.WarnLevel)
	zm := &ZitiManager{db: db, logger: zap.New(core)}

	// Empty ziti_identities → the query runs, returns 0 rows, no controller calls.
	// Pre-fix this still 22P02'd (the `!= ''` cast is evaluated regardless of rows).
	zm.runDeprovisionSweep(ctx)

	for _, e := range logs.All() {
		if e.Message == "Deprovision sweep query failed" {
			t.Fatalf("deprovision sweep query still fails: %v", e.ContextMap()["error"])
		}
	}
}
