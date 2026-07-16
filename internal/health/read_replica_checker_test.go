package health

import (
	"context"
	"testing"

	"github.com/openidx/openidx/internal/common/database"
)

// TestReadReplicaCheckerNonCritical proves the replica checker never fails
// readiness: it is non-critical, and reports "up" when no replica is configured.
func TestReadReplicaCheckerNonCritical(t *testing.T) {
	db := &database.PostgresDB{} // no replica configured
	c := NewReadReplicaChecker(db)

	if c.IsCritical() {
		t.Fatal("ReadReplicaChecker must be non-critical so a replica outage can't fail readiness")
	}
	if c.Name() != "database_replica" {
		t.Fatalf("Name() = %q, want database_replica", c.Name())
	}

	got := c.Check(context.Background())
	if got.Status != "up" {
		t.Fatalf("with no replica, Check().Status = %q, want up", got.Status)
	}
}
