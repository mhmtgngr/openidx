package database

import "testing"

// TestReaderFallsBackToPrimary proves the correctness-by-construction property:
// with no read replica configured, Reader() returns the primary pool, so every
// call site that "reads from the replica" is automatically correct (it just
// loses the offload) rather than nil-panicking.
func TestReaderFallsBackToPrimary(t *testing.T) {
	// A sentinel non-nil pointer is enough; we never dial it. Reader() must return
	// the same pointer as Pool when readPool is nil.
	// &ScopedPool{} rather than NewScopedPool(nil): the constructor returns nil
	// for a nil pool, which would make the identity check below nil == nil and
	// pass whatever Reader() did. Never dialled — this compares identity.
	db := &PostgresDB{Pool: &ScopedPool{}}
	if db.HasReadReplica() {
		t.Fatal("HasReadReplica() = true with no replica configured")
	}
	if db.Reader() != db.Pool {
		t.Fatal("Reader() should return the primary pool when no replica is configured")
	}
}

// TestReaderIsScoped pins the half of the fallback that matters more than the
// identity above: the type.
//
// Reader() returned a bare *pgxpool.Pool for one commit after task 2.1b moved
// the tenant scope into Pool's type. Nothing broke, nothing failed to compile,
// and about a dozen read-path queries — user by id, by username, by email,
// sessions, groups, oauth clients — would have run with no app.org_id once
// RLS_MODE=local stopped the checkout hook from stamping the connection. Under
// FORCE RLS that is not an error; it is zero rows, so a login would have said
// the user does not exist.
//
// A compile-time assertion is the right shape for this: the day someone
// "simplifies" Reader() back to the raw pool to satisfy a signature, this file
// stops building instead of the fleet quietly stopping finding users.
func TestReaderIsScoped(t *testing.T) {
	var _ func(*PostgresDB) *ScopedPool = (*PostgresDB).Reader

	db := &PostgresDB{Pool: &ScopedPool{}, readPool: &ScopedPool{}}
	if !db.HasReadReplica() {
		t.Fatal("HasReadReplica() = false with a replica configured")
	}
	if db.Reader() != db.readPool {
		t.Fatal("Reader() should return the replica pool when one is configured")
	}
}

// TestPingReadNoReplicaIsNil proves that PingRead is a no-op (nil) when no
// replica is configured, so the health checker never fails on a missing replica.
func TestPingReadNoReplicaIsNil(t *testing.T) {
	db := &PostgresDB{}
	if err := db.PingRead(); err != nil {
		t.Fatalf("PingRead() with no replica should be nil, got %v", err)
	}
}
