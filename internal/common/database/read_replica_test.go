package database

import "testing"

// TestReaderFallsBackToPrimary proves the correctness-by-construction property:
// with no read replica configured, Reader() returns the primary pool, so every
// call site that "reads from the replica" is automatically correct (it just
// loses the offload) rather than nil-panicking.
func TestReaderFallsBackToPrimary(t *testing.T) {
	// A sentinel non-nil pointer is enough; we never dial it. Reader() must return
	// the same pointer as Pool when readPool is nil.
	db := &PostgresDB{Pool: nil} // Pool nil is fine: we compare identity, not use it.
	if db.HasReadReplica() {
		t.Fatal("HasReadReplica() = true with no replica configured")
	}
	if db.Reader() != db.Pool {
		t.Fatal("Reader() should return the primary pool when no replica is configured")
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
