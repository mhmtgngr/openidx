package access

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/migrations"
)

// TestGuacLegalHoldBlocksPurge proves sweepExpiredGuacRecordings skips a Guacamole
// session under an active legal hold (recording is preserved), and purges it once the
// hold is released. Uses a migrated testcontainer DB (setupTestDB); the container's
// superuser bypasses RLS so seeding needs no org GUC.
func TestGuacLegalHoldBlocksPurge(t *testing.T) {
	db, cleanup := setupTestDB(t) // skips if testcontainers unavailable
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const defaultOrg = "00000000-0000-0000-0000-000000000010" // seeded by migrations

	// A recording artifact under the sweeper's configured root.
	root := t.TempDir()
	recDir := filepath.Join(root, "sess-rec")
	if err := os.MkdirAll(recDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recDir, "rec.guac"), []byte("recording"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Ended session, 100 days old (past the 90-day hard-fallback retention).
	var sessionID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO guacamole_sessions (org_id, connection_id, recording_path, status, started_at, ended_at)
		VALUES ($1::uuid, gen_random_uuid(), $2, 'ended', NOW() - INTERVAL '101 days', NOW() - INTERVAL '100 days')
		RETURNING id::text`, defaultOrg, recDir).Scan(&sessionID); err != nil {
		t.Fatalf("seed guac session: %v", err)
	}

	h := &RemoteSupportHandler{logger: zap.NewNop(), db: db, guacRecordingsRoot: root}

	// Active hold → the sweep must NOT purge.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO guacamole_recording_legal_holds (session_id, reason) VALUES ($1::uuid, 'litigation')`,
		sessionID); err != nil {
		t.Fatalf("place hold: %v", err)
	}
	h.sweepExpiredGuacRecordings(ctx)
	assertGuacPurged(t, ctx, db, sessionID, false)
	if _, err := os.Stat(recDir); err != nil {
		t.Errorf("held recording dir was removed: %v", err)
	}

	// Release the hold → the sweep must purge.
	if _, err := db.Pool.Exec(ctx,
		`UPDATE guacamole_recording_legal_holds SET released_at = NOW() WHERE session_id = $1::uuid`,
		sessionID); err != nil {
		t.Fatalf("release hold: %v", err)
	}
	h.sweepExpiredGuacRecordings(ctx)
	assertGuacPurged(t, ctx, db, sessionID, true)
	if _, err := os.Stat(recDir); !os.IsNotExist(err) {
		t.Errorf("released recording dir still exists (stat err=%v)", err)
	}
}

func assertGuacPurged(t *testing.T, ctx context.Context, db *database.PostgresDB, sessionID string, want bool) {
	t.Helper()
	var purgedAt *time.Time
	if err := db.Pool.QueryRow(ctx,
		`SELECT recording_purged_at FROM guacamole_sessions WHERE id = $1::uuid`, sessionID).Scan(&purgedAt); err != nil {
		t.Fatalf("query recording_purged_at: %v", err)
	}
	if got := purgedAt != nil; got != want {
		t.Errorf("recording_purged_at set=%v, want %v", got, want)
	}
}
