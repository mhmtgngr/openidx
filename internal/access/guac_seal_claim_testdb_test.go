package access

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// THE SEAL IS ANNOUNCED, AND AN ANNOUNCEMENT MADE TWICE IS A WRONG ANSWER.
//
// Every recording the sweep seals gets a `pam.recording.sealed` audit event
// carrying the digest and the key id -- which is how an auditor answers "when
// was this recording sealed, and under which key". The candidate query selects
// on `recording_sealed_at IS NULL` with no claim, so two replicas on the same
// tick both selected the same session. Before the fix that also meant both
// sealed the file (measured separately, in the double-seal test: that path
// destroys the recording); with the refusal in place the bytes are safe, and
// what is left to settle is the record.
//
// So the metadata write became the claim -- `AND recording_sealed_at IS NULL`
// -- and only the replica that claims announces. Two concurrent sealers, each
// with its own connection pool because one pool shared by goroutines is one
// process pretending to be two.
func TestTwoConcurrentSealersAnnounceTheSealOnce(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the seal claim test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	_, err = pool.Exec(ctx, `
		DROP TABLE IF EXISTS guacamole_sessions, audit_events;
		CREATE TABLE guacamole_sessions (
			id uuid primary key, org_id uuid, status text NOT NULL,
			recording_path text, recording_purged_at timestamptz,
			recording_sealed_at timestamptz, recording_sha256 text, recording_key_id int);
		CREATE TABLE audit_events (
			id uuid primary key, event_type text, category text, action text, outcome text,
			actor_id text, target_type text, resource_id text, details jsonb,
			created_at timestamptz NOT NULL DEFAULT NOW(), org_id uuid);`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS guacamole_sessions, audit_events;`)
	})

	root := t.TempDir()
	dir := filepath.Join(root, "sess")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	recPath := filepath.Join(dir, "recording")
	plaintext := make([]byte, 32*1024)
	_, err = rand.Read(plaintext)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(recPath, plaintext, 0o644))

	session := uuid.NewString()
	_, err = pool.Exec(ctx,
		`INSERT INTO guacamole_sessions (id, org_id, status, recording_path)
		 VALUES ($1, gen_random_uuid(), 'ended', $2)`, session, recPath)
	require.NoError(t, err)

	// One keyring shared by both replicas — they are the same install.
	ring := makeTestRing(t)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		replicaPool, perr := pgxpool.New(ctx, dsn)
		require.NoError(t, perr)
		t.Cleanup(replicaPool.Close)
		h := &RemoteSupportHandler{
			logger:             zap.NewNop(),
			db:                 &database.PostgresDB{Pool: database.NewScopedPool(replicaPool)},
			guacRecordingRing:  ring,
			guacRecordingsRoot: root,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.sealGuacRecordings(ctx)
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, countRows(t, pool, `SELECT count(*) FROM audit_events WHERE event_type = 'pam.recording.sealed'`),
		"the same seal was announced more than once; an auditor now has two answers to when this recording was sealed")
	assert.Equal(t, 1, countRows(t, pool, `SELECT count(*) FROM guacamole_sessions WHERE recording_sealed_at IS NOT NULL`))

	// WHAT THIS TEST DOES AND DOES NOT ESTABLISH, because it was measured
	// rather than assumed: with the refusal in place the second replica returns
	// before it ever reaches the claim, so removing the claim leaves this test
	// GREEN. It covers the bytes and the outcome, not the claim. The claim has
	// its own test below, against the unit the sweep calls.

	// And the recording itself survived the race: one decrypt pass reproduces
	// the session. This is the assertion the whole item exists for.
	h := &RemoteSupportHandler{logger: zap.NewNop(), guacRecordingRing: ring, guacRecordingsRoot: root}
	assertDecryptsTo(t, h, recPath, plaintext)
}

func countRows(t *testing.T, pool *pgxpool.Pool, q string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(), q).Scan(&n))
	return n
}

// The claim, tested where it actually operates: two replicas that both sealed
// the same plaintext -- the interleaving where the second reads the file before
// the first renames over it -- and therefore both reach the announcement. One
// of them must claim it, and only that one announces.
func TestOnlyTheClaimingReplicaAnnouncesASeal(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the seal claim test")
	}
	ctx := context.Background()
	pool, session := seedSealableSession(t, dsn)

	type outcome struct {
		claimed bool
		err     error
	}
	results := make([]outcome, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		replicaPool, perr := pgxpool.New(ctx, dsn)
		require.NoError(t, perr)
		t.Cleanup(replicaPool.Close)
		h := &RemoteSupportHandler{
			logger: zap.NewNop(),
			db:     &database.PostgresDB{Pool: database.NewScopedPool(replicaPool)},
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			claimed, err := h.recordGuacSeal(ctx, session, "", "deadbeef", 1)
			results[i] = outcome{claimed, err}
		}(i)
	}
	wg.Wait()

	require.NoError(t, results[0].err)
	require.NoError(t, results[1].err)
	claims := 0
	for _, r := range results {
		if r.claimed {
			claims++
		}
	}
	assert.Equal(t, 1, claims, "both replicas claimed the same seal")
	assert.Equal(t, 1, countRows(t, pool, `SELECT count(*) FROM audit_events WHERE event_type = 'pam.recording.sealed'`),
		"the seal was announced more than once")
}

// seedSealableSession builds the two tables the seal path writes and one ended
// session ready to be sealed.
func seedSealableSession(t *testing.T, dsn string) (*pgxpool.Pool, string) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	_, err = pool.Exec(ctx, `
		DROP TABLE IF EXISTS guacamole_sessions, audit_events;
		CREATE TABLE guacamole_sessions (
			id uuid primary key, org_id uuid, status text NOT NULL,
			recording_path text, recording_purged_at timestamptz,
			recording_sealed_at timestamptz, recording_sha256 text, recording_key_id int);
		CREATE TABLE audit_events (
			id uuid primary key, event_type text, category text, action text, outcome text,
			actor_id text, target_type text, resource_id text, details jsonb,
			created_at timestamptz NOT NULL DEFAULT NOW(), org_id uuid);`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS guacamole_sessions, audit_events;`)
	})

	session := uuid.NewString()
	_, err = pool.Exec(ctx,
		`INSERT INTO guacamole_sessions (id, status, recording_path) VALUES ($1, 'ended', '/tmp/none')`, session)
	require.NoError(t, err)
	return pool, session
}
