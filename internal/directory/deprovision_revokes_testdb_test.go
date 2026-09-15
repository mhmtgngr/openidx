package directory

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// A DEPROVISION IS NOT DONE WHEN THE ROW IS DISABLED.
//
// The upstream directory -- an HR feed, an LDAP tree, an Azure AD tenant -- has
// said this person has gone. The engine disables or deletes their row, which
// stops the NEXT login. /oauth/userinfo and /oauth/introspect read the per-user
// revocation marker and the per-token blacklist and nothing else, so the access
// token already in that browser answers until it expires on its own.
//
// The wiring guard next door checks that a binary running syncs supplies the
// callback. This checks the other half, which no static guard here can: that
// the engine actually calls it. Measured against a real PostgreSQL, because
// "it revoked" has to mean the row really changed and the callback really fired
// for that user, not that a line exists.

func openDirectoryPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the deprovision tests (they need a real Postgres)")
	}
	schema := "dir_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")

	bootstrap, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	_, err = bootstrap.Exec(context.Background(), `CREATE SCHEMA `+schema)
	bootstrap.Close()
	require.NoError(t, err, "the test DSN must be allowed to create a schema")

	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		pool.Close()
		if drop, derr := pgxpool.New(context.Background(), dsn); derr == nil {
			_, _ = drop.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
			drop.Close()
		}
	})
	return pool
}

type recordingRevoker struct {
	mu   sync.Mutex
	seen []string
}

func (r *recordingRevoker) fn(_ context.Context, userID, _ string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, userID)
}

func (r *recordingRevoker) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func seedDirectoryUsers(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		CREATE TABLE users (
			id uuid PRIMARY KEY, org_id uuid NOT NULL,
			username varchar(255), email varchar(255),
			first_name varchar(255), last_name varchar(255),
			enabled boolean DEFAULT true,
			employment_status varchar(50), termination_date date,
			updated_at timestamptz DEFAULT NOW());`)
	require.NoError(t, err)
}

func newTestEngine(pool *pgxpool.Pool, rec *recordingRevoker) *SyncEngine {
	e := NewSyncEngine(&database.PostgresDB{Pool: database.NewScopedPool(pool)}, zap.NewNop())
	if rec != nil {
		e.revoke = rec.fn
	}
	return e
}

func TestDeprovisioningAUserAlsoRevokesTheirTokens(t *testing.T) {
	pool := openDirectoryPool(t)
	seedDirectoryUsers(t, pool)

	for _, tc := range []struct{ name, action string }{
		{"the HR feed terminates them", "disable"},
		{"the HR feed deletes them", "delete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordingRevoker{}
			e := newTestEngine(pool, rec)

			org, user := uuid.NewString(), uuid.NewString()
			_, err := pool.Exec(context.Background(),
				`INSERT INTO users (id, org_id, username, enabled) VALUES ($1,$2,'leaver',true)`, user, org)
			require.NoError(t, err)

			var result SyncResult
			e.deprovisionHR(context.Background(), org, user, "leaver", tc.action, &result)

			// The sever itself happened, so the assertion below is about the
			// token and not about a no-op.
			var stillEnabled int
			require.NoError(t, pool.QueryRow(context.Background(),
				`SELECT count(*) FROM users WHERE id = $1 AND enabled = true`, user).Scan(&stillEnabled))
			require.Zero(t, stillEnabled, "the account was not severed, so this test proves nothing about the token")

			require.Equal(t, []string{user}, rec.calls(),
				"the directory deprovisioned this user and their outstanding access tokens were not revoked. "+
					"Disabling or deleting the row stops the next login; the token already issued reads the "+
					"per-user revocation marker and the per-token blacklist and nothing else.")
		})
	}
}

// NIL-SAFE ON PURPOSE, and that has to keep being true: a deployment with no
// revocation client must still deprovision, because a sync that refuses to run
// is worse than one that leaves a token live.
func TestDeprovisioningStillWorksWithNoRevoker(t *testing.T) {
	pool := openDirectoryPool(t)
	seedDirectoryUsers(t, pool)

	e := newTestEngine(pool, nil)
	org, user := uuid.NewString(), uuid.NewString()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, org_id, username, enabled) VALUES ($1,$2,'leaver',true)`, user, org)
	require.NoError(t, err)

	var result SyncResult
	require.NotPanics(t, func() {
		e.deprovisionHR(context.Background(), org, user, "leaver", "disable", &result)
	})

	var enabled bool
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT enabled FROM users WHERE id = $1`, user).Scan(&enabled))
	require.False(t, enabled, "the deprovision must still happen without a revoker")
	require.Equal(t, 1, result.UsersDisabled)
}
