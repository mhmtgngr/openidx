package admin

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/revocation"
)

// THE CENSUS PROVES THE CALL EXISTS. THIS PROVES IT FIRES.
//
// internal/revocation's sever census is an AST guard: it fails when a function
// that disables or deletes a user reaches nothing that writes the revocation
// marker. That is the right shape for a census and it cannot answer the next
// question -- whether the call runs, for the right user, on the path an
// operator actually takes.
//
// Every assertion below reads the marker back out of a real Redis, keyed by
// the user id, after driving the real admin path against a real PostgreSQL.
// The distinction matters most for stale-account cleanup, which severs by
// PREDICATE: its statement was changed from Exec to Query ... RETURNING id so
// there would be ids to revoke at all, and "the count still comes out right"
// is a separate claim from "each of those accounts was revoked".

func openAdminSeverPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the admin sever tests (they need a real Postgres)")
	}
	schema := "adminsever_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")

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

// TWO CLIENTS, ON PURPOSE, AND THIS IS NOT A DETAIL. The Redis roles were
// split three ways and the enforcement point reads only the revocation one.
// Wiring the same client to both would make "the marker went to the wrong
// role" invisible -- and a marker written where nothing reads it is precisely
// the defect internal/revocation's package doc was written about. So the
// general client and the revocation client are different databases here, and
// the assertions read the revocation one.
func openAdminSeverRedis(t *testing.T) (general, revocationDB *goredis.Client) {
	t.Helper()
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	open := func(db int) *goredis.Client {
		c := goredis.NewClient(&goredis.Options{Addr: addr, DB: db})
		if err := c.Ping(context.Background()).Err(); err != nil {
			t.Skipf("no Redis at %s: %v", addr, err)
		}
		require.NoError(t, c.FlushDB(context.Background()).Err())
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	return open(12), open(13)
}

func newAdminSeverService(t *testing.T, pool *pgxpool.Pool, general, revocationDB *goredis.Client) *Service {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		CREATE TABLE users (
			id uuid PRIMARY KEY, org_id uuid NOT NULL,
			username varchar(255), email varchar(255),
			enabled boolean DEFAULT true,
			last_login_at timestamptz,
			updated_at timestamptz DEFAULT NOW());`)
	require.NoError(t, err)
	return &Service{
		db:     &database.PostgresDB{Pool: database.NewScopedPool(pool)},
		redis:  &database.RedisClient{Client: general, Revocation: revocationDB},
		logger: zap.NewNop(),
	}
}

// revoked reports whether the enforcement point would now refuse a token this
// user held. It reads the key the enforcement point reads, not a counter kept
// by the test.
func revoked(t *testing.T, rdb *goredis.Client, userID string) bool {
	t.Helper()
	n, err := rdb.Exists(context.Background(), revocation.UserTokensRevokedAtKey(userID)).Result()
	require.NoError(t, err)
	return n > 0
}

func seedUser(t *testing.T, pool *pgxpool.Pool, org string, lastLogin string) string {
	t.Helper()
	id := uuid.NewString()
	var err error
	if lastLogin == "" {
		_, err = pool.Exec(context.Background(),
			`INSERT INTO users (id, org_id, username, enabled, last_login_at) VALUES ($1,$2,'u',true,NULL)`, id, org)
	} else {
		_, err = pool.Exec(context.Background(),
			`INSERT INTO users (id, org_id, username, enabled, last_login_at) VALUES ($1,$2,'u',true,NOW() - $3::interval)`,
			id, org, lastLogin)
	}
	require.NoError(t, err)
	return id
}

// THE ONE THAT CHANGED MOST. The cleanup severs by predicate, so before this
// work it had no ids at all and could not have revoked anything even in
// principle. RETURNING id is what makes the revocation possible; the count and
// the revocations are separate claims and both are checked.
func TestStaleAccountCleanupRevokesEveryAccountItDisables(t *testing.T) {
	pool := openAdminSeverPool(t)
	general, rdb := openAdminSeverRedis(t)
	svc := newAdminSeverService(t, pool, general, rdb)
	org := uuid.NewString()

	stale := []string{
		seedUser(t, pool, org, "200 days"),
		seedUser(t, pool, org, "91 days"),
		seedUser(t, pool, org, ""), // never logged in
	}
	// Two that must NOT be touched: one recently active, one in another tenant.
	active := seedUser(t, pool, org, "3 days")
	otherOrg := seedUser(t, pool, uuid.NewString(), "200 days")

	out := svc.applyRecommendation(context.Background(), org,
		Recommendation{RecommendationType: "stale_account_cleanup"})

	require.True(t, out.Applied, "the recommendation did not apply: %s", out.Message)
	require.Equal(t, len(stale), out.Count,
		"the count changed when the statement moved from Exec to Query ... RETURNING id")

	for _, id := range stale {
		require.False(t, revoked(t, general, id), "the marker for %s went to the general Redis, which nothing reads", id)
		require.True(t, revoked(t, rdb, id),
			"account %s was disabled by the cleanup and its outstanding access tokens were not revoked", id)
	}
	require.False(t, revoked(t, rdb, active), "an account the cleanup did not disable was revoked anyway")
	require.False(t, revoked(t, rdb, otherOrg), "another tenant's account was revoked")

	// And the sever itself still happened, so the assertions above are not
	// about an empty set.
	var enabled bool
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT enabled FROM users WHERE id = $1`, stale[0]).Scan(&enabled))
	require.False(t, enabled)
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT enabled FROM users WHERE id = $1`, otherOrg).Scan(&enabled))
	require.True(t, enabled, "the cleanup reached into another tenant")
}

// The shared helper every admin sever path calls. It is the one line thirteen
// call sites now depend on, so it is measured directly rather than only
// through the paths that use it: a nil client must not panic (breaking a
// disable because Redis is unconfigured would be the worse failure), and a
// working one must write the key the enforcement point reads.
func TestRevokeAfterSeverWritesTheKeyTheEnforcementPointReads(t *testing.T) {
	pool := openAdminSeverPool(t)
	general, rdb := openAdminSeverRedis(t)
	svc := newAdminSeverService(t, pool, general, rdb)

	user := uuid.NewString()
	svc.revokeAfterSever(context.Background(), user, "test")
	require.True(t, revoked(t, rdb, user))
	require.False(t, revoked(t, general, user),
		"the marker went to the GENERAL Redis. The enforcement point reads the revocation role and only "+
			"that one, so a marker written here is a revocation nothing will ever honour -- the exact "+
			"defect internal/revocation's package doc records.")

	// Empty id is a no-op rather than a key named after nothing.
	svc.revokeAfterSever(context.Background(), "", "test")
	n, err := rdb.Exists(context.Background(), revocation.UserTokensRevokedAtKey("")).Result()
	require.NoError(t, err)
	require.Zero(t, n)

	// And no Redis at all must not take the sever down with it.
	bare := &Service{db: svc.db, logger: zap.NewNop()}
	require.NotPanics(t, func() { bare.revokeAfterSever(context.Background(), uuid.NewString(), "test") })
}
