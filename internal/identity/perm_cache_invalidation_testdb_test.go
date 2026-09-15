package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// A REVOKED PERMISSION HAS TO STOP BEING HONOURED, and the thing standing
// between the revoke and the enforcement point is a Redis cache.
//
// PermissionResolver caches a role set's effective permissions under
// `perms:v2:<org>:<sorted role names>` and RequirePermission decides from that
// cache. SetRolePermissions is the write path, and it calls
// invalidatePermissionCache to clear what it just made wrong.
//
// The invalidation is a glob SCAN over `perms:*<roleName>*`, and a glob is not
// a string comparison. These tests ask the two questions that follow from
// that, against a real Redis, because Redis is the thing whose matching rules
// are in question and a fake would have my rules rather than its own.

func openPermPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the permission cache tests (they need a real Postgres)")
	}
	schema := "perm_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")

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

func openPermRedis(t *testing.T) *goredis.Client {
	t.Helper()
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	c := goredis.NewClient(&goredis.Options{Addr: addr, DB: 14})
	if err := c.Ping(context.Background()).Err(); err != nil {
		t.Skipf("no Redis at %s: %v", addr, err)
	}
	require.NoError(t, c.FlushDB(context.Background()).Err())
	t.Cleanup(func() { _ = c.Close() })
	return c
}

type permFixture struct {
	svc  *Service
	pool *pgxpool.Pool
	rdb  *goredis.Client
}

func seedPerms(t *testing.T, pool *pgxpool.Pool, rdb *goredis.Client) *permFixture {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		CREATE TABLE roles (
			id uuid PRIMARY KEY, name varchar(255) NOT NULL, description text,
			is_composite boolean DEFAULT false, org_id uuid NOT NULL,
			created_at timestamptz DEFAULT NOW(), updated_at timestamptz DEFAULT NOW());
		CREATE TABLE permissions (
			id uuid PRIMARY KEY, name varchar(255), description text,
			resource varchar(255) NOT NULL, action varchar(255) NOT NULL,
			created_at timestamptz DEFAULT NOW());
		CREATE TABLE role_permissions (
			role_id uuid NOT NULL, permission_id uuid NOT NULL, org_id uuid NOT NULL,
			PRIMARY KEY (role_id, permission_id));`)
	require.NoError(t, err)

	return &permFixture{
		svc: &Service{
			db:     &database.PostgresDB{Pool: database.NewScopedPool(pool)},
			redis:  &database.RedisClient{Client: rdb},
			logger: zap.NewNop(),
		},
		pool: pool,
		rdb:  rdb,
	}
}

// addRole creates a role in an org and grants it one permission.
func (f *permFixture) addRole(t *testing.T, org, name, resource, action string) (roleID, permID string) {
	t.Helper()
	roleID, permID = uuid.NewString(), uuid.NewString()
	ctx := context.Background()
	_, err := f.pool.Exec(ctx, `INSERT INTO roles (id, name, org_id) VALUES ($1, $2, $3)`, roleID, name, org)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `INSERT INTO permissions (id, name, resource, action) VALUES ($1, $2, $3, $4)`,
		permID, resource+":"+action, resource, action)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `INSERT INTO role_permissions (role_id, permission_id, org_id) VALUES ($1, $2, $3)`,
		roleID, permID, org)
	require.NoError(t, err)
	return roleID, permID
}

// resolve drives the REAL middleware for one request and reports the
// permissions the enforcement point would decide from.
func (f *permFixture) resolve(t *testing.T, org string, roles ...string) []middleware.PermissionEntry {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Set("roles", roles)
		c.Set("user_id", "u1")
		c.Next()
	})
	r.Use(middleware.PermissionResolver(f.svc.db.Pool, f.rdb))

	var got []middleware.PermissionEntry
	r.GET("/x", func(c *gin.Context) {
		if v, ok := c.Get("permissions"); ok {
			if p, ok := v.([]middleware.PermissionEntry); ok {
				got = p
			}
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	require.Equal(t, http.StatusOK, w.Code)
	return got
}

func permOrgCtx(org string) context.Context {
	return orgctx.With(context.Background(), orgctx.Org{ID: org})
}

func grants(perms []middleware.PermissionEntry, resource, action string) bool {
	for _, p := range perms {
		if p.Resource == resource && p.Action == action {
			return true
		}
	}
	return false
}

// The ordinary case, and the control for everything below.
func TestRevokingAPermissionStopsItBeingHonouredOnTheNextRequest(t *testing.T) {
	f := seedPerms(t, openPermPool(t), openPermRedis(t))
	org := uuid.NewString()
	roleID, _ := f.addRole(t, org, "editor", "documents", "write")

	require.True(t, grants(f.resolve(t, org, "editor"), "documents", "write"), "the grant must be in effect first")

	require.NoError(t, f.svc.SetRolePermissions(permOrgCtx(org), roleID, nil))

	require.False(t, grants(f.resolve(t, org, "editor"), "documents", "write"),
		"a revoked permission was still honoured: the write path did not clear what it made wrong")
}

// THE ONE THAT MATTERS. Role names come straight from the request body --
// handleCreateRole binds into a struct with no validation on Name -- and the
// invalidation interpolates that name into a Redis MATCH pattern. `[` opens a
// character class, so `perms:*ops[x]*` looks for "ops" followed by the single
// character `x`, and the key it is meant to delete (which contains a literal
// `[`) matches nothing.
//
// The revoke succeeds, the API returns 200, and the enforcement point keeps
// granting the permission until the entry expires on its own.
func TestARoleWhoseNameContainsAGlobCharacterIsStillInvalidated(t *testing.T) {
	for _, name := range []string{
		"ops[x]",   // a character class: matches one of x, and not a literal [
		"team[a-z", // unterminated, which Redis treats as never matching
		`back\slash`,
	} {
		t.Run(name, func(t *testing.T) {
			f := seedPerms(t, openPermPool(t), openPermRedis(t))
			org := uuid.NewString()
			roleID, _ := f.addRole(t, org, name, "documents", "write")

			require.True(t, grants(f.resolve(t, org, name), "documents", "write"))
			require.NoError(t, f.svc.SetRolePermissions(permOrgCtx(org), roleID, nil))

			require.False(t, grants(f.resolve(t, org, name), "documents", "write"),
				"a permission revoked from role %q is still being granted. The role name is interpolated "+
					"into a Redis MATCH pattern, and the name carries glob syntax, so the SCAN that is "+
					"supposed to delete the stale entry matches nothing. Role names come from the request "+
					"body with no validation, and the revoke reports success.", name)
		})
	}
}

// AND THE OVER-INVALIDATION, which is not a correctness bug but is a cost
// nobody chose: one tenant editing a role named "admin" should not empty every
// other tenant's cache for their own "admin".
func TestInvalidatingOneTenantsRoleLeavesAnotherTenantsCacheAlone(t *testing.T) {
	f := seedPerms(t, openPermPool(t), openPermRedis(t))
	orgA, orgB := uuid.NewString(), uuid.NewString()
	roleA, _ := f.addRole(t, orgA, "admin", "documents", "write")
	f.addRole(t, orgB, "admin", "documents", "write")

	require.True(t, grants(f.resolve(t, orgA, "admin"), "documents", "write"))
	require.True(t, grants(f.resolve(t, orgB, "admin"), "documents", "write"))
	require.Equal(t, int64(2), permKeys(t, f.rdb), "both tenants' entries are warm")

	require.NoError(t, f.svc.SetRolePermissions(permOrgCtx(orgA), roleA, nil))

	require.Equal(t, int64(1), permKeys(t, f.rdb),
		"editing one tenant's role emptied another tenant's cache. Role names are per-tenant -- the same "+
			"'admin' exists in every organization -- so on a large install one role edit makes every "+
			"administrator on the platform re-query at once.")
	// And org B is still correct, which is the half that must not regress.
	require.True(t, grants(f.resolve(t, orgB, "admin"), "documents", "write"))
}

// The same shape within one tenant: "ops" must not invalidate "devops".
func TestARoleNameThatIsASubstringOfAnotherDoesNotInvalidateIt(t *testing.T) {
	f := seedPerms(t, openPermPool(t), openPermRedis(t))
	org := uuid.NewString()
	opsID, _ := f.addRole(t, org, "ops", "servers", "restart")
	f.addRole(t, org, "devops", "pipelines", "run")

	require.True(t, grants(f.resolve(t, org, "ops"), "servers", "restart"))
	require.True(t, grants(f.resolve(t, org, "devops"), "pipelines", "run"))
	require.Equal(t, int64(2), permKeys(t, f.rdb))

	require.NoError(t, f.svc.SetRolePermissions(permOrgCtx(org), opsID, nil))

	require.Equal(t, int64(1), permKeys(t, f.rdb),
		"invalidating 'ops' also cleared 'devops': the pattern is a substring match over the key, "+
			"and a role name is not a substring of another role name by accident on any real install")
	require.True(t, grants(f.resolve(t, org, "devops"), "pipelines", "run"))
}

// A role set is cached under the WHOLE sorted set of names, so revoking from
// one of several roles has to clear the combined entry too.
func TestRevokingFromOneRoleClearsTheEntryForEveryRoleSetThatContainsIt(t *testing.T) {
	f := seedPerms(t, openPermPool(t), openPermRedis(t))
	org := uuid.NewString()
	editorID, _ := f.addRole(t, org, "editor", "documents", "write")
	f.addRole(t, org, "viewer", "documents", "read")

	combined := f.resolve(t, org, "editor", "viewer")
	require.True(t, grants(combined, "documents", "write"))
	require.True(t, grants(combined, "documents", "read"))

	require.NoError(t, f.svc.SetRolePermissions(permOrgCtx(org), editorID, nil))

	after := f.resolve(t, org, "editor", "viewer")
	require.False(t, grants(after, "documents", "write"),
		"a user holding editor AND viewer kept the revoked permission: the cache entry for a role SET "+
			"is a different key from the entry for the role alone")
	require.True(t, grants(after, "documents", "read"), "and the permission that was not revoked must survive")
}

func permKeys(t *testing.T, rdb *goredis.Client) int64 {
	t.Helper()
	var n int64
	iter := rdb.Scan(context.Background(), 0, "perms:*", 100).Iterator()
	for iter.Next(context.Background()) {
		n++
	}
	require.NoError(t, iter.Err())
	return n
}

// A COMMA IS NOT A SEPARATOR WHEN IT CAN ALSO BE A CHARACTER IN A NAME.
//
// The v2 key joined the sorted role names with "," and nothing validated a
// role name, so the role SET {reader, writer} and a single role literally
// NAMED "reader,writer" produced the same key. Two different permission sets,
// one cache entry, and whichever request arrived first decided what the other
// one was granted.
//
// Which direction it goes depends on who warms the cache, so this asserts the
// only thing that is always true: they are different entries.
func TestARoleNamedLikeARoleSetDoesNotShareItsCacheEntry(t *testing.T) {
	f := seedPerms(t, openPermPool(t), openPermRedis(t))
	org := uuid.NewString()

	f.addRole(t, org, "reader", "documents", "read")
	f.addRole(t, org, "writer", "documents", "write")
	// A single role whose NAME contains the separator.
	f.addRole(t, org, "reader,writer", "billing", "administer")

	// A user holding both ordinary roles warms the entry for that set.
	both := f.resolve(t, org, "reader", "writer")
	require.True(t, grants(both, "documents", "read"))
	require.True(t, grants(both, "documents", "write"))
	require.False(t, grants(both, "billing", "administer"),
		"holding reader and writer granted the permissions of a role NAMED \"reader,writer\": "+
			"the two produce the same cache key, so a role name that contains the separator is "+
			"indistinguishable from a set of roles")

	// And the single oddly-named role gets its own permissions, not theirs.
	odd := f.resolve(t, org, "reader,writer")
	require.True(t, grants(odd, "billing", "administer"))
	require.False(t, grants(odd, "documents", "read"),
		"the role named \"reader,writer\" was served the entry belonging to the SET {reader, writer}")
}
