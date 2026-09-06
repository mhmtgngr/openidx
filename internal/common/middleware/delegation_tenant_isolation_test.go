package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Tenant isolation for delegated administration, migration v152.
//
// These two cases sit in the middleware package on purpose: this is the policy
// enforcement point. PermissionResolver builds the permission set that
// RequirePermission then decides on, and an admin_delegations row is merged
// straight into it. A defect here is not a disclosure, it is a grant.
//
// Both run against the Postgres and Redis that ci.yml attaches to the unit-test
// matrix (DATABASE_URL / REDIS_URL), so they are real in CI rather than skipped
// there and green only on a developer's machine.

func delegationTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("OPENIDX_TEST_DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("no DATABASE_URL/OPENIDX_TEST_DATABASE_URL; ci.yml supplies one to this matrix shard")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Skipf("database not reachable: %v", err)
	}
	if err := migrations.NewMigrator(pool, zap.NewNop()).MigrateTo(context.Background(), -1); err != nil {
		pool.Close()
		t.Fatalf("migrate to latest: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedDelegationFixture creates two organizations, a user who belongs to the
// first, and a delegation granting that user a permission in the first
// organization. Returns (orgA, orgB, userID, permission).
func seedDelegationFixture(t *testing.T, pool *pgxpool.Pool, tag string) (string, string, string, string) {
	t.Helper()
	ctx := orgctx.WithBypassRLS(context.Background())
	suffix := fmt.Sprintf("%s-%d", tag, time.Now().UnixNano())

	var orgA, orgB string
	if err := pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1,$1) RETURNING id::text`, "dlg-a-"+suffix).Scan(&orgA); err != nil {
		t.Fatalf("seed org A: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1,$1) RETURNING id::text`, "dlg-b-"+suffix).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	var userID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (org_id, username, email, enabled)
		VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
		orgA, "dlg-u-"+suffix, "dlg-u-"+suffix+"@example.test").Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	perm := "vault:reveal"
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_delegations
		    (org_id, delegate_id, delegated_by, scope_type, scope_id, permissions, enabled)
		VALUES ($1::uuid, $2::uuid, $2::uuid, 'organization', $1::uuid, $3::jsonb, true)`,
		orgA, userID, `["`+perm+`"]`); err != nil {
		t.Fatalf("seed delegation: %v", err)
	}

	t.Cleanup(func() {
		c := orgctx.WithBypassRLS(context.Background())
		_, _ = pool.Exec(c, `DELETE FROM admin_delegations WHERE delegate_id = $1::uuid`, userID)
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id = $1::uuid`, userID)
		_, _ = pool.Exec(c, `DELETE FROM organizations WHERE id = ANY(ARRAY[$1,$2]::uuid[])`, orgA, orgB)
	})
	return orgA, orgB, userID, perm
}

// THE GRANT THAT FOLLOWED THE USER.
//
// resolveDelegations runs under a deliberate orgctx.WithBypassRLS — it has to,
// because this middleware runs before the tenant GUC is established and a
// bare-context read would return nothing and 403 every caller. The bypass means
// the belt cannot help: whatever the SQL says is the whole of the scoping. The
// SQL said `WHERE delegate_id = $1`, under a comment claiming it was "the same
// RLS reasoning" as the role_permissions read eight lines above, which is
// scoped by r.org_id. delegate_id is a user id.
func TestResolveDelegations_TenantIsolation(t *testing.T) {
	pool := delegationTestPool(t)
	orgA, orgB, userID, perm := seedDelegationFixture(t, pool, "resolve")
	ctx := orgctx.WithBypassRLS(context.Background())

	inA := resolveDelegations(ctx, pool, userID, orgA)
	if len(inA) != 1 || inA[0].Resource+":"+inA[0].Action != perm {
		t.Fatalf("the delegation is invisible in its OWN organization (%+v); the predicate must "+
			"scope the read, not empty it", inA)
	}

	inB := resolveDelegations(ctx, pool, userID, orgB)
	if len(inB) != 0 {
		t.Fatalf("a delegation granted in one organization was returned for the same user acting "+
			"in another (%+v). This read runs under a deliberate bypass, so the SQL predicate is "+
			"the only scoping there is, and it merges straight into the set RequirePermission "+
			"decides on: %q would be granted in an organization that never delegated it",
			inB, perm)
	}
}

// THE CACHE THAT SHARED ONE PERSON'S DELEGATION WITH EVERYONE.
//
// The permission cache is keyed on (org, role set) and its own comment explains
// why the org must be in the key. The delegation block then appended ITS
// caller's per-user rows to the same slice before it was cached, so for the
// next five minutes every user in that organization holding the same roles was
// served one person's delegated permissions as their own.
func TestPermissionResolver_DelegationsAreNotCachedAcrossUsers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := delegationTestPool(t)
	orgA, _, delegateID, perm := seedDelegationFixture(t, pool, "cache")

	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "redis://localhost:6379"
	}
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Skipf("bad REDIS_URL: %v", err)
	}
	rdb := redis.NewClient(opt)
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("redis not reachable: %v", err)
	}
	defer rdb.Close()

	// A role both users hold. Its own permission set is irrelevant — what
	// matters is that the two callers share a cache key.
	roles := []string{"delegation-cache-test"}
	sorted := make([]string, len(roles))
	copy(sorted, roles)
	sort.Strings(sorted)
	key := "perms:v2:" + orgA + ":" + strings.Join(sorted, ",")
	_ = rdb.Del(context.Background(), key).Err()
	t.Cleanup(func() { _ = rdb.Del(context.Background(), key).Err() })

	run := func(userID string) []PermissionEntry {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/x", nil).
			WithContext(orgctx.With(context.Background(), orgctx.Org{ID: orgA}))
		c.Set("roles", roles)
		c.Set("user_id", userID)
		PermissionResolver(pool, rdb)(c)
		raw, ok := c.Get("permissions")
		if !ok {
			return nil
		}
		perms, _ := raw.([]PermissionEntry)
		return perms
	}

	has := func(perms []PermissionEntry, want string) bool {
		for _, p := range perms {
			if p.Resource+":"+p.Action == want {
				return true
			}
		}
		return false
	}

	// The delegate goes first, so the cache is populated by a request that has
	// a delegation — the exact ordering that poisoned it.
	if got := run(delegateID); !has(got, perm) {
		t.Fatalf("the delegate did not receive their own delegated %q (%+v)", perm, got)
	}

	// A different user, same organization, same roles: a cache hit.
	const otherUser = "00000000-0000-0000-0000-0000000000c3"
	if got := run(otherUser); has(got, perm) {
		t.Fatalf("a second user with the same roles was granted %q, which was delegated to "+
			"someone else. The cache key is (org, role set), so anything user-specific written "+
			"into the cached value is handed to every user who shares it — for five minutes, "+
			"renewed on every miss", perm)
	}

	// And what IS cached must be role-derived only.
	cached, err := rdb.Get(context.Background(), key).Result()
	if err != nil {
		t.Fatalf("nothing was cached under %s: %v", key, err)
	}
	var stored []PermissionEntry
	if err := json.Unmarshal([]byte(cached), &stored); err != nil {
		t.Fatalf("bad cached payload: %v", err)
	}
	if has(stored, perm) {
		t.Fatalf("the delegated permission %q was written into the shared cache entry itself", perm)
	}
}
