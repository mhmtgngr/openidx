package oauth

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// THE BELT ON THE IDENTITY LINKS, MEASURED AS THE APPLICATION ROLE.
//
// v200 gave user_identity_links and social_account_links org_id and FORCE ROW
// LEVEL SECURITY. A superuser cannot measure that -- RLS does not apply to it
// -- so this runs only as TEST_POSTGRES_DSN, the unprivileged openidx_app role
// the rls-isolation job provides, and refuses a role that would pass by
// bypassing. The tables are built from the REGISTERED DDL (v54's CREATE TABLEs
// and v200's column, policy and belt statements), not a copy.
//
// What is pinned here that no handler test can pin:
//   - a tenant's connection sees only its own links, on both tables;
//   - a tenant cannot write a link row into another tenant (WITH CHECK), and
//     cannot re-point one through the upsert's ON CONFLICT branch;
//   - the same external account, through two different providers, links once
//     in each tenant -- the decision v200 records -- and neither tenant sees
//     the other's row.
func TestIdentityLinksBelt_TenantRowsAreInvisibleAcrossTenants(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the identity-links belt test")
	}
	ctx := context.Background()
	db, err := database.NewPostgres(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	var super bool
	require.NoError(t, db.Pool.Raw().QueryRow(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&super))
	require.False(t, super, "TEST_POSTGRES_DSN is a role RLS does not apply to; this test would pass by bypassing")

	raw := db.Pool.Raw()
	drop := `DROP TABLE IF EXISTS user_identity_links, social_account_links, identity_providers, users CASCADE`
	_, err = raw.Exec(ctx, drop)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = raw.Exec(context.Background(), drop) })
	// v54's tables reference users(id) and identity_providers(id); the shape
	// is all that is needed, and identity_providers carries org_id (v155).
	_, err = raw.Exec(ctx, `CREATE TABLE users (id UUID PRIMARY KEY, org_id UUID)`)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, `CREATE TABLE identity_providers (id UUID PRIMARY KEY, org_id UUID)`)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, registeredIdentityLinksBeltDDL(t))
	require.NoError(t, err)

	orgA, orgB := uuid.NewString(), uuid.NewString()
	tenant := func(org string) context.Context { return orgctx.With(context.Background(), orgctx.Org{ID: org}) }
	bypass := orgctx.WithBypassRLS(context.Background())

	// One provider and one user per tenant, seeded under bypass.
	provA, provB := uuid.NewString(), uuid.NewString()
	userA, userB := uuid.NewString(), uuid.NewString()
	for _, s := range []struct{ org, prov, user string }{{orgA, provA, userA}, {orgB, provB, userB}} {
		_, err = db.Pool.Exec(bypass, `INSERT INTO identity_providers (id, org_id) VALUES ($1, $2)`, s.prov, s.org)
		require.NoError(t, err)
		_, err = db.Pool.Exec(bypass, `INSERT INTO users (id, org_id) VALUES ($1, $2)`, s.user, s.org)
		require.NoError(t, err)
	}

	// THE DECISION: the same external subject links once in each tenant.
	const subject = "sub-shared-by-a-consultant"
	svc := &Service{db: db}
	for _, s := range []struct{ org, prov, user string }{{orgA, provA, userA}, {orgB, provB, userB}} {
		info := &SocialUserInfo{ID: subject, Email: "c@consultancy.example", Name: "Consultant", Provider: "corp"}
		created, err := svc.linkSocialAccountToUser(tenant(s.org), s.prov, s.user, info)
		require.NoError(t, err, "linking in tenant %s", s.org)
		require.True(t, created, "each tenant's first link is a new link")
	}

	count := func(ctx context.Context, table string) int {
		var n int
		require.NoError(t, db.Pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n))
		return n
	}
	for _, table := range []string{"user_identity_links", "social_account_links"} {
		require.Equal(t, 2, count(bypass, table), "%s: two links exist in total", table)
		require.Equal(t, 1, count(tenant(orgA), table), "%s: tenant A sees only its own", table)
		require.Equal(t, 1, count(tenant(orgB), table), "%s: tenant B sees only its own", table)
		require.Equal(t, 0, count(orgctx.With(context.Background(), orgctx.Org{ID: uuid.NewString()}), table),
			"%s: a tenant with no links sees none", table)
	}

	// The row is owned by its tenant: A's connection cannot read B's row by
	// id, cannot delete it, and cannot write a row that claims to be B's.
	var linkB string
	require.NoError(t, db.Pool.QueryRow(tenant(orgB), `SELECT id FROM user_identity_links WHERE user_id = $1`, userB).Scan(&linkB))
	var seen int
	require.NoError(t, db.Pool.QueryRow(tenant(orgA), `SELECT count(*) FROM user_identity_links WHERE id = $1`, linkB).Scan(&seen))
	require.Equal(t, 0, seen, "tenant A must not see tenant B's link by id")
	tag, err := db.Pool.Exec(tenant(orgA), `DELETE FROM user_identity_links WHERE id = $1`, linkB)
	require.NoError(t, err)
	require.EqualValues(t, 0, tag.RowsAffected(), "tenant A must not be able to delete tenant B's link")
	_, err = db.Pool.Exec(tenant(orgA),
		`INSERT INTO user_identity_links (id, org_id, user_id, provider_id, external_id) VALUES ($1, $2, $3, $4, 'forged')`,
		uuid.NewString(), orgB, userB, provB)
	require.Error(t, err, "WITH CHECK must refuse a row written into another tenant")
	require.Contains(t, err.Error(), "row-level security")

	// The upsert's ON CONFLICT branch cannot re-point another tenant's link:
	// A, holding B's provider id, cannot move B's subject onto A's user.
	err = svc.upsertIdentityLink(tenant(orgA), orgA, provB, userA,
		&SocialUserInfo{ID: subject, Email: "c@consultancy.example", Name: "Consultant", Provider: "corp"})
	require.Error(t, err, "the conflicting row is B's; A's write must be refused, not applied")
	var owner string
	require.NoError(t, db.Pool.QueryRow(tenant(orgB), `SELECT user_id FROM user_identity_links WHERE provider_id = $1 AND external_id = $2`, provB, subject).Scan(&owner))
	require.Equal(t, userB, owner, "B's link still points at B's user")

	// The same for the login-path table, whose upsert has the same branch.
	err = svc.createSocialAccountLink(tenant(orgA), orgA, provB, userA,
		&SocialUserInfo{ID: subject, Email: "c@consultancy.example", Name: "Consultant", Provider: "corp"})
	require.Error(t, err, "social_account_links: the conflicting row is B's; A's write must be refused, not applied")
	require.NoError(t, db.Pool.QueryRow(tenant(orgB), `SELECT user_id FROM social_account_links WHERE provider_id = $1 AND external_id = $2`, provB, subject).Scan(&owner))
	require.Equal(t, userB, owner, "B's login link still points at B's user")
}

// registeredIdentityLinksBeltDDL builds the two link tables from the
// migration registry: v54's CREATE TABLEs and v200's column, index, policy,
// belt and grant statements. The backfill and the foreign key to
// organizations are left out -- they need the full chain -- and are covered
// by the migration test on the SQL text.
func registeredIdentityLinksBeltDDL(t *testing.T) string {
	t.Helper()
	var v54, v200 string
	for _, m := range migrations.All() {
		switch m.Version {
		case 54:
			v54 = m.UpSQL
		case 200:
			v200 = m.UpSQL
		}
	}
	require.NotEmpty(t, v54)
	require.NotEmpty(t, v200)
	var out []string
	for _, table := range []string{"social_account_links", "user_identity_links"} {
		re := regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS ` + table + ` \(.*?\);`)
		stmt := re.FindString(v54)
		require.NotEmpty(t, stmt, "v54 no longer creates %s", table)
		out = append(out, stmt)
	}
	for _, stmt := range strings.Split(v200, ";") {
		s := strings.TrimSpace(stmt)
		switch {
		case strings.Contains(s, "ADD COLUMN IF NOT EXISTS org_id"),
			strings.HasPrefix(s, "DROP POLICY"), strings.HasPrefix(s, "CREATE POLICY"),
			strings.Contains(s, "ROW LEVEL SECURITY"), strings.HasPrefix(s, "GRANT"),
			strings.HasPrefix(s, "CREATE INDEX"):
			out = append(out, s+";")
		}
	}
	require.Greater(t, len(out), 10, "v200's belt statements were not found")
	return strings.Join(out, "\n")
}
