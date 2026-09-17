package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// THE BELT ON THE FLEET, MEASURED AS THE APPLICATION ROLE.
//
// v197 made the three fleet tables per-tenant and put FORCE ROW LEVEL SECURITY
// on them. A superuser cannot measure that -- RLS does not apply to it -- so
// this runs only as TEST_POSTGRES_DSN, the unprivileged openidx_app role the
// rls-isolation job provides, and refuses a role that would pass by bypassing.
// The tables are built from the REGISTERED DDL (v43's CREATE TABLEs, v86, and
// v197's column, policy and belt statements), not a copy; the foreign keys and
// backfill of v197 need organizations and users and are measured by the fleet
// tenant isolation test against the full chain.
//
// Three things are pinned here that no handler test can pin:
//   - a tenant's connection sees only its own devices, tokens and posture, and
//     cannot write a row into another tenant (WITH CHECK);
//   - the two pre-tenant reads -- redeeming a token, verifying an agent's
//     credential -- still work with NO tenant on the context, because they opt
//     out explicitly; drop the bypass and the public enrolment door is shut for
//     every tenant at once;
//   - after those two reads, the tenant they hand back is what everything else
//     is scoped by: the agent's report lands in its own tenant.
func TestFleetBelt_TenantRowsAreInvisibleAcrossTenantsAndThePublicDoorsStillOpen(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the fleet belt test")
	}
	ctx := context.Background()
	db, err := database.NewPostgres(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	var super bool
	require.NoError(t, db.Pool.Raw().QueryRow(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&super))
	require.False(t, super, "TEST_POSTGRES_DSN is a role RLS does not apply to; this test would pass by bypassing")

	raw := db.Pool.Raw()
	drop := `DROP TABLE IF EXISTS agent_posture_results, enrolled_agents, agent_enrollment_tokens, users CASCADE`
	_, err = raw.Exec(ctx, drop)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = raw.Exec(context.Background(), drop) })
	// v43's enrolled_agents references users(id); the shape is all that is needed.
	_, err = raw.Exec(ctx, `CREATE TABLE users (id UUID PRIMARY KEY, org_id UUID)`)
	require.NoError(t, err)
	_, err = raw.Exec(ctx, registeredFleetBeltDDL(t))
	require.NoError(t, err)

	orgA, orgB := uuid.NewString(), uuid.NewString()
	tenant := func(org string) context.Context { return orgctx.With(context.Background(), orgctx.Org{ID: org}) }
	bypass := orgctx.WithBypassRLS(context.Background())

	// Seed under bypass: a token, a device and a posture row per tenant.
	tokA, tokB := uuid.NewString(), uuid.NewString()
	for _, s := range []struct{ org, tok, agent string }{{orgA, tokA, "agent-a"}, {orgB, tokB, "agent-b"}} {
		_, err = db.Pool.Exec(bypass, `INSERT INTO agent_enrollment_tokens (token_hash, expires_at, org_id) VALUES ($1, NOW() + interval '1 hour', $2)`, sha256Hex(s.tok), s.org)
		require.NoError(t, err)
		_, err = db.Pool.Exec(bypass, `INSERT INTO enrolled_agents (agent_id, device_id, auth_token_hash, status, org_id) VALUES ($1, $1, $2, 'active', $3)`, s.agent, sha256Hex("secret-"+s.agent), s.org)
		require.NoError(t, err)
		_, err = db.Pool.Exec(bypass, `INSERT INTO agent_posture_results (agent_id, check_type, status, severity, org_id) VALUES ($1, 'disk', 'pass', 'low', $2)`, s.agent, s.org)
		require.NoError(t, err)
	}

	count := func(ctx context.Context, table string) int {
		var n int
		require.NoError(t, db.Pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n))
		return n
	}
	t.Run("a tenant sees only its own fleet", func(t *testing.T) {
		for _, table := range []string{"enrolled_agents", "agent_enrollment_tokens", "agent_posture_results"} {
			assert.Equal(t, 1, count(tenant(orgA), table), "%s as tenant A", table)
			assert.Equal(t, 1, count(tenant(orgB), table), "%s as tenant B", table)
			assert.Equal(t, 2, count(bypass, table), "%s under bypass", table)
		}
		var id string
		err := db.Pool.QueryRow(tenant(orgA), `SELECT agent_id FROM enrolled_agents WHERE agent_id = 'agent-b'`).Scan(&id)
		assert.Error(t, err, "tenant A read tenant B's device by its id")
	})

	t.Run("a tenant cannot write a row into another tenant", func(t *testing.T) {
		_, err := db.Pool.Exec(tenant(orgA), `INSERT INTO enrolled_agents (agent_id, device_id, status, org_id) VALUES ('smuggled', 'smuggled', 'active', $1)`, orgB)
		assert.Error(t, err, "tenant A wrote a device into tenant B")
		tag, err := db.Pool.Exec(tenant(orgA), `UPDATE enrolled_agents SET status = 'revoked' WHERE agent_id = 'agent-b'`)
		require.NoError(t, err)
		assert.EqualValues(t, 0, tag.RowsAffected(), "tenant A revoked tenant B's device")
	})

	t.Run("the public doors still open with no tenant on the context", func(t *testing.T) {
		// Redeeming a token: no JWT, no tenant. The bypass inside the redeemer
		// is what finds the row; the tenant comes back out of it.
		got, err := redeemEnrollmentToken(context.Background(), db.Pool, tokB)
		require.NoError(t, err, "the public enrolment door is shut: the redeemer could not see the token without a tenant")
		assert.Equal(t, orgB, got.OrgID)
		// Verifying an agent's credential: same shape.
		org, ok := verifyEnrolledAgent(context.Background(), db, "agent-a", "secret-agent-a")
		require.True(t, ok, "the agent could not authenticate without a tenant on the context")
		assert.Equal(t, orgA, org)
		_, ok = verifyEnrolledAgent(context.Background(), db, "agent-a", "wrong")
		assert.False(t, ok, "a wrong credential authenticated")
	})

	t.Run("an agent's report lands in its own tenant and nowhere else", func(t *testing.T) {
		h := &AgentAPIHandler{logger: zap.NewNop(), db: db, conf: &config.Config{Environment: "production"}}
		w := postAgentReport(h, "agent-a", "secret-agent-a", `{"results":[{"check_type":"firewall","result":{"status":"pass","score":1},"severity":"low"}]}`)
		require.Equal(t, 202, w.Code, w.Body.String())
		var n int
		require.NoError(t, db.Pool.QueryRow(tenant(orgA), `SELECT count(*) FROM agent_posture_results WHERE agent_id = 'agent-a' AND check_type = 'firewall'`).Scan(&n))
		assert.Equal(t, 1, n, "the report did not land in the agent's tenant")
		require.NoError(t, db.Pool.QueryRow(tenant(orgB), `SELECT count(*) FROM agent_posture_results WHERE check_type = 'firewall'`).Scan(&n))
		assert.Equal(t, 0, n, "the report is visible to another tenant")
		var org string
		require.NoError(t, db.Pool.QueryRow(bypass, `SELECT org_id::text FROM agent_posture_results WHERE check_type = 'firewall'`).Scan(&org))
		assert.Equal(t, orgA, org)
	})
}

// registeredFleetBeltDDL is the three fleet tables as the migrations register
// ships them: v43's CREATE TABLEs, v86, v93, and from v197 the tenant
// columns, the policies, the belt and the grants. v197's backfill, NOT NULL and
// foreign keys are left out here -- they need organizations and users -- and
// are measured against the full chain in the fleet tenant isolation test.
func registeredFleetBeltDDL(t *testing.T) string {
	t.Helper()
	var v43, v86, v93, v197 string
	for _, m := range migrations.All() {
		switch m.Version {
		case 43:
			v43 = m.UpSQL
		case 86:
			v86 = m.UpSQL
		case 93:
			v93 = m.UpSQL // device_fingerprint, whose key v197 makes per-tenant
		case 197:
			v197 = m.UpSQL
		}
	}
	require.NotEmpty(t, v43)
	require.NotEmpty(t, v86)
	require.NotEmpty(t, v93)
	require.NotEmpty(t, v197)
	var out []string
	for _, table := range []string{"enrolled_agents", "agent_posture_results", "agent_enrollment_tokens"} {
		re := regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS ` + table + ` \(.*?\);`)
		stmt := re.FindString(v43)
		require.NotEmpty(t, stmt, "v43 no longer creates %s", table)
		out = append(out, stmt)
	}
	out = append(out, v86, v93)
	for _, stmt := range strings.Split(v197, ";") {
		s := strings.TrimSpace(stmt)
		switch {
		case strings.Contains(s, "ADD COLUMN IF NOT EXISTS org_id"),
			strings.HasPrefix(s, "DROP POLICY"), strings.HasPrefix(s, "CREATE POLICY"),
			strings.Contains(s, "ROW LEVEL SECURITY"), strings.HasPrefix(s, "GRANT"),
			strings.HasPrefix(s, "CREATE INDEX"), strings.HasPrefix(s, "DROP INDEX"),
			strings.HasPrefix(s, "CREATE UNIQUE INDEX"):
			out = append(out, s+";")
		}
	}
	require.Greater(t, len(out), 10, "v197's belt statements were not found")
	return strings.Join(out, "\n")
}

// postAgentReport drives POST /agent/report with the agent's credential.
func postAgentReport(h *AgentAPIHandler, agentID, token, body string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/agent/report", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.Header.Set("X-Agent-ID", agentID)
	c.Request.Header.Set("X-Auth-Token", token)
	h.HandleReport(c)
	return w
}
