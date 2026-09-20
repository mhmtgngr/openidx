package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// THE QUOTA, MEASURED AT THE THREE DOORS.
//
// Against the full migrated schema: a tenant mints up to the quota, the next
// request at each of the three mint sites is a 429 carrying a Retry-After
// that says when the oldest token in the window ages out, a second tenant is
// not affected by the first's spending, and a quota of 0 mints without limit.
func TestEnrollmentQuota_PerTenantAcrossEveryMintSite(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	require.NoError(t, migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1))

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	var orgB string
	require.NoError(t, db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('quota-b','quota-b') RETURNING id::text`).Scan(&orgB))
	// A user in each tenant for the session mint site's created_by_user_id.
	seedUser := func(org, name string) string {
		var id string
		require.NoError(t, db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`, org, name, name+"@example.test").Scan(&id))
		return id
	}
	userA, userB := seedUser(orgA, "quota-a"), seedUser(orgB, "quota-b")

	const quota = 3
	h := NewAgentAPIHandler(zap.NewNop(), db, nil, &config.Config{Environment: "development", AgentEnrollmentQuotaPerHour: quota})

	drive := func(handler gin.HandlerFunc, org, user, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)).
			WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Set("user_id", user)
		c.Set("org_id", org) // HandleCreateEnrollSession reads the tenant from here
		c.Set("amr", []string{"pwd"})
		handler(c)
		return w
	}
	count := func(org string) int {
		var n int
		require.NoError(t, db.Pool.QueryRow(ctx, `SELECT count(*) FROM agent_enrollment_tokens WHERE org_id = $1`, org).Scan(&n))
		return n
	}

	// Tenant A spends its quota at the admin endpoint.
	for i := 0; i < quota; i++ {
		w := drive(h.HandleGenerateToken, orgA, userA, `{"description":"t"}`)
		require.Equal(t, http.StatusOK, w.Code, "mint %d of %d: %s", i+1, quota, w.Body.String())
	}
	require.Equal(t, quota, count(orgA))

	// The (N+1)th is refused at EVERY door, with a Retry-After, and mints nothing.
	for name, handler := range map[string]gin.HandlerFunc{
		"HandleGenerateToken":       h.HandleGenerateToken,
		"HandleGenerateQR":          h.HandleGenerateQR,
		"HandleCreateEnrollSession": h.HandleCreateEnrollSession,
	} {
		w := drive(handler, orgA, userA, `{}`)
		require.Equal(t, http.StatusTooManyRequests, w.Code, "%s over quota: %s", name, w.Body.String())
		ra, err := strconv.Atoi(w.Header().Get("Retry-After"))
		require.NoError(t, err, "%s: Retry-After must be an integer number of seconds", name)
		require.Greater(t, ra, 0)
		require.LessOrEqual(t, ra, 3600, "%s: the window is an hour; the wait cannot exceed it", name)
		var body map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		require.Equal(t, "enrollment_quota_exceeded", body["error"])
	}
	require.Equal(t, quota, count(orgA), "a refused request must not mint")

	// The quota is the TENANT's: B has spent nothing and mints freely.
	w := drive(h.HandleGenerateQR, orgB, userB, `{}`)
	require.Equal(t, http.StatusOK, w.Code, "tenant B blocked by tenant A's spending: %s", w.Body.String())
	w = drive(h.HandleCreateEnrollSession, orgB, userB, `{}`)
	require.Equal(t, http.StatusOK, w.Code, "%s", w.Body.String())
	require.Equal(t, 2, count(orgB))

	// Tokens outside the window do not count: age A's tokens by more than an
	// hour and it may mint again.
	_, err := db.Pool.Exec(orgctx.WithBypassRLS(ctx), `UPDATE agent_enrollment_tokens SET created_at = NOW() - interval '61 minutes' WHERE org_id = $1`, orgA)
	require.NoError(t, err)
	w = drive(h.HandleGenerateToken, orgA, userA, `{}`)
	require.Equal(t, http.StatusOK, w.Code, "tokens older than the window still counted: %s", w.Body.String())

	// Quota 0 is OFF: the same tenant mints past any number.
	off := NewAgentAPIHandler(zap.NewNop(), db, nil, &config.Config{Environment: "development", AgentEnrollmentQuotaPerHour: 0})
	for i := 0; i < quota+2; i++ {
		w := drive(off.HandleGenerateToken, orgB, userB, `{}`)
		require.Equal(t, http.StatusOK, w.Code, "quota 0 must not limit: %s", w.Body.String())
	}
}
