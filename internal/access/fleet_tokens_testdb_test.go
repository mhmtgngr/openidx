package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// FLEET TOKENS (v250): a reusable token counts its uses, stops at max_uses,
// stamps its default tags on every device it enrols, lives at most a year and
// is not counted against the hourly one-time-token quota.

func (f *enrollTokenFixture) seedFleet(t *testing.T, maxUses *int, tags []string) seededToken {
	t.Helper()
	plaintext := uuid.New().String()
	if tags == nil {
		tags = []string{}
	}
	var id string
	require.NoError(t, f.db.Pool.QueryRow(f.ctx, `
		INSERT INTO agent_enrollment_tokens (token_hash, description, expires_at, reusable, max_uses, default_tags, org_id)
		VALUES ($1, 'fleet', NOW() + INTERVAL '1 day', true, $2, $3, $4) RETURNING id`,
		sha256Hex(plaintext), maxUses, tags, redeemOrg).Scan(&id))
	return seededToken{plaintext: plaintext, id: id}
}

func TestFleetTokenCountsUsesAndStopsAtMaxUses(t *testing.T) {
	f := newEnrollTokenFixture(t)
	three := 3
	tok := f.seedFleet(t, &three, nil)
	for i := 0; i < three; i++ {
		_, err := redeemEnrollmentToken(f.ctx, f.db.Pool, tok.plaintext)
		require.NoError(t, err, "use %d of %d", i+1, three)
	}
	_, err := redeemEnrollmentToken(f.ctx, f.db.Pool, tok.plaintext)
	assert.ErrorIs(t, err, errEnrollmentTokenExhausted)
	w := agentEnroll(f.agentHandler(), tok.plaintext)
	assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "maximum number of uses")

	var uses int
	var last *time.Time
	require.NoError(t, f.db.Pool.QueryRow(f.ctx, `SELECT uses, last_used_at FROM agent_enrollment_tokens WHERE id = $1`, tok.id).Scan(&uses, &last))
	assert.Equal(t, three, uses, "a refused use was counted")
	assert.NotNil(t, last)
	assert.Nil(t, f.usedAt(t, tok.id), "a fleet token was spent")

	// No cap: counts, never refuses.
	open := f.seedFleet(t, nil, nil)
	for i := 0; i < 5; i++ {
		_, err := redeemEnrollmentToken(f.ctx, f.db.Pool, open.plaintext)
		require.NoError(t, err)
	}
	require.NoError(t, f.db.Pool.QueryRow(f.ctx, `SELECT uses FROM agent_enrollment_tokens WHERE id = $1`, open.id).Scan(&uses))
	assert.Equal(t, 5, uses)
}

func TestFleetTokenAppliesDefaultTags(t *testing.T) {
	f := newEnrollTokenFixture(t)
	tok := f.seedFleet(t, nil, []string{"finance", "ankara"})
	w := agentEnroll(f.agentHandler(), tok.plaintext)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		AgentID string `json:"agent_id"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.AgentID)

	var tags []string
	var tokenID string
	require.NoError(t, f.db.Pool.QueryRow(f.ctx,
		`SELECT tags, enrolled_with_token_id::text FROM enrolled_agents WHERE agent_id = $1`, resp.AgentID).Scan(&tags, &tokenID))
	assert.ElementsMatch(t, []string{"finance", "ankara"}, tags)
	assert.Equal(t, tok.id, tokenID)
}

func driveMint(h *AgentAPIHandler, org, body string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/agent/tokens", strings.NewReader(body)).
		WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
	c.Request.Header.Set("Content-Type", "application/json")
	h.HandleGenerateToken(c)
	return w
}

func TestMintTokenRefusesTTLOverOneYear(t *testing.T) {
	h := newTestAgentHandler()
	w := driveMint(h, redeemOrg, `{"reusable":true,"ttl_hours":8761}`)
	assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	w = driveMint(h, redeemOrg, `{"reusable":true,"ttl_hours":8760}`)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Default lifetime of a fleet token is 90 days.
	w = driveMint(h, redeemOrg, `{"reusable":true}`)
	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.WithinDuration(t, time.Now().Add(90*24*time.Hour), resp.ExpiresAt, time.Minute)

	// And the database refuses a row that outlives a year, whatever wrote it.
	f := newEnrollTokenFixture(t)
	_, err := f.db.Pool.Exec(f.ctx, `
		INSERT INTO agent_enrollment_tokens (token_hash, expires_at, reusable, org_id)
		VALUES ($1, NOW() + INTERVAL '400 days', true, $2)`, sha256Hex(uuid.New().String()), redeemOrg)
	assert.Error(t, err, "v250's CHECK let a 400-day token in")
}

func TestFleetTokenMintIsQuotaExempt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()
	require.NoError(t, migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1))

	var org string
	require.NoError(t, db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('fleet-quota','fleet-quota-`+uuid.New().String()[:8]+`') RETURNING id::text`).Scan(&org))
	const quota = 2
	h := NewAgentAPIHandler(zap.NewNop(), db, nil, &config.Config{Environment: "development", AgentEnrollmentQuotaPerHour: quota})

	for i := 0; i < quota; i++ {
		require.Equal(t, http.StatusOK, driveMint(h, org, `{"description":"one-time"}`).Code)
	}
	// Positive control: the quota is spent for one-time tokens.
	require.Equal(t, http.StatusTooManyRequests, driveMint(h, org, `{"description":"one-time"}`).Code)

	// A fleet token still mints, with its name, cap and tags.
	w := driveMint(h, org, `{"reusable":true,"name":"Intune pilot","max_uses":50,"default_tags":["Pilot"," intune "],"ttl_hours":720}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var minted struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &minted))
	var name string
	var maxUses int
	var tags []string
	require.NoError(t, db.Pool.QueryRow(ctx,
		`SELECT name, max_uses, default_tags FROM agent_enrollment_tokens WHERE id = $1`, minted.ID).Scan(&name, &maxUses, &tags))
	assert.Equal(t, "Intune pilot", name)
	assert.Equal(t, 50, maxUses)
	assert.Equal(t, []string{"pilot", "intune"}, tags)
}
