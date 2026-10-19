package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/testsupport"
)

const (
	gateOrg       = "00000000-0000-0000-0000-0000000000a1"
	gateDeviceApp = "00000000-0000-0000-0000-0000000000b1"
	gatePlainApp  = "00000000-0000-0000-0000-0000000000b2"
	gateLiveUser  = "00000000-0000-0000-0000-0000000000c1"
	gateIdleUser  = "00000000-0000-0000-0000-0000000000c2"
)

// SSO_DEVICE_GATE: a sign-in to an application that requires a trusted device
// needs a live, compliant agent behind the person. Observe records and lets
// it through; enforce refuses with 403; an application without the condition
// and a person with a live device are never touched.
func TestSSODeviceGate(t *testing.T) {
	pool := ssoGateScratch(t)
	s := &Service{db: &database.PostgresDB{Pool: database.NewScopedPool(pool)}, logger: zap.NewNop(),
		config: &config.Config{AgentLivenessTimeout: "10m"}}

	try := func(user, app string) (bool, int) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
		ok := s.ssoDeviceGateAllows(c, user, "client-1", app, gateOrg)
		return ok, w.Code
	}

	s.config.SSODeviceGate = "off"
	ok, _ := try(gateIdleUser, gateDeviceApp)
	assert.True(t, ok, "off must not check anything")
	assert.Equal(t, 0, unifiedRows(t, pool, ""))

	s.config.SSODeviceGate = "observe"
	ok, _ = try(gateIdleUser, gateDeviceApp)
	assert.True(t, ok, "observe must let the sign-in through")
	assert.Equal(t, 1, unifiedRows(t, pool, "access.device.would_deny"), "observe must record what enforce would refuse")

	s.config.SSODeviceGate = "enforce"
	ok, code := try(gateIdleUser, gateDeviceApp)
	assert.False(t, ok, "a person whose only device went silent was let in")
	assert.Equal(t, http.StatusForbidden, code)
	assert.Equal(t, 1, unifiedRows(t, pool, "access.device.denied"))

	ok, _ = try(gateLiveUser, gateDeviceApp)
	assert.True(t, ok, "a person with a live, compliant device was refused")
	ok, _ = try(gateIdleUser, gatePlainApp)
	assert.True(t, ok, "an application that does not require a trusted device was gated")

	// With the liveness rule off, a compliant device counts however old its report.
	s.config.AgentLivenessTimeout = "0"
	ok, _ = try(gateIdleUser, gateDeviceApp)
	assert.True(t, ok)
}

func ssoGateScratch(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn, ok := testsupport.ScratchDatabase(t)
	if !ok {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the SSO device gate test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	_, err = pool.Exec(context.Background(), `
		CREATE TABLE applications (id uuid primary key, name text, kind text, enabled boolean, org_id uuid);
		CREATE TABLE resource_conditions (application_id uuid primary key, require_device_trust boolean,
			max_risk_score int, allowed_countries text[], require_step_up boolean, legacy_roles text[]);
		CREATE TABLE enrolled_agents (agent_id text primary key, org_id uuid, enrolled_by_user_id uuid,
			status text, compliance_status text, last_report_at timestamptz);
		CREATE TABLE unified_audit_events (id uuid primary key, org_id uuid, source text, event_type text,
			route_id text, user_id uuid, actor_ip text, details jsonb, created_at timestamptz);`)
	require.NoError(t, err)
	for _, q := range []string{
		`INSERT INTO applications VALUES ('` + gateDeviceApp + `', 'Payroll', 'web', true, '` + gateOrg + `')`,
		`INSERT INTO applications VALUES ('` + gatePlainApp + `', 'Wiki', 'web', true, '` + gateOrg + `')`,
		`INSERT INTO resource_conditions VALUES ('` + gateDeviceApp + `', true, NULL, '{}', false, '{}')`,
		`INSERT INTO enrolled_agents VALUES ('a-live', '` + gateOrg + `', '` + gateLiveUser + `', 'active', 'compliant', NOW() - interval '1 minute')`,
		`INSERT INTO enrolled_agents VALUES ('a-idle', '` + gateOrg + `', '` + gateIdleUser + `', 'active', 'compliant', NOW() - interval '2 hours')`,
	} {
		_, err = pool.Exec(context.Background(), q)
		require.NoError(t, err, q)
	}
	return pool
}

func unifiedRows(t *testing.T, pool *pgxpool.Pool, eventType string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM unified_audit_events WHERE $1 = '' OR event_type = $1`, eventType).Scan(&n))
	return n
}
