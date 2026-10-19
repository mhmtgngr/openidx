package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// PAM_DEVICE_GATE: an internal user's privileged launch needs a live,
// compliant agent; a vendor (external) is never held to it.
func TestPAMDeviceGate(t *testing.T) {
	const org = "00000000-0000-0000-0000-0000000000a1"
	const live = "00000000-0000-0000-0000-0000000000c1"
	const idle = "00000000-0000-0000-0000-0000000000c2"
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	pool := db.Pool.Raw()
	_, err := pool.Exec(context.Background(), `
		CREATE TABLE enrolled_agents (agent_id text primary key, org_id uuid, enrolled_by_user_id uuid,
			status text, compliance_status text, last_report_at timestamptz);
		INSERT INTO enrolled_agents VALUES ('a-live', '`+org+`', '`+live+`', 'active', 'compliant', NOW() - interval '1 minute');
		INSERT INTO enrolled_agents VALUES ('a-idle', '`+org+`', '`+idle+`', 'active', 'compliant', NOW() - interval '3 hours');`)
	require.NoError(t, err)

	s := &Service{db: &database.PostgresDB{Pool: database.NewScopedPool(pool)}, logger: zap.NewNop(),
		config: &config.Config{AgentLivenessTimeout: "10m"}}
	try := func(caller pamCaller) (bool, int) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/access/pam/entries/e1/connect", nil)
		refused := s.refuseNoLiveDevice(c, org, caller, "e1")
		return refused, w.Code
	}

	s.config.PAMDeviceGate = "observe"
	refused, _ := try(pamCaller{UserID: idle})
	assert.False(t, refused, "observe must not refuse")

	s.config.PAMDeviceGate = "enforce"
	refused, code := try(pamCaller{UserID: idle})
	assert.True(t, refused, "a launch with no live device went ahead under enforce")
	assert.Equal(t, http.StatusForbidden, code)

	refused, _ = try(pamCaller{UserID: live})
	assert.False(t, refused, "a person with a live device was refused")
	refused, _ = try(pamCaller{UserID: idle, External: true})
	assert.False(t, refused, "a vendor works with nothing installed and must not be held to the gate")

	s.config.PAMDeviceGate = "off"
	refused, _ = try(pamCaller{UserID: idle})
	assert.False(t, refused)
}
