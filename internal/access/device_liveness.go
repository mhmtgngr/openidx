package access

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// A DEVICE THAT STOPS REPORTING STOPS BEING TRUSTED.
//
// DeviceAttributes already refuses #device-trusted to an agent that has not
// reported within AGENT_LIVENESS_TIMEOUT, but attributes are only rewritten
// when something syncs the identity: a report (which a silent agent never
// sends) or the poller. sweepSilentDevices finds the devices whose identity
// still carries the attribute although their agent has gone quiet, takes it
// away and cuts what they were reaching.
//
// The status stays 'active'. The next compliant report syncs the identity
// again and the attribute comes back by itself; nobody has to re-approve a
// laptop that was asleep.
//
// The claim and the work are one statement, as in enforceExpiredGracePeriods:
// the UPDATE removes the attribute from the recorded row and returns the agent,
// so a second replica running the same sweep finds the attribute gone and
// returns nothing. Only the replica that claimed a device announces it.

// sweepSilentDevices returns how many devices lost trust in this pass.
func (h *AgentAPIHandler) sweepSilentDevices(ctx context.Context) int {
	cfg := h.cfg()
	if h.db == nil || h.db.Pool == nil || cfg == nil {
		return 0
	}
	timeout := cfg.AgentLiveness()
	if timeout <= 0 {
		return 0
	}
	rctx := orgctx.WithBypassRLS(ctx)
	//orgscope:ignore install-wide liveness sweep over every tenant's devices; the RETURNING rows carry their own agent and the sync that follows is per agent
	rows, err := h.db.Pool.Query(rctx, `
		UPDATE ziti_identities zi
		   SET attributes = zi.attributes - 'device-trusted', updated_at = NOW()
		  FROM enrolled_agents ea
		 WHERE zi.agent_id = ea.agent_id
		   AND zi.attributes ? 'device-trusted'
		   AND (ea.last_report_at IS NULL OR ea.last_report_at < NOW() - $1::interval)
		RETURNING ea.agent_id`, timeout.String())
	if err != nil {
		h.logger.Warn("liveness sweep: claim query", zap.Error(err))
		return 0
	}
	var silent []string
	for rows.Next() {
		var agentID string
		if rows.Scan(&agentID) == nil {
			silent = append(silent, agentID)
		}
	}
	rows.Close()
	for _, agentID := range silent {
		// The sync reads last_report_at and writes the controller the same
		// attributes without #device-trusted; severing ends what the device
		// had already opened. With the controller unreachable the recorded
		// row is already right, and the poller re-syncs the identity from it.
		if h.zm != nil {
			if err := h.zm.SyncDeviceIdentity(rctx, agentID); err != nil {
				h.logger.Warn("liveness sweep: device identity sync", zap.String("agent_id", agentID), zap.Error(err))
			}
			h.zm.SeverDeviceCircuits(rctx, agentID)
		}
		detail := "no report within " + timeout.String()
		h.logger.Warn("Device no longer trusted: agent stopped reporting",
			zap.String("agent_id", agentID), zap.Duration("timeout", timeout))
		h.logAuditEvent("agent.stale", agentID, "enforced", detail)
		h.logAuditEventToDB(ctx, "agent.stale", agentID, "enforced", detail)
	}
	return len(silent)
}

// silentWindow bounds the devices the silent gauge looks at: an agent that
// last reported more than a day ago is a laptop that is off, not news.
const silentWindow = 24 * time.Hour

var registerSilentGauges sync.Once

// RegisterAgentSilentGauges exposes two counts over active devices that
// reported in during the last 24 hours: openidx_agents_recent, all of them,
// and openidx_agents_silent, those that have not reported within the
// liveness timeout and so are no longer trusted. Laptops closing for the
// night move the second; most of the fleet falling silent at once means the
// agents cannot reach the server, and OpenIDXAgentsMostlySilent watches that
// ratio. Each count is read at most every 30 seconds. Registered once per
// process; with the liveness rule off nothing is registered.
func RegisterAgentSilentGauges(db *database.PostgresDB, timeout time.Duration, logger *zap.Logger) {
	if db == nil || db.Pool == nil || timeout <= 0 {
		return
	}
	registerSilentGauges.Do(func() {
		var mu sync.Mutex
		var recent, silent float64
		var at time.Time
		read := func() {
			if time.Since(at) < 30*time.Second {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var r, s int
			err := db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
				//orgscope:ignore install-wide metric: two counts across every organization's devices, no row leaves the query
				`
				SELECT count(*),
				       count(*) FILTER (WHERE last_report_at < NOW() - $2::interval)
				  FROM enrolled_agents
				 WHERE status = 'active' AND last_report_at > NOW() - $1::interval`,
				silentWindow.String(), timeout.String()).Scan(&r, &s)
			if err != nil {
				logger.Debug("agent silent gauges: count failed", zap.Error(err))
				return
			}
			recent, silent, at = float64(r), float64(s), time.Now()
		}
		promauto.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: "openidx",
			Name:      "agents_recent",
			Help:      "Active devices whose agent reported in during the last 24 hours.",
		}, func() float64 {
			mu.Lock()
			defer mu.Unlock()
			read()
			return recent
		})
		promauto.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: "openidx",
			Name:      "agents_silent",
			Help:      "Active devices that reported in during the last 24 hours but not within the liveness timeout (no longer trusted).",
		}, func() float64 {
			mu.Lock()
			defer mu.Unlock()
			read()
			return silent
		})
	})
}
