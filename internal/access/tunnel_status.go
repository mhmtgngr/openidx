package access

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// THE DEVICE'S TUNNEL, AS ITS AGENT LAST SAW IT.
//
// The VPN replacement runs the OpenZiti tunneler beside the agent. The agent
// adds what it knows of the tunneler to its /agent/report: whether it is up,
// its version, when it last saw it, the services it carried and how many
// dials failed since the previous report. The server keeps the last report on
// enrolled_agents (tunnel_status, and tunnel_last_seen: the server's clock at
// the last report that said "up", never the device's), shows it on the
// Devices page, counts the dial failures for Prometheus, and exposes how many
// devices are reporting in with their tunnel down, for the alert in
// deployments/monitoring/alerts.yml.

// agentTunnelService is one service the tunneler reported.
type agentTunnelService struct {
	Name         string `json:"name"`
	Status       string `json:"status,omitempty"`
	DialFailures int    `json:"dial_failures,omitempty"`
}

// agentTunnelStatus is the optional tunnel_status block of an agent report.
type agentTunnelStatus struct {
	State    string               `json:"state"`
	Version  string               `json:"version,omitempty"`
	LastSeen string               `json:"last_seen,omitempty"`
	Services []agentTunnelService `json:"services,omitempty"`
	// DialFailures is the number of failed dials since the previous report,
	// beside the per-service counts (an agent may report either).
	DialFailures int `json:"dial_failures,omitempty"`
}

// tunnelStates is the vocabulary of State; anything else is stored as
// "unknown" so the console and the alert never see free text.
var tunnelStates = map[string]bool{"up": true, "down": true, "starting": true, "stopped": true, "not_installed": true, "unknown": true}

const (
	maxTunnelServices      = 500
	maxTunnelFieldLen      = 128
	maxTunnelDialsPerCheck = 100000
)

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// normalize bounds what a device can make the server store: a known state,
// short strings, at most maxTunnelServices services, non-negative counts.
// It returns the dial failures to count.
func (t *agentTunnelStatus) normalize() int {
	t.State = strings.ToLower(strings.TrimSpace(t.State))
	if !tunnelStates[t.State] {
		t.State = "unknown"
	}
	t.Version = clip(t.Version, maxTunnelFieldLen)
	if t.LastSeen != "" {
		if ts, err := time.Parse(time.RFC3339, t.LastSeen); err == nil {
			t.LastSeen = ts.UTC().Format(time.RFC3339)
		} else {
			t.LastSeen = ""
		}
	}
	if len(t.Services) > maxTunnelServices {
		t.Services = t.Services[:maxTunnelServices]
	}
	failures := 0
	if t.DialFailures > 0 {
		failures += t.DialFailures
	} else {
		t.DialFailures = 0
	}
	for i := range t.Services {
		s := &t.Services[i]
		s.Name = clip(s.Name, maxTunnelFieldLen)
		s.Status = clip(s.Status, 32)
		if s.DialFailures < 0 {
			s.DialFailures = 0
		}
		failures += s.DialFailures
	}
	if failures > maxTunnelDialsPerCheck {
		failures = maxTunnelDialsPerCheck
	}
	return failures
}

// TunnelDialFailuresTotal counts the tunneler dial failures agents report.
var TunnelDialFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: "openidx",
	Name:      "tunnel_dial_failures_total",
	Help:      "Dial failures reported by device tunnelers in /agent/report (failures since each device's previous report, summed).",
})

// recordTunnelStatus stores the agent's tunnel status and counts its dial
// failures. Best-effort: a failure is logged and the report still succeeds.
func (h *AgentAPIHandler) recordTunnelStatus(ctx context.Context, agentID string, t *agentTunnelStatus) {
	if t == nil {
		return
	}
	failures := t.normalize()
	if failures > 0 {
		TunnelDialFailuresTotal.Add(float64(failures))
	}
	if h.db == nil || h.db.Pool == nil {
		return
	}
	raw, _ := json.Marshal(t)
	if _, err := h.db.Pool.Exec(ctx, `
		UPDATE enrolled_agents
		   SET tunnel_status = $1::jsonb,
		       tunnel_last_seen = CASE WHEN $2 THEN NOW() ELSE tunnel_last_seen END
		 WHERE agent_id = $3 AND org_id = $4`,
		string(raw), t.State == "up", agentID, orgIDFrom(ctx)); err != nil {
		h.logger.Warn("failed to store tunnel status", logsafe.String("agent_id", agentID), zap.Error(err))
	}
}

// tunnelDownWindow is how long a tunnel may go unseen while its agent is
// still reporting before the device counts as "tunnel down".
const tunnelDownWindow = 15 * time.Minute

var registerTunnelGauge sync.Once

// RegisterTunnelDownGauge exposes openidx_tunnel_agents_down: the number of
// active devices whose agent reported in during the last 15 minutes while
// their tunnel was not up, or not seen up for 15 minutes. A device that is
// switched off reports nothing and is not counted. The count is read at most
// every 30 seconds. Registered once per process.
func RegisterTunnelDownGauge(db *database.PostgresDB, logger *zap.Logger) {
	if db == nil || db.Pool == nil {
		return
	}
	registerTunnelGauge.Do(func() {
		var mu sync.Mutex
		var last float64
		var at time.Time
		promauto.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: "openidx",
			Name:      "tunnel_agents_down",
			Help:      "Active devices whose agent is reporting in but whose tunneler is not up (or not seen up for 15 minutes).",
		}, func() float64 {
			mu.Lock()
			defer mu.Unlock()
			if time.Since(at) < 30*time.Second {
				return last
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var n int
			err := db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
				//orgscope:ignore install-wide metric: one count across every organization's devices, no row leaves the query
				`
				SELECT count(*) FROM enrolled_agents
				 WHERE status = 'active' AND tunnel_status IS NOT NULL
				   AND last_seen_at > NOW() - $1::interval
				   AND (tunnel_status->>'state' <> 'up'
				        OR tunnel_last_seen IS NULL OR tunnel_last_seen < NOW() - $1::interval)`,
				tunnelDownWindow.String()).Scan(&n)
			if err != nil {
				logger.Debug("tunnel down gauge: count failed", zap.Error(err))
				return last
			}
			last, at = float64(n), time.Now()
			return last
		})
	})
}
