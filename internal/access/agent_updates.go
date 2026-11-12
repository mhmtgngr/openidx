package access

// Agent version telemetry and update rings (Faz B8.5, v253).
//
// Every report carries the agent's build version and, after an update
// attempt, its outcome; both land on the agent's row so the console shows
// what the fleet runs and where an update failed. GET /agent/config answers
// with an update block that tells the device which feed to read, which
// version to aim for, and whether it may move at all:
//
//	paused            the organization holds the fleet, or this device is
//	                  outside the rollout percentage.
//	target_version    the pin, when one is set; empty means the feed's latest.
//	allow_downgrade   true only with a pin: a device on a newer build goes
//	                  back to the pinned one.
//
// The rollout gate is fnv32a(agent_id) % 100 < percent, so a device's place
// in the ring never changes between checks and raising the percentage only
// ever adds devices.

import (
	"context"
	"encoding/json"
	"hash/fnv"
	"os"
	"regexp"
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

const (
	updateChannelStable = "stable"
	updateChannelBeta   = "beta"
)

// defaultChannelManifest is the release feed per channel: where
// windows-client-build.yml publishes (github.com/<this repo>). An installation
// that mirrors releases overrides them with AGENT_UPDATE_MANIFEST_STABLE and
// AGENT_UPDATE_MANIFEST_BETA. Either is only a fallback: when the box mirrors
// a channel (agent_mirror.go) /agent/config names the box instead.
var defaultChannelManifest = map[string]string{
	updateChannelStable: "https://github.com/mhmtgngr/openidx/releases/download/agent-latest/latest.json",
	updateChannelBeta:   "https://github.com/mhmtgngr/openidx/releases/download/agent-beta/latest.json",
}

func channelManifestURL(channel string) string {
	env := "AGENT_UPDATE_MANIFEST_STABLE"
	if channel == updateChannelBeta {
		env = "AGENT_UPDATE_MANIFEST_BETA"
	}
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		return v
	}
	return defaultChannelManifest[channel]
}

// agentVersionPattern bounds what a device may write as its version.
var agentVersionPattern = regexp.MustCompile(`^v?[0-9A-Za-z.+\-]{1,63}$`)

// agentUpdateSettings is the update half of org_agent_settings.
type agentUpdateSettings struct {
	Channel        string `json:"update_channel"`
	PinVersion     string `json:"update_pin_version"`
	RolloutPercent int    `json:"update_rollout_percent"`
	Paused         bool   `json:"update_paused"`
}

func defaultAgentUpdateSettings() agentUpdateSettings {
	return agentUpdateSettings{Channel: updateChannelStable, RolloutPercent: 100}
}

// agentUpdateBlock is the update object in /agent/config.
type agentUpdateBlock struct {
	ManifestURL    string `json:"manifest_url"`
	TargetVersion  string `json:"target_version,omitempty"`
	Channel        string `json:"channel"`
	Paused         bool   `json:"paused"`
	AllowDowngrade bool   `json:"allow_downgrade"`
}

// agentUpdateResult is what a device reports after an update attempt.
type agentUpdateResult struct {
	State   string `json:"state"`
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
	At      string `json:"at,omitempty"`
}

// inRollout reports whether agentID falls within percent of the fleet.
func inRollout(agentID string, percent int) bool {
	if percent >= 100 {
		return true
	}
	if percent <= 0 {
		return false
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(agentID))
	return int(h.Sum32()%100) < percent
}

// updateTarget is the update block for one agent under s.
func updateTarget(agentID string, s agentUpdateSettings) agentUpdateBlock {
	ch := s.Channel
	if ch != updateChannelBeta {
		ch = updateChannelStable
	}
	b := agentUpdateBlock{
		ManifestURL: channelManifestURL(ch),
		Channel:     ch,
		Paused:      s.Paused || !inRollout(agentID, s.RolloutPercent),
	}
	if s.PinVersion != "" {
		b.TargetVersion = s.PinVersion
		b.AllowDowngrade = true
	}
	return b
}

// updateSettingsFor reads the organization's update ring; defaults when it
// has no row or the read fails.
func (h *AgentAPIHandler) updateSettingsFor(ctx context.Context, orgID string) agentUpdateSettings {
	s := defaultAgentUpdateSettings()
	if h.db == nil || h.db.Pool == nil || orgID == "" {
		return s
	}
	var pin *string
	if err := h.db.Pool.QueryRow(ctx, `
		SELECT update_channel, update_pin_version, update_rollout_percent, update_paused
		  FROM org_agent_settings WHERE org_id = $1`, orgID).
		Scan(&s.Channel, &pin, &s.RolloutPercent, &s.Paused); err != nil {
		return defaultAgentUpdateSettings()
	}
	if pin != nil {
		s.PinVersion = *pin
	}
	return s
}

// updateBlockFor is the /agent/config update block for agentID.
func (h *AgentAPIHandler) updateBlockFor(ctx context.Context, agentID string) *agentUpdateBlock {
	b := updateTarget(agentID, h.updateSettingsFor(ctx, orgIDFrom(ctx)))
	// The box's own mirror wins over the GitHub default (and the env
	// overrides): endpoints then never reach github.com for an update.
	if u := h.mirrorManifestURL(b.Channel); u != "" {
		b.ManifestURL = u
	}
	return &b
}

// recordAgentVersion stores the version a report names and, when present,
// the update outcome. Best-effort: the report is accepted regardless.
func (h *AgentAPIHandler) recordAgentVersion(ctx context.Context, agentID, version string, res *agentUpdateResult) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	version = strings.TrimSpace(version)
	if version != "" && !agentVersionPattern.MatchString(version) {
		version = ""
	}
	var stateJSON []byte
	if res != nil {
		switch res.State {
		case "ok", "failed", "applying", "held":
		default:
			res = nil
		}
	}
	if res != nil {
		if len(res.Error) > 500 {
			res.Error = res.Error[:500]
		}
		if res.Version != "" && !agentVersionPattern.MatchString(res.Version) {
			res.Version = ""
		}
		if res.At == "" {
			res.At = time.Now().UTC().Format(time.RFC3339)
		}
		stateJSON, _ = json.Marshal(res)
	}
	if version == "" && stateJSON == nil {
		return
	}
	if _, err := h.db.Pool.Exec(ctx, `
		UPDATE enrolled_agents
		   SET agent_version = COALESCE(NULLIF($1, ''), agent_version),
		       update_state  = COALESCE($2::jsonb, update_state)
		 WHERE agent_id = $3 AND org_id = $4`,
		version, stateJSON, agentID, orgIDFrom(ctx)); err != nil {
		h.logger.Warn("failed to record the agent version",
			logsafe.String("agent_id", agentID), zap.Error(err))
	}
}

// validUpdateSettings checks an update-ring change.
func validUpdateSettings(s agentUpdateSettings) string {
	if s.Channel != updateChannelStable && s.Channel != updateChannelBeta {
		return "update_channel must be stable or beta"
	}
	if s.RolloutPercent < 0 || s.RolloutPercent > 100 {
		return "update_rollout_percent must be between 0 and 100"
	}
	if s.PinVersion != "" && !agentVersionPattern.MatchString(s.PinVersion) {
		return "update_pin_version is not a version"
	}
	return ""
}

var registerUpdateFailingGauge sync.Once

// RegisterAgentUpdateFailingGauge exposes openidx_agents_update_failing: the
// active devices, across organizations, whose last reported update attempt
// failed in the last day. OpenIDXAgentUpdateFailing watches it. Read at most
// every 30 seconds; registered once per process.
func RegisterAgentUpdateFailingGauge(db *database.PostgresDB, logger *zap.Logger) {
	if db == nil || db.Pool == nil {
		return
	}
	registerUpdateFailingGauge.Do(func() {
		var mu sync.Mutex
		var failing float64
		var at time.Time
		promauto.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: "openidx",
			Name:      "agents_update_failing",
			Help:      "Active devices whose last update attempt, reported in the last 24 hours, failed.",
		}, func() float64 {
			mu.Lock()
			defer mu.Unlock()
			if time.Since(at) < 30*time.Second {
				return failing
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var n int
			err := db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
				//orgscope:ignore install-wide metric: one count across every organization's devices, no row leaves the query
				`
				SELECT count(*) FROM enrolled_agents
				 WHERE status = 'active' AND update_state->>'state' = 'failed'
				   AND last_report_at > NOW() - interval '24 hours'`).Scan(&n)
			if err != nil {
				logger.Debug("agent update gauge: count failed", zap.Error(err))
				return failing
			}
			failing, at = float64(n), time.Now()
			return failing
		})
	})
}
