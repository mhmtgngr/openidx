package access

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/agentic"
)

// The tools the platform's assistants may call. They are thin: each one asks
// the same code the console's cards ask, so what an assistant says and what
// the page shows cannot differ, and each runs with the asking person's
// authority (agentic.Principal) and no more. Nothing here changes anything yet;
// the fix tools arrive with the approval flow.

// agenticTools holds a service's registry, built on first use. The tools close
// over the service, so each service has its own.
type agenticTools struct {
	once sync.Once
	reg  *agentic.Registry
}

// agenticRegistry builds the registry once.
func (s *Service) agenticRegistry() *agentic.Registry {
	s.agentic.once.Do(func() {
		r := agentic.NewRegistry()
		r.Register(agentic.Tool{
			Name: "diagnose_my_device",
			Description: "Why a device of the person asking cannot connect: the rule engine's verdict " +
				"(cause codes, which part of the chain they come from, and the fixes with who may do them). " +
				"With no agent_id it judges the device that reported most recently.",
			Tier: agentic.TierRead, Audience: agentic.AudienceUser,
			InputSchema: json.RawMessage(`{"type":"object","properties":{"agent_id":{"type":"string","description":"a device id from list_my_devices"}},"additionalProperties":false}`),
			Scope:       agentic.ScopeDevice("agent_id"),
			Run:         s.toolDiagnoseMyDevice,
		})
		r.Register(agentic.Tool{
			Name:        "list_my_devices",
			Description: "The devices of the person asking: id, platform, status, whether it is reporting now and when it last reported.",
			Tier:        agentic.TierRead, Audience: agentic.AudienceUser,
			InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
			Run:         s.toolListMyDevices,
		})
		r.Register(agentic.Tool{
			Name: "recent_automatic_actions",
			Description: "What the platform did, would have done or held back on devices by itself lately " +
				"(the automatic-fix ledger), optionally for one device.",
			Tier: agentic.TierRead, Audience: agentic.AudienceOperator,
			InputSchema: json.RawMessage(`{"type":"object","properties":{"agent_id":{"type":"string"}},"additionalProperties":false}`),
			Run:         s.toolRecentActions,
		})
		s.agentic.reg = r
	})
	return s.agentic.reg
}

// agenticPrincipal is who is asking, from the authenticated request: the
// organization, the person, whether they are an operator and which devices are
// theirs. It is the only place a Principal is made.
func (s *Service) agenticPrincipal(c *gin.Context) (agentic.Principal, error) {
	ctx := c.Request.Context()
	p := agentic.Principal{OrgID: orgIDFrom(ctx), UserID: c.GetString("user_id")}
	if p.OrgID == "" || p.UserID == "" {
		return p, errors.New("no organization or user on the request")
	}
	p.Operator = (s.config != nil && s.config.DevAdminBypass) ||
		callerTierRank(pamCallerRoles(c), false) >= quickLinkRank("operator")
	devices, err := s.collectUserDevices(ctx, p.OrgID, p.UserID)
	if err != nil {
		return p, err
	}
	for _, d := range devices {
		if d.Ziti != nil {
			p.DeviceIDs = append(p.DeviceIDs, d.Ziti.AgentID)
		}
	}
	return p, nil
}

func (s *Service) toolDiagnoseMyDevice(ctx context.Context, p agentic.Principal, input json.RawMessage) (any, error) {
	var in struct {
		AgentID string `json:"agent_id"`
	}
	if err := agentic.Decode(input, &in); err != nil {
		return nil, err
	}
	devices, err := s.collectUserDevices(ctx, p.OrgID, p.UserID)
	if err != nil {
		return nil, err
	}
	return s.myDiagnosis(ctx, p.OrgID, p.UserID, in.AgentID, devices)
}

func (s *Service) toolListMyDevices(ctx context.Context, p agentic.Principal, input json.RawMessage) (any, error) {
	if err := agentic.Decode(input, &struct{}{}); err != nil {
		return nil, err
	}
	devices, err := s.collectUserDevices(ctx, p.OrgID, p.UserID)
	if err != nil {
		return nil, err
	}
	type row struct {
		AgentID      string     `json:"agent_id"`
		Platform     string     `json:"platform,omitempty"`
		Status       string     `json:"status"`
		Reporting    *bool      `json:"reporting_now,omitempty"`
		LastReportAt *time.Time `json:"last_report_at,omitempty"`
	}
	out := []row{}
	for _, d := range devices {
		if z := d.Ziti; z != nil {
			out = append(out, row{z.AgentID, z.Platform, z.Status, z.Live, z.LastReportAt})
		}
	}
	return map[string]any{"devices": out}, nil
}

func (s *Service) toolRecentActions(ctx context.Context, p agentic.Principal, input json.RawMessage) (any, error) {
	var in struct {
		AgentID string `json:"agent_id"`
	}
	if err := agentic.Decode(input, &in); err != nil {
		return nil, err
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT agent_id, action, cause, outcome, reason, created_at
		  FROM agentic_actions
		 WHERE org_id = $1 AND ($2 = '' OR agent_id = $2)
		 ORDER BY created_at DESC, id DESC LIMIT 20`, p.OrgID, in.AgentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type row struct {
		AgentID, Action, Cause, Outcome, Reason string
		At                                      time.Time
	}
	out := []map[string]any{}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.AgentID, &r.Action, &r.Cause, &r.Outcome, &r.Reason, &r.At); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"agent_id": r.AgentID, "action": r.Action, "cause": r.Cause,
			"outcome": r.Outcome, "reason": r.Reason, "at": r.At})
	}
	return map[string]any{"actions": out}, rows.Err()
}
