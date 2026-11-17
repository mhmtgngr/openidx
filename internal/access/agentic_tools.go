package access

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

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
	// providerOverride replaces the organization's model in tests.
	providerOverride agentic.Provider
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
		s.registerOperatorTools(r)
		s.agentic.reg = r
	})
	return s.agentic.reg
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

// registerOperatorTools adds what the operations assistant may do. Four tools
// look and one proposes: it can lay out a plan to open an application to a
// group, which an administrator then approves or dismisses. Nothing here
// changes access, an update ring or a device.
func (s *Service) registerOperatorTools(r *agentic.Registry) {
	r.Register(agentic.Tool{
		Name:        "rollout_status",
		Description: "How the agent update is going for this organization: the target version, the update ring, the rules' verdict with reasons and counts, and any step waiting for an administrator.",
		Tier:        agentic.TierRead, Audience: agentic.AudienceOperator,
		InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		Run:         s.toolRolloutStatus,
	})
	r.Register(agentic.Tool{
		Name:        "search_applications",
		Description: "Find applications of this organization by part of the name (up to ten): id, name, kind, whether it is enabled. Use it to get the exact name before planning.",
		Tier:        agentic.TierRead, Audience: agentic.AudienceOperator,
		InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","maxLength":100}},"additionalProperties":false}`),
		Run:         s.toolSearchApplications,
	})
	r.Register(agentic.Tool{
		Name:        "search_groups",
		Description: "Find groups of this organization by part of the name (up to ten): id, name, number of members.",
		Tier:        agentic.TierRead, Audience: agentic.AudienceOperator,
		InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","maxLength":100}},"additionalProperties":false}`),
		Run:         s.toolSearchGroups,
	})
	r.Register(agentic.Tool{
		Name:        "list_access_plans",
		Description: "The plans to open applications to groups that are waiting for an administrator, and those decided in the last week.",
		Tier:        agentic.TierRead, Audience: agentic.AudienceOperator,
		InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		Run:         s.toolListAccessPlans,
	})
	r.Register(agentic.Tool{
		Name: "plan_open_access",
		Description: "Lay out a plan to open one application to one group, given as names or ids. This changes nothing: a ready plan is stored for an administrator, who approves or dismisses it. " +
			"The answer says whether it can be done, the risks and what a member of the group can do today.",
		Tier: agentic.TierPropose, Audience: agentic.AudienceOperator,
		InputSchema: json.RawMessage(`{"type":"object","properties":{"resource":{"type":"string","maxLength":255},"group":{"type":"string","maxLength":255}},"required":["resource","group"],"additionalProperties":false}`),
		Run:         s.toolPlanOpenAccess,
	})
}

func (s *Service) toolRolloutStatus(ctx context.Context, p agentic.Principal, input json.RawMessage) (any, error) {
	if err := agentic.Decode(input, &struct{}{}); err != nil {
		return nil, err
	}
	if s.agentHandler == nil {
		return nil, errors.New("the agent fleet is not available")
	}
	return s.agentHandler.assessRollout(ctx, p.OrgID)
}

// searchTerm is the query a model sent, bounded; matching is by substring with
// no pattern characters, so a query can only narrow a list.
func searchTerm(input json.RawMessage) (string, error) {
	var in struct {
		Query string `json:"query"`
	}
	if err := agentic.Decode(input, &in); err != nil {
		return "", err
	}
	if len(in.Query) > 100 {
		in.Query = in.Query[:100]
	}
	return in.Query, nil
}

func (s *Service) toolSearchApplications(ctx context.Context, p agentic.Principal, input json.RawMessage) (any, error) {
	q, err := searchTerm(input)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id::text, name, kind, enabled FROM applications
		 WHERE org_id = $1 AND ($2 = '' OR position(lower($2) in lower(name)) > 0)
		 ORDER BY name LIMIT 10`, p.OrgID, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, name, kind string
		var enabled bool
		if err := rows.Scan(&id, &name, &kind, &enabled); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "name": name, "kind": kind, "enabled": enabled})
	}
	return map[string]any{"applications": out}, rows.Err()
}

func (s *Service) toolSearchGroups(ctx context.Context, p agentic.Principal, input json.RawMessage) (any, error) {
	q, err := searchTerm(input)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT g.id::text, g.name, (SELECT count(*) FROM group_memberships gm WHERE gm.group_id = g.id)
		  FROM groups g
		 WHERE g.org_id = $1 AND ($2 = '' OR position(lower($2) in lower(g.name)) > 0)
		 ORDER BY g.name LIMIT 10`, p.OrgID, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, name string
		var members int
		if err := rows.Scan(&id, &name, &members); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "name": name, "members": members})
	}
	return map[string]any{"groups": out}, rows.Err()
}

func (s *Service) toolListAccessPlans(ctx context.Context, p agentic.Principal, input json.RawMessage) (any, error) {
	if err := agentic.Decode(input, &struct{}{}); err != nil {
		return nil, err
	}
	plans, err := s.accessPlanViews(ctx, p.OrgID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"plans": plans}, nil
}

func (s *Service) toolPlanOpenAccess(ctx context.Context, p agentic.Principal, input json.RawMessage) (any, error) {
	var in struct {
		Resource string `json:"resource"`
		Group    string `json:"group"`
	}
	if err := agentic.Decode(input, &in); err != nil {
		return nil, err
	}
	if in.Resource == "" || in.Group == "" || len(in.Resource) > 255 || len(in.Group) > 255 {
		return nil, errors.New("name the resource and the group")
	}
	view, status, err := s.proposeAccessPlan(ctx, p.OrgID, in.Resource, in.Group,
		func(action, target string, details map[string]interface{}) {
			s.logger.Info("AUDIT", zap.String("category", "agentic"), zap.String("action", action),
				zap.String("actor", p.UserID), zap.String("target", target), zap.Any("details", details), zap.String("via", "assistant"))
		})
	if errors.Is(err, errAmbiguous) {
		return map[string]any{"result": "ambiguous", "note": "the name matches more than one; search and use the id"}, nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"result": map[int]string{http.StatusCreated: "stored_for_approval", http.StatusOK: "nothing_to_do", http.StatusUnprocessableEntity: "cannot_be_done"}[status],
		"plan":   view,
		"note":   "nothing has changed; an administrator must approve a stored plan",
	}, nil
}
