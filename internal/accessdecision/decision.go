// Package accessdecision answers one question in one place: may this person,
// on this device, in this situation, reach this resource — and why.
//
// Until now the answer was assembled differently at every enforcement point.
// The proxy checked a route's roles and groups, then overlaid application
// assignment; the APISIX forward-auth path checked roles and groups and never
// assignment at all; /oauth/authorize checked assignment through its own
// code; the overlay's dial policies were generated from a third reading. Six
// places defined who may reach what, no two agreed, and none could say why a
// request was allowed.
//
// A resource is an applications row. Its principals are the application's
// user and group assignments (internal/appaccess), plus the legacy roles the
// migration carried over from a route whose roles matched no group. Its
// conditions are the resource_conditions row: device trust, a risk ceiling,
// allowed countries, a fresh second factor. Evaluate reads both and returns a
// Decision that names its grant and every condition it judged; Explain turns
// that into one sentence an administrator can read.
//
// Enforcement is ACCESS_ASSIGNMENT_ENFORCE. In observe mode the Decision is
// allowed and WouldDeny says what enforcement would have done, so every
// caller records the same shape (DecisionEventType) on both branches.
package accessdecision

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/openidx/openidx/internal/common/database"
)

// Subject is who is asking, and what is known about the situation. Zero
// values mean "not known": a condition whose input is not known is reported
// as unjudged rather than failed, so a caller that only knows the principal
// (the OAuth gate) gets a principal decision and the explain endpoint, which
// knows everything, gets the whole one.
type Subject struct {
	UserID string
	OrgID  string
	// Roles are the session's role names, judged against legacy_roles.
	Roles []string
	// Situation, when the caller knows it.
	KnowsSituation bool
	DeviceTrusted  bool
	RiskScore      int
	Country        string
	// FreshMFA is judged only when MFAKnown: the proxy knows the device, the
	// country and the risk of a request but not when the person last proved a
	// second factor (its session is not the login session), so it reports a
	// fresh-factor condition unjudged rather than guess.
	FreshMFA bool
	MFAKnown bool
}

// Reason codes a Decision can carry.
const (
	ReasonNotAssigned     = "not_assigned"
	ReasonDeviceTrust     = "device_trust_required"
	ReasonRiskAboveMax    = "risk_above_max"
	ReasonCountry         = "country_not_allowed"
	ReasonStepUp          = "step_up_required"
	ReasonAppDisabled     = "application_disabled"
	ReasonNoSuchApp       = "no_such_application"
	ReasonNoSubject       = "no_subject"
	ConditionDeviceTrust  = "device_trust"
	ConditionRiskCeiling  = "risk_ceiling"
	ConditionCountry      = "country"
	ConditionStepUp       = "fresh_mfa"
	GrantDirect           = "direct"
	GrantGroupPrefix      = "group:"
	GrantLegacyRolePrefix = "legacy_role:"
)

// ConditionResult is one condition the resource sets and how the subject met it.
type ConditionResult struct {
	Name      string `json:"name"`
	Required  string `json:"required"`
	Observed  string `json:"observed"`
	Satisfied bool   `json:"satisfied"`
	// Judged is false when the caller did not know the input.
	Judged bool `json:"judged"`
}

// Decision is the answer.
type Decision struct {
	AppID   string `json:"application_id"`
	AppName string `json:"application_name"`
	Kind    string `json:"kind"`
	// Enforced is whether the verdict applies or only reports.
	Enforced bool `json:"enforced"`
	// Allowed is the verdict that applies: under observe mode, always true.
	Allowed bool `json:"allowed"`
	// WouldDeny is what enforcement would decide; equal to !Allowed when enforced.
	WouldDeny bool `json:"would_deny"`
	// ConditionsDeclared is whether the resource has a resource_conditions row.
	// When it has, those conditions are the resource's; an enforcement point
	// that also carries a pre-230 copy of them (a proxy route's columns) lets
	// this decision rule and does not judge its copy a second time.
	ConditionsDeclared bool `json:"conditions_declared"`
	// Grant names what let the subject in: "direct", "group:<name>",
	// "legacy_role:<role>", or "" when nothing did.
	Grant      string            `json:"grant"`
	Conditions []ConditionResult `json:"conditions"`
	Reasons    []string          `json:"reasons"`
	StepUp     bool              `json:"step_up_required"`
}

// Conditions is a resource_conditions row.
type Conditions struct {
	RequireDeviceTrust bool
	MaxRiskScore       *int
	AllowedCountries   []string
	RequireStepUp      bool
	LegacyRoles        []string
}

// Resource is what Evaluate needs to know about the application.
type Resource struct {
	ID, Name, Kind string
	Enabled        bool
	Conditions     Conditions
	// ConditionsDeclared is whether a resource_conditions row exists.
	ConditionsDeclared bool
}

// Evaluate decides whether s may reach application appID.
func Evaluate(ctx context.Context, db *database.PostgresDB, enforce bool, s Subject, appID string) (Decision, error) {
	d := Decision{AppID: appID, Enforced: enforce}
	if s.UserID == "" || s.OrgID == "" || appID == "" {
		return deny(d, ReasonNoSubject), nil
	}
	res, err := LoadResource(ctx, db, appID, s.OrgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return deny(d, ReasonNoSuchApp), nil
		}
		return d, err
	}
	d.AppName, d.Kind, d.ConditionsDeclared = res.Name, res.Kind, res.ConditionsDeclared
	if !res.Enabled {
		return deny(d, ReasonAppDisabled), nil
	}
	grant, err := grantFor(ctx, db, s, appID)
	if err != nil {
		return d, err
	}
	if grant == "" {
		for _, want := range res.Conditions.LegacyRoles {
			for _, have := range s.Roles {
				if strings.EqualFold(want, have) {
					grant = GrantLegacyRolePrefix + want
				}
			}
		}
	}
	d.Grant = grant
	if grant == "" {
		d = deny(d, ReasonNotAssigned)
	}
	d = judgeConditions(d, res.Conditions, s)
	// Under observe mode the verdict applies to nobody; WouldDeny carries it.
	d.WouldDeny = len(d.Reasons) > 0
	d.Allowed = !enforce || !d.WouldDeny
	return d, nil
}

func deny(d Decision, reason string) Decision {
	d.Reasons = append(d.Reasons, reason)
	d.WouldDeny = true
	d.Allowed = !d.Enforced
	return d
}

// judgeConditions reports every condition the resource sets. Conditions whose
// input the subject does not carry are listed unjudged and do not deny.
func judgeConditions(d Decision, c Conditions, s Subject) Decision {
	add := func(cr ConditionResult, reason string) {
		d.Conditions = append(d.Conditions, cr)
		if cr.Judged && !cr.Satisfied {
			d.Reasons = append(d.Reasons, reason)
		}
	}
	if c.RequireDeviceTrust {
		add(ConditionResult{Name: ConditionDeviceTrust, Required: "trusted", Observed: observed(s.KnowsSituation, boolWord(s.DeviceTrusted, "trusted", "untrusted")),
			Satisfied: s.DeviceTrusted, Judged: s.KnowsSituation}, ReasonDeviceTrust)
		if s.KnowsSituation && !s.DeviceTrusted {
			d.StepUp = true
		}
	}
	if c.MaxRiskScore != nil {
		add(ConditionResult{Name: ConditionRiskCeiling, Required: fmt.Sprintf("<= %d", *c.MaxRiskScore), Observed: observed(s.KnowsSituation, fmt.Sprint(s.RiskScore)),
			Satisfied: s.RiskScore <= *c.MaxRiskScore, Judged: s.KnowsSituation}, ReasonRiskAboveMax)
		if s.KnowsSituation && s.RiskScore > *c.MaxRiskScore {
			d.StepUp = true
		}
	}
	if len(c.AllowedCountries) > 0 {
		ok := false
		for _, cc := range c.AllowedCountries {
			if strings.EqualFold(cc, s.Country) {
				ok = true
			}
		}
		known := s.KnowsSituation && s.Country != ""
		add(ConditionResult{Name: ConditionCountry, Required: strings.Join(c.AllowedCountries, ","), Observed: observed(known, s.Country),
			Satisfied: ok, Judged: known}, ReasonCountry)
	}
	if c.RequireStepUp {
		known := s.KnowsSituation && s.MFAKnown
		add(ConditionResult{Name: ConditionStepUp, Required: "fresh second factor", Observed: observed(known, boolWord(s.FreshMFA, "fresh", "stale")),
			Satisfied: s.FreshMFA, Judged: known}, ReasonStepUp)
		if known && !s.FreshMFA {
			d.StepUp = true
		}
	}
	return d
}

func observed(known bool, v string) string {
	if !known {
		return "unknown"
	}
	return v
}

func boolWord(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

// Explain is the Decision in one sentence: what let the person in (or did
// not), and every condition with its outcome.
func Explain(d Decision) string {
	var b strings.Builder
	name := d.AppName
	if name == "" {
		name = d.AppID
	}
	switch {
	case d.Grant == GrantDirect:
		fmt.Fprintf(&b, "%s: assigned directly", name)
	case strings.HasPrefix(d.Grant, GrantGroupPrefix):
		fmt.Fprintf(&b, "%s: assigned through group %s", name, strings.TrimPrefix(d.Grant, GrantGroupPrefix))
	case strings.HasPrefix(d.Grant, GrantLegacyRolePrefix):
		fmt.Fprintf(&b, "%s: allowed by the route's legacy role %s", name, strings.TrimPrefix(d.Grant, GrantLegacyRolePrefix))
	default:
		fmt.Fprintf(&b, "%s: not assigned", name)
	}
	for _, c := range d.Conditions {
		mark := "✓"
		if !c.Judged {
			mark = "?"
		} else if !c.Satisfied {
			mark = "✗"
		}
		fmt.Fprintf(&b, "; %s %s (%s, observed %s)", c.Name, mark, c.Required, c.Observed)
	}
	if len(d.Reasons) > 0 {
		verdict := "would deny"
		if d.Enforced {
			verdict = "denied"
		}
		fmt.Fprintf(&b, " → %s: %s", verdict, strings.Join(d.Reasons, ", "))
	} else {
		b.WriteString(" → allowed")
	}
	return b.String()
}

// LoadResource reads the application and its conditions.
func LoadResource(ctx context.Context, db *database.PostgresDB, appID, orgID string) (Resource, error) {
	var r Resource
	var maxRisk *int
	err := db.Pool.QueryRow(ctx, `
		SELECT a.id, a.name, a.kind, a.enabled,
		       COALESCE(c.require_device_trust, false), c.max_risk_score,
		       COALESCE(c.allowed_countries, '{}'), COALESCE(c.require_step_up, false),
		       COALESCE(c.legacy_roles, '{}'), c.application_id IS NOT NULL
		  FROM applications a
		  LEFT JOIN resource_conditions c ON c.application_id = a.id
		 WHERE a.id = $1 AND a.org_id = $2`, appID, orgID).Scan(
		&r.ID, &r.Name, &r.Kind, &r.Enabled,
		&r.Conditions.RequireDeviceTrust, &maxRisk,
		&r.Conditions.AllowedCountries, &r.Conditions.RequireStepUp,
		&r.Conditions.LegacyRoles, &r.ConditionsDeclared)
	if err != nil {
		return r, err
	}
	r.Conditions.MaxRiskScore = maxRisk
	return r, nil
}

// grantFor names the assignment that admits the subject: a direct one first,
// else the first group that carries one. The predicates are appaccess's.
func grantFor(ctx context.Context, db *database.PostgresDB, s Subject, appID string) (string, error) {
	var direct bool
	var group *string
	err := db.Pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM user_application_assignments uaa
		                WHERE uaa.application_id = $3 AND uaa.user_id = $1 AND uaa.org_id = $2
		                  AND (uaa.expires_at IS NULL OR uaa.expires_at > NOW())),
		       (SELECT g.name FROM group_application_assignments gaa
		          JOIN group_memberships gm ON gm.group_id = gaa.group_id
		          JOIN groups g ON g.id = gaa.group_id
		         WHERE gaa.application_id = $3 AND gm.user_id = $1 AND gaa.org_id = $2
		           AND (gm.expires_at IS NULL OR gm.expires_at > NOW())
		         ORDER BY g.name LIMIT 1)`, s.UserID, s.OrgID, appID).Scan(&direct, &group)
	if err != nil {
		return "", fmt.Errorf("accessdecision: grant: %w", err)
	}
	if direct {
		return GrantDirect, nil
	}
	if group != nil {
		return GrantGroupPrefix + *group, nil
	}
	return "", nil
}
