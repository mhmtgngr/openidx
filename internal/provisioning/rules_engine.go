package provisioning

import (
	"context"
	"encoding/json"
	"strings"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// Provisioning-rule evaluation.
//
// The rules CRUD (POST/GET/PUT/DELETE /rules) and its admin-console page have
// existed since v12, but nothing ever evaluated the stored rules — rule-based
// auto-provisioning silently did nothing. This engine executes the safe,
// additive subset on the SCIM lifecycle triggers:
//
//   - triggers: user_created, user_updated
//   - conditions: ALL must hold (AND); string operators equals / not_equals /
//     contains / not_contains / starts_with / ends_with, compared
//     case-insensitively, over the SCIM user fields listed in scimUserField.
//     An unknown field or operator makes the rule NOT match (fail closed) and
//     is logged — a typo can only result in fewer assignments, never more.
//   - actions: add_to_group and assign_role, resolved by target id or name
//     WITHIN the caller's org, idempotently (ON CONFLICT DO NOTHING). Every
//     other action type (remove_*, disable_account, set_attribute,
//     send_email, notify_admin) is deliberately not auto-executed and is
//     logged as skipped: destructive or side-effecting actions need a human
//     in the loop until they get their own reviewed implementation.
//
// Evaluation is best-effort after the user write succeeds: an engine error
// never fails the SCIM operation and never grants anything beyond the two
// explicit idempotent inserts above.

// applyProvisioningRules evaluates the org's enabled rules for trigger and
// applies matching rules' supported actions to the user.
func (s *Service) applyProvisioningRules(ctx context.Context, trigger RuleTrigger, user *SCIMUser) {
	if user == nil || user.ID == "" {
		return
	}
	org, err := orgctx.From(ctx)
	if err != nil {
		return
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, name, conditions, actions
		FROM provisioning_rules
		WHERE org_id = $1 AND enabled = true AND trigger = $2
		ORDER BY priority ASC, created_at ASC`, org.ID, string(trigger))
	if err != nil {
		s.logger.Warn("provisioning rules query failed; no rules applied", zap.Error(err))
		return
	}
	defer rows.Close()

	type storedRule struct {
		id, name   string
		conditions []RuleCondition
		actions    []RuleAction
	}
	var rules []storedRule
	for rows.Next() {
		var r storedRule
		var condJSON, actJSON []byte
		if err := rows.Scan(&r.id, &r.name, &condJSON, &actJSON); err != nil {
			continue
		}
		if json.Unmarshal(condJSON, &r.conditions) != nil || json.Unmarshal(actJSON, &r.actions) != nil {
			s.logger.Warn("provisioning rule has malformed conditions/actions; skipped",
				zap.String("rule", r.name))
			continue
		}
		rules = append(rules, r)
	}

	for _, r := range rules {
		if !s.ruleMatches(r.conditions, user, r.name) {
			continue
		}
		for _, a := range r.actions {
			s.applyRuleAction(ctx, org.ID, user.ID, a, r.name)
		}
	}
}

// ruleMatches reports whether every condition holds for the user. A rule with
// no conditions matches every user (the admin explicitly configured it so).
func (s *Service) ruleMatches(conds []RuleCondition, user *SCIMUser, ruleName string) bool {
	for _, c := range conds {
		got, ok := scimUserField(user, c.Field)
		if !ok {
			s.logger.Warn("provisioning rule references an unsupported field; rule will not match",
				zap.String("rule", ruleName), zap.String("field", c.Field))
			return false
		}
		if !supportedOperator(c.Operator) {
			s.logger.Warn("provisioning rule uses an unsupported operator; rule will not match",
				zap.String("rule", ruleName), zap.String("operator", c.Operator))
			return false
		}
		if !conditionHolds(got, c.Operator, c.Value) {
			return false
		}
	}
	return true
}

// scimUserField maps a condition field name to the user's attribute value.
func scimUserField(u *SCIMUser, field string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "username", "user_name":
		return u.UserName, true
	case "email", "emails.value":
		if len(u.Emails) > 0 {
			return u.Emails[0].Value, true
		}
		return "", true
	case "displayname", "display_name":
		return u.DisplayName, true
	case "givenname", "given_name", "firstname", "first_name":
		return u.Name.GivenName, true
	case "familyname", "family_name", "lastname", "last_name":
		return u.Name.FamilyName, true
	case "externalid", "external_id":
		return u.ExternalID, true
	case "department":
		if u.Enterprise != nil {
			return u.Enterprise.Department, true
		}
		return "", true
	default:
		return "", false
	}
}

func supportedOperator(op string) bool {
	switch op {
	case "equals", "not_equals", "contains", "not_contains", "starts_with", "ends_with":
		return true
	default:
		// regex / greater_than / less_than (offered by the UI) and anything
		// unknown: not auto-evaluated — the rule fails closed.
		return false
	}
}

// conditionHolds compares case-insensitively: SCIM userName is
// case-insensitive by spec and email matching is conventionally so.
func conditionHolds(got, op, want string) bool {
	g, w := strings.ToLower(got), strings.ToLower(want)
	switch op {
	case "equals":
		return g == w
	case "not_equals":
		return g != w
	case "contains":
		return strings.Contains(g, w)
	case "not_contains":
		return !strings.Contains(g, w)
	case "starts_with":
		return strings.HasPrefix(g, w)
	case "ends_with":
		return strings.HasSuffix(g, w)
	default:
		return false
	}
}

// applyRuleAction executes a single supported action, org-scoped and
// idempotent. Unsupported action types are skipped loudly.
func (s *Service) applyRuleAction(ctx context.Context, orgID, userID string, a RuleAction, ruleName string) {
	target := strings.TrimSpace(a.Target)
	switch a.Type {
	case "add_to_group":
		res, err := s.db.Pool.Exec(ctx, `
			INSERT INTO group_memberships (user_id, group_id, org_id)
			SELECT $1, id, $3 FROM groups WHERE (id::text = $2 OR name = $2) AND org_id = $3
			ON CONFLICT DO NOTHING`, userID, target, orgID)
		s.reportRuleAction(ctx, ruleName, a, userID, res.RowsAffected(), err)
	case "assign_role":
		res, err := s.db.Pool.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, org_id)
			SELECT $1, id, $3 FROM roles WHERE (id::text = $2 OR name = $2) AND org_id = $3
			ON CONFLICT DO NOTHING`, userID, target, orgID)
		s.reportRuleAction(ctx, ruleName, a, userID, res.RowsAffected(), err)
	default:
		s.logger.Warn("provisioning rule action type is not auto-executed; skipped",
			zap.String("rule", ruleName), zap.String("type", a.Type), zap.String("target", target))
	}
}

func (s *Service) reportRuleAction(ctx context.Context, ruleName string, a RuleAction, userID string, rows int64, err error) {
	if err != nil {
		s.logger.Warn("provisioning rule action failed",
			zap.String("rule", ruleName), zap.String("type", a.Type),
			zap.String("target", a.Target), zap.Error(err))
		return
	}
	if rows == 0 {
		// Either the target doesn't exist in this org or the assignment
		// already existed; the former is the case worth surfacing.
		s.logger.Warn("provisioning rule action affected no rows (target missing in org, or already assigned)",
			zap.String("rule", ruleName), zap.String("type", a.Type), zap.String("target", a.Target))
		return
	}
	s.logAuditEvent(ctx, "provisioning", "scim", "scim.rule_action_applied", "success",
		"system", userID, "user", map[string]interface{}{
			"rule":   ruleName,
			"action": a.Type,
			"target": a.Target,
		})
}
