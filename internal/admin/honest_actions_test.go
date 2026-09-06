package admin

import (
	"encoding/json"
	"net/http"
	"testing"
)

// The two buttons that reported success without acting.
//
// ISPM "Remediate" answered `notification_sent` / "MFA enrollment reminder
// WOULD be sent to user" and `flagged_for_review`, then wrote
// status='remediated' regardless. The posture score counts OPEN findings, so
// that button lowered the open count and raised the score for work nobody had
// done. AI-recommendation "Apply" was the same shape in four cases at once:
// it composed a past-tense sentence ("Stale accounts have been disabled
// pending review"), disabled nobody, and set status='applied'.
//
// These tests pin the rule both now follow: a finding or recommendation moves
// out of its open state only when something really changed, and what the API
// says matches what the database did.

func TestISPMRemediateOnlyResolvesWhatItFixed(t *testing.T) {
	f, cleanup := newTenantFixture(t)
	if f == nil {
		return
	}
	defer cleanup()

	// Seed one finding per check type, all open, against a real user.
	uid := f.seedStaleUser(f.orgA, "ha-user-"+f.orgA[:8])
	newFinding := func(checkType, entityType, entityID string) string {
		t.Helper()
		var id string
		if err := f.db.Pool.QueryRow(f.bypass(), `
			INSERT INTO ispm_findings (org_id, check_type, severity, category, title, affected_entity_type, affected_entity_id, status)
			VALUES ($1, $2, 'high', 'accounts', 'seeded', $3, $4, 'open') RETURNING id`,
			f.orgA, checkType, entityType, entityID).Scan(&id); err != nil {
			t.Fatalf("seed finding %s: %v", checkType, err)
		}
		return id
	}

	type call struct {
		Message  string `json:"message"`
		Resolved bool   `json:"resolved"`
	}
	remediate := func(id string) call {
		t.Helper()
		w := f.call(f.orgA, f.s.handleRemediatePostureFinding, "POST", "/api/v1/ispm/findings/x/remediate",
			map[string]string{"id": id}, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("remediate: %d %s", w.Code, w.Body.String())
		}
		var out call
		decode(t, w, &out)
		return out
	}
	statusOf := func(id string) string {
		t.Helper()
		var st string
		if err := f.db.Pool.QueryRow(f.bypass(), "SELECT status FROM ispm_findings WHERE id = $1", id).Scan(&st); err != nil {
			t.Fatalf("status: %v", err)
		}
		return st
	}

	t.Run("mfa_adoption really sends a reminder and stays open", func(t *testing.T) {
		before := f.count("SELECT COUNT(*) FROM notifications WHERE user_id = $1", uid)
		id := newFinding("mfa_adoption", "user", uid)
		got := remediate(id)
		if got.Resolved {
			t.Error("a sent reminder is not a fixed posture: the finding must stay open")
		}
		if st := statusOf(id); st != "open" {
			t.Errorf("status = %q, want open — the score must not move for a reminder", st)
		}
		if after := f.count("SELECT COUNT(*) FROM notifications WHERE user_id = $1", uid); after != before+1 {
			t.Errorf("notifications for the user: %d -> %d, want +1 (the reminder must be real)", before, after)
		}
	})

	t.Run("stale_accounts really disables and resolves", func(t *testing.T) {
		id := newFinding("stale_accounts", "user", uid)
		got := remediate(id)
		if !got.Resolved {
			t.Fatalf("disabling the account should resolve the finding: %+v", got)
		}
		if st := statusOf(id); st != "remediated" {
			t.Errorf("status = %q, want remediated", st)
		}
		if n := f.count("SELECT COUNT(*) FROM users WHERE id = $1 AND enabled = false", uid); n != 1 {
			t.Error("the account was not actually disabled")
		}
	})

	t.Run("an unimplemented check does not resolve", func(t *testing.T) {
		id := newFinding("over_privileged", "user", uid)
		got := remediate(id)
		if got.Resolved {
			t.Error("over_privileged has no automatic remediation but reported resolved")
		}
		if st := statusOf(id); st != "open" {
			t.Errorf("status = %q, want open", st)
		}
		// The attempt is still recorded, so an operator can see it was tried.
		var details json.RawMessage
		if err := f.db.Pool.QueryRow(f.bypass(),
			"SELECT remediation_details FROM ispm_findings WHERE id = $1", id).Scan(&details); err != nil {
			t.Fatalf("details: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(details, &m); err != nil || m["action"] != "manual_review_required" {
			t.Errorf("remediation_details = %s, want the attempt recorded with manual_review_required", details)
		}
	})
}

func TestRecommendationApplyOnlyMarksAppliedWhenItActed(t *testing.T) {
	f, cleanup := newTenantFixture(t)
	if f == nil {
		return
	}
	defer cleanup()

	uid := f.seedStaleUser(f.orgA, "ha-rec-"+f.orgA[:8])
	newRec := func(recType string, entities string) string {
		t.Helper()
		var id string
		if err := f.db.Pool.QueryRow(f.bypass(), `
			INSERT INTO ai_recommendations (org_id, recommendation_type, category, title, affected_entities, status)
			VALUES ($1, $2, 'security', 'seeded', $3::jsonb, 'pending') RETURNING id`,
			f.orgA, recType, entities).Scan(&id); err != nil {
			t.Fatalf("seed recommendation %s: %v", recType, err)
		}
		return id
	}
	apply := func(id string) (int, string) {
		t.Helper()
		w := f.call(f.orgA, f.s.handleApplyRecommendation, "POST", "/api/v1/recommendations/x/apply",
			map[string]string{"id": id}, nil)
		return w.Code, w.Body.String()
	}
	statusOf := func(id string) string {
		t.Helper()
		var st string
		if err := f.db.Pool.QueryRow(f.bypass(), "SELECT status FROM ai_recommendations WHERE id = $1", id).Scan(&st); err != nil {
			t.Fatalf("status: %v", err)
		}
		return st
	}

	t.Run("mfa_enrollment sends real notifications", func(t *testing.T) {
		before := f.count("SELECT COUNT(*) FROM notifications WHERE user_id = $1", uid)
		id := newRec("mfa_enrollment", `[{"type":"user","id":"`+uid+`","name":"x"}]`)
		if code, body := apply(id); code != http.StatusOK {
			t.Fatalf("apply: %d %s", code, body)
		}
		if after := f.count("SELECT COUNT(*) FROM notifications WHERE user_id = $1", uid); after != before+1 {
			t.Errorf("notifications: %d -> %d, want +1", before, after)
		}
		if st := statusOf(id); st != "applied" {
			t.Errorf("status = %q, want applied", st)
		}
	})

	t.Run("stale_account_cleanup really disables", func(t *testing.T) {
		id := newRec("stale_account_cleanup", `[{"type":"summary","count":1}]`)
		if code, body := apply(id); code != http.StatusOK {
			t.Fatalf("apply: %d %s", code, body)
		}
		if n := f.count("SELECT COUNT(*) FROM users WHERE id = $1 AND enabled = false", uid); n != 1 {
			t.Error("the stale account was not disabled")
		}
		if st := statusOf(id); st != "applied" {
			t.Errorf("status = %q, want applied", st)
		}
	})

	for _, recType := range []string{"permission_right_sizing", "policy_tightening", "agent_permission_scoping", "compliance_gap"} {
		t.Run(recType+" answers 501 and stays pending", func(t *testing.T) {
			id := newRec(recType, `[]`)
			code, body := apply(id)
			if code != http.StatusNotImplemented {
				t.Fatalf("apply %s: %d %s, want 501", recType, code, body)
			}
			if st := statusOf(id); st != "pending" {
				t.Errorf("status = %q, want pending — nothing happened, so nothing may be recorded as applied", st)
			}
			if n := f.count("SELECT COUNT(*) FROM recommendation_history WHERE recommendation_id = $1", id); n != 0 {
				t.Errorf("history rows = %d, want 0 for an action that did not run", n)
			}
		})
	}
}
