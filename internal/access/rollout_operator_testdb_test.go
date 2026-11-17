package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

type rolloutHarness struct {
	*diagnoseHarness
	h      *AgentAPIHandler
	router *gin.Engine
	user   string
}

func newRolloutHarness(t *testing.T, slug string) *rolloutHarness {
	t.Helper()
	d, ada, _ := newDiagnoseHarness(t, slug)
	h := NewAgentAPIHandler(zap.NewNop(), d.svc.db, nil, &config.Config{AgentLivenessTimeout: "10m"})
	r := gin.New()
	api := r.Group("/api/v1/access", func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: d.orgID}))
		c.Set("user_id", ada)
		c.Next()
	})
	api.GET("/agent/rollout", h.HandleGetRollout)
	api.POST("/agent/rollout/proposals/:id/approve", h.HandleApproveRolloutProposal)
	api.POST("/agent/rollout/proposals/:id/reject", h.HandleRejectRolloutProposal)
	return &rolloutHarness{diagnoseHarness: d, h: h, router: r, user: ada}
}

// device adds an active device, live now, on version, with its last update
// outcome (state "" for none).
func (r *rolloutHarness) device(i int, version, state string) {
	r.t.Helper()
	var st interface{}
	if state != "" {
		st = fmt.Sprintf(`{"state":%q,"at":%q}`, state, time.Now().UTC().Add(-time.Hour).Format(time.RFC3339))
	}
	r.exec(`INSERT INTO enrolled_agents (org_id, agent_id, device_id, auth_token_hash, status, compliance_status, enrolled_by_user_id,
	                                      last_report_at, agent_version, update_state)
	        VALUES ($1::uuid, $2::text, $2::text, md5($2::text), 'active', 'compliant', $3::uuid, NOW(), $4::text, $5::jsonb)`,
		r.orgID, fmt.Sprintf("roll-%s-%d", r.orgID[:8], i), r.user, version, st)
}

// ring sets the organization's update ring, last changed `ago` ago.
func (r *rolloutHarness) ring(percent int, paused bool, pin string, ago string) {
	r.t.Helper()
	r.exec(`INSERT INTO org_agent_settings (org_id, update_rollout_percent, update_paused, update_pin_version, updated_at)
	        VALUES ($1::uuid, $2, $3, $4, NOW() - $5::interval)
	        ON CONFLICT (org_id) DO UPDATE SET update_rollout_percent = $2, update_paused = $3,
	             update_pin_version = $4, updated_at = NOW() - $5::interval`, r.orgID, percent, paused, pin, ago)
}

func (r *rolloutHarness) call(method, path string) (int, map[string]any) {
	req := httptest.NewRequest(method, "/api/v1/access"+path, nil)
	w := httptest.NewRecorder()
	r.router.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (r *rolloutHarness) ctx() context.Context { return context.Background() }

func (r *rolloutHarness) settings() (percent int, paused bool) {
	r.t.Helper()
	if err := r.pool.QueryRow(r.ctx(), `SELECT update_rollout_percent, update_paused FROM org_agent_settings WHERE org_id = $1::uuid`, r.orgID).Scan(&percent, &paused); err != nil {
		r.t.Fatal(err)
	}
	return
}

func (r *rolloutHarness) pending(kind string) (id string) {
	r.t.Helper()
	_ = r.pool.QueryRow(r.ctx(), `SELECT COALESCE((SELECT id::text FROM agentic_proposals WHERE org_id = $1::uuid AND kind = $2 AND status = 'pending'), '')`, r.orgID, kind).Scan(&id)
	return
}

func (r *rolloutHarness) runOperator() {
	r.t.Helper()
	r.h.runRolloutOperator(orgctx.With(r.ctx(), orgctx.Org{ID: r.orgID}), r.orgID)
}

func TestRolloutAdvanceNeedsAPersonAndOnlyAppliesWhileNothingHasMoved(t *testing.T) {
	r := newRolloutHarness(t, "rollout-advance-org")
	for i := 0; i < 10; i++ {
		r.device(i, "0.6.0", "ok")
	}
	r.ring(50, false, "0.6.0", "2 hours")

	// Even in tier1 a widening is only proposed, never taken.
	r.exec(`INSERT INTO org_agentic_settings (org_id, mode) VALUES ($1::uuid, 'tier1')`, r.orgID)
	r.runOperator()
	if p, _ := r.settings(); p != 50 {
		t.Fatalf("the operator widened the ring by itself: %d", p)
	}
	id := r.pending(proposalAdvance)
	if id == "" {
		t.Fatal("no advance proposal was made for a healthy, soaked ring")
	}
	r.runOperator() // a second look does not ask again
	if n := r.count(`SELECT COUNT(*) FROM agentic_proposals WHERE org_id = $1::uuid`, r.orgID); n != 1 {
		t.Errorf("%d proposals after two looks, want 1", n)
	}

	code, view := r.call(http.MethodGet, "/agent/rollout")
	verdict, _ := view["verdict"].(map[string]any)
	if code != http.StatusOK || verdict["status"] != "ready" || len(view["pending"].([]any)) != 1 || view["target_source"] != "pin" {
		t.Fatalf("assessment: %d %v", code, view)
	}

	// The settings move after the proposal was made: it must not apply.
	r.ring(25, false, "0.6.0", "2 hours")
	if code, _ := r.call(http.MethodPost, "/agent/rollout/proposals/"+id+"/approve"); code != http.StatusConflict {
		t.Errorf("a stale proposal answered %d, want 409", code)
	}
	if p, _ := r.settings(); p != 25 {
		t.Errorf("a stale approval changed the ring to %d", p)
	}

	// A fresh look proposes again; this one is approved.
	r.runOperator()
	id = r.pending(proposalAdvance)
	if id == "" {
		t.Fatal("no proposal after the ring changed")
	}
	if code, out := r.call(http.MethodPost, "/agent/rollout/proposals/"+id+"/approve"); code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, out)
	}
	if p, _ := r.settings(); p != 50 {
		t.Errorf("ring after approval = %d, want 50 (25 -> next ring)", p)
	}
	if code, _ := r.call(http.MethodPost, "/agent/rollout/proposals/"+id+"/approve"); code != http.StatusNotFound {
		t.Errorf("approving twice answered %d, want 404", code)
	}
}

func TestRolloutPauseFollowsTheOrganizationsMode(t *testing.T) {
	r := newRolloutHarness(t, "rollout-pause-org")
	for i := 0; i < 8; i++ {
		r.device(i, "0.6.0", "ok")
	}
	r.device(8, "0.5.0", "failed")
	r.device(9, "0.5.0", "failed")
	r.ring(100, false, "0.6.0", "3 hours")

	// observe (the default): recorded and proposed, nothing done.
	r.runOperator()
	if _, paused := r.settings(); paused {
		t.Fatal("observe mode paused the rollout")
	}
	if r.count(`SELECT COUNT(*) FROM agentic_actions WHERE org_id = $1::uuid AND action = 'rollout_pause' AND outcome = 'observed'`, r.orgID) != 1 ||
		r.pending(proposalPause) == "" {
		t.Fatal("observe mode should record one observation and leave a pause proposal")
	}

	// tier0: the circuit breaker closes by itself.
	r.exec(`INSERT INTO org_agentic_settings (org_id, mode) VALUES ($1::uuid, 'tier0')`, r.orgID)
	r.runOperator()
	if _, paused := r.settings(); !paused {
		t.Fatal("tier0 did not pause a failing rollout")
	}
	if r.count(`SELECT COUNT(*) FROM agentic_actions WHERE org_id = $1::uuid AND outcome = 'applied' AND action = 'rollout_pause'`, r.orgID) != 1 {
		t.Error("the pause was not written to the ledger")
	}
	if id := r.pending(proposalPause); id != "" {
		t.Error("a pause proposal is still pending after the pause was taken")
	}

	// Un-paused by a person and failing again the same day: held, proposed.
	r.exec(`UPDATE org_agent_settings SET update_paused = FALSE, updated_at = NOW() - interval '3 hours' WHERE org_id = $1::uuid`, r.orgID)
	r.runOperator()
	if _, paused := r.settings(); paused {
		t.Error("the operator paused twice in a day")
	}
	if r.count(`SELECT COUNT(*) FROM agentic_actions WHERE org_id = $1::uuid AND reason = 'anti_flap'`, r.orgID) != 1 || r.pending(proposalPause) == "" {
		t.Error("the second pause should be held back as anti_flap and proposed instead")
	}

	// The kill switch stops automation, not the advice.
	r.exec(`DELETE FROM agentic_actions WHERE org_id = $1::uuid`, r.orgID)
	r.exec(`UPDATE org_agentic_settings SET kill_switch = TRUE WHERE org_id = $1::uuid`, r.orgID)
	r.runOperator()
	if _, paused := r.settings(); paused {
		t.Error("the kill switch did not stop the pause")
	}
	if r.count(`SELECT COUNT(*) FROM agentic_actions WHERE org_id = $1::uuid AND reason = 'kill_switch'`, r.orgID) != 1 {
		t.Error("the held-back pause under the kill switch was not recorded")
	}

	// A person approves the pause proposal.
	id := r.pending(proposalPause)
	if id == "" {
		t.Fatal("no pause proposal to approve")
	}
	if code, out := r.call(http.MethodPost, "/agent/rollout/proposals/"+id+"/approve"); code != http.StatusOK {
		t.Fatalf("approve pause: %d %v", code, out)
	}
	if _, paused := r.settings(); !paused {
		t.Error("an approved pause did not pause")
	}
}

func TestRolloutRejectAndOtherOrganizations(t *testing.T) {
	r := newRolloutHarness(t, "rollout-reject-org")
	for i := 0; i < 4; i++ {
		r.device(i, "0.6.0", "ok")
	}
	r.ring(5, false, "0.6.0", "2 hours")
	r.runOperator()
	id := r.pending(proposalAdvance)
	if id == "" {
		t.Fatal("no proposal")
	}
	if code, _ := r.call(http.MethodPost, "/agent/rollout/proposals/"+id+"/reject"); code != http.StatusOK {
		t.Fatal("reject failed")
	}
	if r.pending(proposalAdvance) != "" {
		t.Error("a rejected proposal is still pending")
	}
	if p, _ := r.settings(); p != 5 {
		t.Errorf("rejecting changed the ring to %d", p)
	}

	// Another organization's proposal is not found, whoever asks.
	var other, otherProposal string
	_ = r.pool.QueryRow(r.ctx(), `INSERT INTO organizations (name, slug) VALUES ('rollout-other', 'rollout-other') RETURNING id::text`).Scan(&other)
	r.exec(`INSERT INTO agentic_proposals (org_id, kind, params, base_hash) VALUES ($1::uuid, 'rollout_advance', '{"action":"advance","percent":25}', 'x')`, other)
	_ = r.pool.QueryRow(r.ctx(), `SELECT id::text FROM agentic_proposals WHERE org_id = $1::uuid`, other).Scan(&otherProposal)
	for _, op := range []string{"approve", "reject"} {
		if code, _ := r.call(http.MethodPost, "/agent/rollout/proposals/"+otherProposal+"/"+op); code != http.StatusNotFound {
			t.Errorf("%s of another organization's proposal answered %d, want 404", op, code)
		}
	}
}
