package access

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/diagnose"
	"github.com/openidx/openidx/internal/migrations"
)

type diagnoseHarness struct {
	t    *testing.T
	exec func(sql string, args ...any)
	pool interface {
		QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	}
	orgID  string
	router *gin.Engine
	as     *string
	svc    *Service
}

func newDiagnoseHarness(t *testing.T, slug string) (*diagnoseHarness, string, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.Skip("no test database")
	}
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	h := &diagnoseHarness{t: t, pool: db.Pool}
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, slug).Scan(&h.orgID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	user := func(name string) string {
		var id string
		if err := db.Pool.QueryRow(ctx,
			`INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2::text, $2::text || '@example.test', true)
			 RETURNING id::text`, h.orgID, slug+"-"+name).Scan(&id); err != nil {
			t.Fatalf("seed user: %v", err)
		}
		return id
	}
	ada, bo := user("ada"), user("bo")
	h.exec = func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("exec %q: %v", sql, err)
		}
	}
	s := &Service{db: db, logger: zap.NewNop(), config: &config.Config{AgentLivenessTimeout: "10m"}}
	h.svc = s
	caller := ada
	h.as = &caller
	h.router = gin.New()
	api := h.router.Group("/api/v1/access", func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: h.orgID}))
		c.Set("user_id", *h.as)
		c.Next()
	})
	api.POST("/my/diagnose", s.handleMyDiagnose)
	return h, ada, bo
}

func (h *diagnoseHarness) agent(agentID, owner, status, compliance, lastReport, tunnelState string) {
	h.t.Helper()
	h.exec(`INSERT INTO enrolled_agents (org_id, agent_id, device_id, auth_token_hash, status, compliance_status, enrolled_by_user_id, last_report_at, tunnel_status)
	        VALUES ($1::uuid, $2::text, $2::text, md5($2::text), $3, $4, $5::uuid, NOW() - $6::interval,
	                CASE WHEN $7 = '' THEN NULL ELSE jsonb_build_object('state', $7::text) END)`,
		h.orgID, agentID, status, compliance, owner, lastReport, tunnelState)
}

func (h *diagnoseHarness) bundle(agentID, age string, failing ...string) {
	h.t.Helper()
	b := diagnose.BundleFromCodes(failing)
	doc, _ := json.Marshal(b)
	h.exec(`INSERT INTO agent_diagnostics (org_id, agent_id, bundle, collected_at)
	        VALUES ($1::uuid, $2, jsonb_set($3::jsonb, '{collected_at}', to_jsonb(NOW() - $4::interval)), NOW() - $4::interval)`,
		h.orgID, agentID, string(doc), age)
}

func (h *diagnoseHarness) diagnose(agentID string) (int, MyDiagnosis) {
	h.t.Helper()
	var body *bytes.Reader
	if agentID == "" {
		body = bytes.NewReader(nil)
	} else {
		raw, _ := json.Marshal(map[string]string{"agent_id": agentID})
		body = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/access/my/diagnose", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	var out MyDiagnosis
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestMyDiagnose(t *testing.T) {
	h, ada, bo := newDiagnoseHarness(t, "my-diagnose-org")

	// No device at all.
	code, out := h.diagnose("")
	if code != http.StatusOK || out.AgentID != "" || out.Verdict.Primary() != diagnose.CauseNoDevice {
		t.Fatalf("with no device: %d %+v", code, out)
	}

	h.agent("ada-old", ada, "active", "compliant", "3 hours", "")
	h.agent("ada-new", ada, "active", "compliant", "1 minute", "degraded")
	h.agent("ada-gone", ada, "revoked", "compliant", "2 days", "")
	h.agent("bo-pc", bo, "active", "compliant", "1 minute", "")

	// The newest-reporting device is the one judged, from its last report.
	code, out = h.diagnose("")
	if code != http.StatusOK || out.AgentID != "ada-new" || out.Verdict.Primary() != diagnose.CauseTunnelDown || out.BundleAt != nil {
		t.Errorf("default device: %d %+v", code, out)
	}
	// The device is there and has sent no bundle: it is asked for one, once.
	waiting := func(agentID string) (n int) {
		h.t.Helper()
		if err := h.pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM agent_commands WHERE agent_id = $1 AND kind = 'diagnose' AND status = 'queued'`, agentID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if !out.BundleRequested || waiting("ada-new") != 1 {
		t.Errorf("a live device with no bundle: requested=%v, %d waiting", out.BundleRequested, waiting("ada-new"))
	}
	if _, out = h.diagnose("ada-new"); !out.BundleRequested || waiting("ada-new") != 1 {
		t.Errorf("asking again: requested=%v, %d waiting, want one command still", out.BundleRequested, waiting("ada-new"))
	}
	// A named device of the caller's. It is silent: asking it would wait for
	// nothing.
	if code, out = h.diagnose("ada-old"); code != http.StatusOK || out.Verdict.Primary() != diagnose.CauseDeviceOffline {
		t.Errorf("silent device: %d %+v", code, out)
	}
	if out.BundleRequested || waiting("ada-old") != 0 {
		t.Errorf("a silent device was asked for a bundle")
	}
	if code, out = h.diagnose("ada-gone"); code != http.StatusOK || out.Verdict.Primary() != diagnose.CauseDeviceRevoked {
		t.Errorf("revoked device: %d %+v", code, out)
	}
	// Someone else's device, and one that does not exist, answer alike.
	if code, _ = h.diagnose("bo-pc"); code != http.StatusNotFound {
		t.Errorf("another user's device answered %d, want 404", code)
	}
	if code, _ = h.diagnose("no-such-agent"); code != http.StatusNotFound {
		t.Errorf("a missing device answered %d, want 404", code)
	}

	// A fresh bundle from the device's own doctor outranks the last report.
	h.bundle("ada-new", "2 minutes", "DNS_FAIL")
	code, out = h.diagnose("ada-new")
	if code != http.StatusOK || out.Verdict.Primary() != diagnose.CauseDNSFail || out.BundleAt == nil || out.BundleRequested {
		t.Errorf("with a fresh bundle: %d %+v", code, out)
	}
	// An old one is not used, and the answer says so.
	h.bundle("ada-old", "2 hours", "DNS_FAIL")
	h.exec(`UPDATE agent_diagnostics SET created_at = NOW() - interval '2 hours' WHERE agent_id = 'ada-old'`)
	code, out = h.diagnose("ada-old")
	if code != http.StatusOK || !out.Verdict.BundleStale || out.BundleAt != nil || out.Verdict.Primary() != diagnose.CauseDeviceOffline {
		t.Errorf("with a stale bundle: %d %+v", code, out)
	}

	// The other user sees their own device, healthy, and none of the caller's.
	*h.as = bo
	if code, out = h.diagnose(""); code != http.StatusOK || out.AgentID != "bo-pc" || !out.Verdict.Healthy {
		t.Errorf("the other user: %d %+v", code, out)
	}
	if code, _ = h.diagnose("ada-new"); code != http.StatusNotFound {
		t.Errorf("the other user reading the caller's device answered %d", code)
	}
}
