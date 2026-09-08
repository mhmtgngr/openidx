package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/openidx/openidx/internal/common/database"
)

// An overlay identity nothing in the product names.
//
// Enrolling an agent and approving one both create a Ziti identity carrying
// #openidx-agent -- which is what puts the device on the overlay -- and then
// write one column, enrolled_agents.ziti_identity_id, tying it to the agent
// row. Both writes were unchecked.
//
// The consequence is the reason this class matters at all: removing the agent
// reads that column to find the identity to delete. Without it the row goes and
// the identity stays, still carrying #openidx-agent, still on the network, and
// invisible to every console that lists agents. It is recoverable -- the next
// enrolment finds the orphan by name -- but only if somebody enrols that agent
// again, which nobody has a reason to do.
//
// The two halves report differently because they can. Approval is a request an
// admin is waiting on, so the response carries a warning. Enrolment fills a
// device-facing result with no room for one, so the report is a loud log; these
// tests hold each to what it can actually do.

const agentLinkSchema = `
CREATE TABLE IF NOT EXISTS enrolled_agents (
    agent_id VARCHAR(255) PRIMARY KEY,
    status VARCHAR(32) DEFAULT 'pending',
    ziti_identity_id VARCHAR(255),
    updated_at TIMESTAMPTZ DEFAULT NOW());`

const linkedAgent = "agent-77"

// agentLinkFixture gives a handler whose controller creates identities happily,
// with one pending agent waiting to be approved.
func agentLinkFixture(t *testing.T) (*AgentAPIHandler, *zitiStub, *database.PostgresDB, *observer.ObservedLogs, context.Context, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, nil, nil, nil, nil, func() {}
	}
	gin.SetMode(gin.TestMode)
	ctx := context.Background()

	if _, err := db.Pool.Exec(ctx, agentLinkSchema); err != nil {
		cleanup()
		t.Fatalf("schema: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO enrolled_agents (agent_id, status) VALUES ($1, 'pending')`, linkedAgent); err != nil {
		cleanup()
		t.Fatalf("seed the agent: %v", err)
	}

	stub := newZitiStub(t)
	stub.on("POST /edge/management/v1/identities", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"id":"ident-agent-77","enrollment":{"ott":{"jwt":"an-enrolment-jwt"}}}}`))
	})

	core, logs := observer.New(zap.ErrorLevel)
	h := &AgentAPIHandler{
		logger: zap.New(core),
		db:     db,
		zm:     zitiManagerAgainst(t, stub, db),
	}
	return h, stub, db, logs, ctx, cleanup
}

func approveAgent(t *testing.T, h *AgentAPIHandler, ctx context.Context) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/agents/"+linkedAgent+"/approve", nil).WithContext(ctx)
	c.Params = gin.Params{{Key: "agent_id", Value: linkedAgent}}
	h.HandleApproveAgent(c)
	return w
}

func TestApprovingAnAgentLinksItsNewIdentityToTheAgentRow(t *testing.T) {
	h, stub, db, _, ctx, cleanup := agentLinkFixture(t)
	if h == nil {
		return
	}
	defer cleanup()

	w := approveAgent(t, h, ctx)
	if w.Code != http.StatusOK {
		t.Fatalf("approving a pending agent answered %d: %s (controller saw %v)",
			w.Code, w.Body.String(), stub.received())
	}
	if !strings.Contains(w.Body.String(), "an-enrolment-jwt") {
		t.Errorf("the approval did not hand back the enrolment JWT the device needs: %s", w.Body.String())
	}

	var identityID *string
	if err := db.Pool.QueryRow(ctx,
		`SELECT ziti_identity_id FROM enrolled_agents WHERE agent_id = $1`, linkedAgent).Scan(&identityID); err != nil {
		t.Fatalf("read the agent back: %v", err)
	}
	if identityID == nil || *identityID != "ident-agent-77" {
		t.Errorf("the agent row names identity %v; removing the agent looks up the identity to delete "+
			"through exactly this column", identityID)
	}
}

// The case the old code answered 200 to: the device is on the network and no
// agent record says so.
func TestAnApprovalThatCannotLinkTheIdentityWarnsInsteadOfReportingSuccess(t *testing.T) {
	h, stub, db, logs, ctx, cleanup := agentLinkFixture(t)
	if h == nil {
		return
	}
	defer cleanup()

	// Refuse only the link write: the status update to 'active' has to succeed,
	// because the identity is created after it.
	if _, err := db.Pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION refuse_identity_link() RETURNS trigger AS $$
		BEGIN
			IF NEW.ziti_identity_id IS DISTINCT FROM OLD.ziti_identity_id THEN
				RAISE EXCEPTION 'refused by test';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER refuse_identity_link_trg BEFORE UPDATE ON enrolled_agents
		FOR EACH ROW EXECUTE FUNCTION refuse_identity_link();`); err != nil {
		t.Fatalf("install the link refusal: %v", err)
	}

	w := approveAgent(t, h, ctx)
	if !strings.Contains(w.Body.String(), "could not be linked") {
		t.Errorf("the response does not warn that the agent and its network identity were not linked, "+
			"so the admin who approved it has no way to know: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "an-enrolment-jwt") {
		t.Errorf("the approval handed back an enrolment JWT for an identity no agent row names: %s",
			w.Body.String())
	}
	if !stub.saw("POST /edge/management/v1/identities") {
		t.Errorf("no identity was created on the controller, so this proves nothing about the split; "+
			"calls: %v", stub.received())
	}
	if logs.FilterMessageSnippet("could not link its new Ziti identity").Len() == 0 {
		t.Errorf("nothing was logged at error level about the unlinked identity; the operator who has to "+
			"go and remove it by hand has only this: %v", logs.All())
	}

	// The row really is unlinked — otherwise the warning describes a state this
	// test never produced.
	var identityID *string
	if err := db.Pool.QueryRow(ctx,
		`SELECT ziti_identity_id FROM enrolled_agents WHERE agent_id = $1`, linkedAgent).Scan(&identityID); err != nil {
		t.Fatalf("read the agent back: %v", err)
	}
	if identityID != nil {
		t.Errorf("the agent is linked to %q; the test's premise (the link write was refused) did not hold",
			*identityID)
	}
}

// Enrolment has no response field to carry a warning, so the report is the log.
// A test that did not check it would be testing that nothing happens.
func TestAnEnrolmentThatCannotLinkTheIdentitySaysSoLoudly(t *testing.T) {
	h, stub, db, logs, ctx, cleanup := agentLinkFixture(t)
	if h == nil {
		return
	}
	defer cleanup()
	refuseWrites(t, db, ctx, "enrolled_agents", "UPDATE")

	// The overlay is opt-in; without it ensureAgentZitiIdentity returns before
	// creating anything and the test would assert nothing.
	t.Setenv("ZITI_AGENT_OVERLAY_ENABLED", "true")

	result := issuedAgentCredentials{AgentID: linkedAgent, Status: "active"}
	h.ensureAgentZitiIdentity(ctx, linkedAgent, &result)

	if !stub.saw("POST /edge/management/v1/identities") {
		t.Fatalf("no identity was created on the controller; calls: %v", stub.received())
	}
	entries := logs.FilterMessageSnippet("could not link it to the agent row")
	if entries.Len() == 0 {
		t.Fatalf("the identity holds #openidx-agent on the overlay, no agent row names it, and nothing "+
			"was logged at error level: %v", logs.All())
	}
	// The identity id has to be in the record: it is the only handle an
	// operator has for the thing left behind.
	var named bool
	for _, f := range entries.All()[0].Context {
		if f.Key == "ziti_id" && f.String == "ident-agent-77" {
			named = true
		}
	}
	if !named {
		t.Errorf("the log record does not name the identity that was left on the overlay: %v",
			entries.All()[0].Context)
	}

	var identityID *string
	if err := db.Pool.QueryRow(ctx,
		`SELECT ziti_identity_id FROM enrolled_agents WHERE agent_id = $1`, linkedAgent).Scan(&identityID); err != nil {
		t.Fatalf("read the agent back: %v", err)
	}
	if identityID != nil {
		t.Errorf("the agent is linked to %q; the test's premise did not hold", *identityID)
	}
}
