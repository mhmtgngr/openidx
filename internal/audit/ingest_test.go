package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// POST /api/v1/audit/events refused every event the product sent it.
//
// audit_events.id is `uuid NOT NULL DEFAULT gen_random_uuid()`, and LogEvent's
// INSERT names the column, so the default never applied: an event that arrived
// without an id put "" into a uuid column and Postgres refused the write with
// `invalid input syntax for type uuid`. The endpoint answered 500.
//
// Its only caller in the whole product is internal/access.logAuditEvent, and it
// has never sent an id. So every audit event access-service emitted — every PAM
// credential reveal, every entry created or deleted, every grant added, every
// proxy allow and deny — was refused and dropped, on every install, and the
// only trace was one warning line in the emitting service's log.
//
// This drives the ingest handler exactly as access-service calls it: no id.
func TestAnEventWithNoIDIsAcceptedAndGivenOne(t *testing.T) {
	db, cleanup := setupComplianceSchemaDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const orgA = "00000000-0000-0000-0000-000000000010"

	gin.SetMode(gin.TestMode)
	svc := &Service{db: db, logger: zap.NewNop()}
	router := gin.New()
	router.POST("/audit/events", func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: orgA}))
		svc.handleLogEvent(c)
	})

	// The body access-service builds, field for field: no id, and no
	// server-assigned anything.
	body := `{
		"event_type":  "authorization",
		"category":    "access_proxy",
		"action":      "pam.entry_revealed",
		"outcome":     "success",
		"target_id":   "b3f1c0de-0000-4000-8000-00000000f00d",
		"target_type": "pam_entry",
		"actor_id":    "77777777-0000-0000-0000-0000000000d1",
		"actor_ip":    "203.0.113.9",
		"details":     {"reason": "on-call incident 4471"}
	}`

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/audit/events", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("ingest answered %d for an event with no id: %s\n"+
			"This is the shape access-service sends. A 500 here means the audit trail "+
			"silently loses every event it emits.", w.Code, w.Body.String())
	}

	var echoed ServiceAuditEvent
	if err := json.Unmarshal(w.Body.Bytes(), &echoed); err != nil {
		t.Fatalf("decode the 201 body %q: %v", w.Body.String(), err)
	}
	if echoed.ID == "" {
		t.Error("the response carries no id; the caller has no handle on the event it just filed")
	}

	var stored, actor string
	if err := db.Pool.QueryRow(orgctx.WithBypassRLS(context.Background()), `
		SELECT id::text, COALESCE(actor_id, '') FROM audit_events
		WHERE action = 'pam.entry_revealed'`).Scan(&stored, &actor); err != nil {
		t.Fatalf("the event was answered 201 and is not in the trail: %v", err)
	}
	if stored != echoed.ID {
		t.Errorf("the row's id is %s and the response said %s", stored, echoed.ID)
	}
	if actor != "77777777-0000-0000-0000-0000000000d1" {
		t.Errorf("actor_id = %q; an audit row that does not name who acted answers the wrong half "+
			"of every question asked of it", actor)
	}
}

// An id the caller does supply is kept, so a caller that wants to correlate its
// own record with the trail still can.
func TestAnEventWithAnIDKeepsIt(t *testing.T) {
	db, cleanup := setupComplianceSchemaDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const (
		orgA    = "00000000-0000-0000-0000-000000000010"
		chosen  = "5c0de000-0000-4000-8000-0000000000a1"
		theCall = `{"id":"` + chosen + `","event_type":"authorization","category":"access_proxy",` +
			`"action":"pam.entry_revealed","outcome":"success","target_type":"pam_entry"}`
	)

	gin.SetMode(gin.TestMode)
	svc := &Service{db: db, logger: zap.NewNop()}
	router := gin.New()
	router.POST("/audit/events", func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: orgA}))
		svc.handleLogEvent(c)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/audit/events", strings.NewReader(theCall))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("ingest answered %d: %s", w.Code, w.Body.String())
	}

	var stored string
	if err := db.Pool.QueryRow(orgctx.WithBypassRLS(context.Background()),
		`SELECT id::text FROM audit_events WHERE action = 'pam.entry_revealed'`).Scan(&stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored != chosen {
		t.Errorf("the caller supplied id %s and the trail stored %s", chosen, stored)
	}
}
