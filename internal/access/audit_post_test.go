package access

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The audit POST carries the tenant, and stops throwing the answer away.
//
// This helper is how every proxy and PAM event reaches the audit trail --
// pam.entry_revealed, guacamole.recording_downloaded, proxy_access_denied. It
// sent no tenant signal at all, and the ingest endpoint is server-to-server
// with no JWT: cmd/audit-service mounts TenantResolver globally, so its JWT and
// X-Org-ID steps cannot fire and every one of these events landed on the
// default-org fallback. On a multi-tenant install the most sensitive reads in
// the product were missing from the audit log of the tenant they belonged to
// and present in another's.
//
// It also discarded the response. handleLogEvent answers 400 for a body it
// refuses and 500 when the write fails; both were closed and forgotten, so a
// rejected audit event vanished with no line anywhere.
func TestAuditPostCarriesTheTenantAndReadsTheAnswer(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var mu sync.Mutex
	var gotSlug, gotType string
	var status = http.StatusCreated

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var event map[string]interface{}
		_ = json.Unmarshal(body, &event)
		mu.Lock()
		gotSlug = r.Header.Get("X-Org-Slug")
		gotType, _ = event["action"].(string)
		code := status
		mu.Unlock()
		w.WriteHeader(code)
	}))
	defer srv.Close()

	core, logs := observer.New(zapcore.WarnLevel)
	svc := &Service{auditURL: srv.URL, logger: zap.New(core)}

	post := func(action string) {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(),
			orgctx.Org{ID: "00000000-0000-0000-0000-0000000000c9", Slug: "acme"}))
		svc.logAuditEvent(c, action, "entry-1", "pam_entry", nil)
	}

	// The write is fire-and-forget on a goroutine, so wait for the server to
	// have seen it rather than sleeping a fixed amount.
	waitFor := func(cond func() bool) bool {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			ok := cond()
			mu.Unlock()
			if ok {
				return true
			}
			time.Sleep(5 * time.Millisecond)
		}
		return false
	}

	post("pam.entry_revealed")
	if !waitFor(func() bool { return gotType == "pam.entry_revealed" }) {
		t.Fatal("the audit service never received the event")
	}
	mu.Lock()
	slug := gotSlug
	mu.Unlock()
	if slug != "acme" {
		t.Errorf("X-Org-Slug = %q, want acme: without it the event is filed under the "+
			"default organisation and is invisible to the tenant it belongs to", slug)
	}
	if n := logs.FilterMessageSnippet("refused").Len(); n != 0 {
		t.Errorf("a 201 produced %d warning(s); only a refusal should", n)
	}

	// And a refusal is heard.
	mu.Lock()
	status = http.StatusBadRequest
	gotType = ""
	mu.Unlock()

	post("guacamole.recording_downloaded")
	if !waitFor(func() bool { return gotType == "guacamole.recording_downloaded" }) {
		t.Fatal("the audit service never received the second event")
	}
	if !waitFor(func() bool { return logs.FilterMessageSnippet("refused").Len() > 0 }) {
		t.Error("the audit service refused the event with 400 and nothing was logged; " +
			"a dropped audit row is the one loss that must never be silent")
	}
}
