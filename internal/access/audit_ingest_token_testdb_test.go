package access

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/openidx/openidx/internal/audit"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
	"github.com/openidx/openidx/internal/organization"
)

// THE PROXY'S AUDIT EVENTS REACH THE TRAIL WITH THE INTERNAL SERVICE TOKEN.
//
// The audit service now writes an event only for an OpenIDX service that
// presents INTERNAL_SERVICE_TOKEN, and access-service is the one service that
// posts events to it. This drives both sides as they run: logAuditEvent, the
// helper every PAM reveal and proxy decision goes through, posting to the
// audit service's own route table behind the tenant resolver, on a migrated
// database.
//
//   - with the token both services share, the event is filed under the
//     organization the action happened in;
//   - with none configured on the proxy, the audit service refuses it, nothing
//     is written, and the proxy says so in its log.
func TestTheProxysAuditEventsReachTheTrailWithTheInternalServiceToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := orgctx.WithBypassRLS(context.Background())
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	org := orgctx.Org{Slug: "proxy-audit-" + suffix}
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, org.Slug).Scan(&org.ID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}

	// The audit service, as cmd/audit-service mounts it.
	const token = "proxy-audit-shared-internal-token"
	auditCfg := &config.Config{InternalServiceToken: token}
	r := gin.New()
	r.Use(middleware.TenantResolver(organization.NewOrgLookup(organization.NewService(db, nil, auditCfg, zap.NewNop())),
		middleware.TenantResolverConfig{DefaultOrgFallback: true, DefaultOrgID: middleware.DefaultOrgID, Logger: zap.NewNop()}))
	audit.RegisterRoutes(r, audit.NewService(db, nil, auditCfg, zap.NewNop()))
	auditSrv := httptest.NewServer(r)
	defer auditSrv.Close()

	// emit runs the proxy's audit helper for a request in org, and waits for
	// the audit service's answer to be logged or the event to land.
	emit := func(proxyToken, action string) (*observer.ObservedLogs, int) {
		t.Helper()
		core, logs := observer.New(zapcore.WarnLevel)
		svc := &Service{auditURL: auditSrv.URL, logger: zap.New(core),
			config: &config.Config{InternalServiceToken: proxyToken}}
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), org))
		svc.logAuditEvent(c, action, "entry-1", "pam_entry", map[string]interface{}{"test": suffix})

		deadline := time.Now().Add(5 * time.Second)
		for {
			var n int
			if err := db.Pool.QueryRow(ctx,
				`SELECT COUNT(*) FROM audit_events WHERE action = $1 AND org_id = $2::uuid`, action, org.ID).Scan(&n); err != nil {
				t.Fatalf("count %s: %v", action, err)
			}
			if n > 0 || logs.Len() > 0 || time.Now().After(deadline) {
				return logs, n
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	if logs, n := emit(token, "pam.entry_revealed."+suffix); n != 1 {
		t.Fatalf("with the shared token the event did not reach the organization's trail (%d rows); logged: %v",
			n, logs.All())
	}

	logs, n := emit("", "pam.entry_revealed.untokened."+suffix)
	if n != 0 {
		t.Errorf("with no token configured on the proxy the audit service still wrote %d event(s)", n)
	}
	refused := logs.FilterMessage("Audit event was refused by the audit service").All()
	if len(refused) != 1 {
		t.Fatalf("the refusal was not logged by the proxy: %v", logs.All())
	}
	if got := refused[0].ContextMap()["status"]; got != int64(http.StatusUnauthorized) {
		t.Errorf("the refusal carried status %v, want 401", got)
	}
	if strings.Contains(fmt.Sprint(refused[0].ContextMap()), token) {
		t.Error("the refusal's log line carries the token")
	}
}
