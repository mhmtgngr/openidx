package access

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/resilience"
	"github.com/openidx/openidx/internal/migrations"
)

// fakeGuacBroker is a Guacamole server running the given active connections. It
// answers the list, the terminate PATCH and the monitor-link calls, and
// records what it was asked to end and to share.
type fakeGuacBroker struct {
	*httptest.Server
	mu         sync.Mutex
	active     map[string]string // active connection id -> connection identifier
	terminated []string
	shared     []string
}

func newFakeGuacBroker(t *testing.T, active map[string]string) *fakeGuacBroker {
	t.Helper()
	b := &fakeGuacBroker{active: active}
	b.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/activeConnections") && r.Method == http.MethodGet:
			out := map[string]map[string]any{}
			for id, conn := range b.active {
				out[id] = map[string]any{"identifier": id, "connectionIdentifier": conn, "username": "broker", "startDate": 1}
			}
			_ = json.NewEncoder(w).Encode(out)
		case strings.HasSuffix(p, "/activeConnections") && r.Method == http.MethodPatch:
			var ops []struct{ Path string }
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &ops)
			for _, op := range ops {
				id := strings.TrimPrefix(op.Path, "/")
				b.terminated = append(b.terminated, id)
				delete(b.active, id)
			}
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(p, "/sharingProfiles") && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{}`))
		case strings.HasSuffix(p, "/sharingProfiles") && r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"identifier":"sp-1"}`))
		case strings.Contains(p, "/sharingCredentials/"):
			id := strings.Split(strings.SplitN(p, "/activeConnections/", 2)[1], "/")[0]
			b.shared = append(b.shared, id)
			_, _ = w.Write([]byte(`{"values":{"key":"k-` + id + `"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(b.Close)
	return b
}

func (b *fakeGuacBroker) client() *GuacamoleClient {
	return &GuacamoleClient{
		baseURL: b.URL, publicBaseURL: b.URL, dataSource: "postgresql", authToken: "stub-token",
		httpClient: resilience.NewResilientHTTPClient(&http.Client{Timeout: 5 * time.Second}, guacBreaker("test", zap.NewNop())),
		logger:     zap.NewNop(), component: "guacamole",
	}
}

// The administrator's Guacamole session page covers both brokers. It used
// the direct broker only, so a session on the OpenZiti overlay broker --
// every external user's, and every one under PAM_REQUIRE_ZTNA=enforce -- was
// not listed, and could not be ended or watched from it. On the migrated
// schema, against two fake brokers:
//
//   - the list shows every broker's sessions, each with its broker;
//   - ending an overlay session ends it on the overlay broker, and the direct
//     broker is not asked to;
//   - a monitor link for an overlay session is minted on the overlay broker;
//   - a session no broker runs answers 404.
func TestTheAdminSessionPageCoversTheOverlayBroker(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	direct := newFakeGuacBroker(t, map[string]string{"direct-1": "conn-d"})
	overlay := newFakeGuacBroker(t, map[string]string{"ziti-1": "conn-z", "ziti-2": "conn-z2"})
	svc := &Service{db: db, config: &config.Config{}, logger: zap.NewNop(),
		guacamoleClient: direct.client(), guacamoleZitiClient: overlay.client()}

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Set("user_id", "00000000-0000-0000-0000-0000000000a1")
		c.Set("roles", []string{"admin"})
		c.Next()
	})
	r.GET("/guacamole/sessions", svc.handleListActiveGuacSessions)
	r.POST("/guacamole/sessions/:id/terminate", svc.handleTerminateGuacSession)
	r.POST("/guacamole/sessions/:id/share", svc.handleShareGuacSession)
	call := func(method, path string) (int, map[string]any) {
		t.Helper()
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(`{}`)))
		out := map[string]any{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	code, body := call(http.MethodGet, "/guacamole/sessions")
	brokerOf := map[string]string{}
	if list, ok := body["sessions"].([]any); ok {
		for _, s := range list {
			m := s.(map[string]any)
			brokerOf[m["identifier"].(string)], _ = m["broker"].(string)
		}
	}
	if code != http.StatusOK || brokerOf["direct-1"] != "direct" || brokerOf["ziti-1"] != "ziti" || brokerOf["ziti-2"] != "ziti" {
		t.Errorf("the session list: %d, brokers %v; want all three sessions, each with its broker", code, brokerOf)
	}

	if code, body := call(http.MethodPost, "/guacamole/sessions/ziti-1/share"); code != http.StatusOK || body["share_url"] == nil {
		t.Errorf("a monitor link for an overlay session: %d %v; want 200 with a link", code, body)
	}
	if len(overlay.shared) != 1 || overlay.shared[0] != "ziti-1" || len(direct.shared) != 0 {
		t.Errorf("the monitor link was minted on overlay %v, direct %v; want the overlay broker only", overlay.shared, direct.shared)
	}

	if code, body := call(http.MethodPost, "/guacamole/sessions/ziti-1/terminate"); code != http.StatusOK {
		t.Errorf("ending an overlay session: %d %v; want 200", code, body)
	}
	if len(overlay.terminated) != 1 || overlay.terminated[0] != "ziti-1" || len(direct.terminated) != 0 {
		t.Errorf("ended on overlay %v, direct %v; want the overlay broker only", overlay.terminated, direct.terminated)
	}
	if code, _ := call(http.MethodPost, "/guacamole/sessions/direct-1/terminate"); code != http.StatusOK || len(direct.terminated) != 1 {
		t.Errorf("ending a direct session: %d, direct ended %v", code, direct.terminated)
	}
	if code, _ := call(http.MethodPost, "/guacamole/sessions/nowhere/terminate"); code != http.StatusNotFound {
		t.Errorf("ending a session no broker runs: %d; want 404", code)
	}
}
