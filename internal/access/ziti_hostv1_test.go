package access

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// newTestZitiManager constructs a ZitiManager pointed at baseURL with a
// no-op logger and the standard HTTP client, mirroring what the reconciler
// tests do (see ziti_reconciler_test.go line 85-86). The configTypeCache is
// pre-seeded so resolveConfigTypeID does not make a live request.
func newTestZitiManager(t *testing.T, baseURL string) *ZitiManager {
	t.Helper()
	return &ZitiManager{
		logger:          zap.NewNop(),
		mgmtToken:       "fake",
		mgmtClient:      &http.Client{},
		cfg:             &config.Config{ZitiCtrlURL: baseURL},
		initialized:     true,
		configTypeCache: map[string]string{"host.v1": "NH5p4FpGR"},
	}
}

func TestCreateHostV1ConfigFixedOmitsForwardKeys(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/edge/management/v1/configs" && r.Method == "POST" {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &gotBody)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"cfg-1"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	zm := newTestZitiManager(t, srv.URL)
	id, err := zm.CreateHostV1ConfigFixed(context.Background(), "psm-zt-host", "192.168.152.112", 443)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "cfg-1" {
		t.Fatalf("want config id cfg-1, got %q", id)
	}
	data, _ := gotBody["data"].(map[string]interface{})
	if data == nil {
		t.Fatalf("config body missing data object: %+v", gotBody)
	}
	for _, forbidden := range []string{"forwardProtocol", "forwardAddress", "forwardPort", "allowedProtocols", "allowedAddresses", "allowedPortRanges"} {
		if _, present := data[forbidden]; present {
			t.Fatalf("fixed host.v1 config must omit %q; got %+v", forbidden, data)
		}
	}
	if data["protocol"] != "tcp" || data["address"] != "192.168.152.112" || data["port"].(float64) != 443 {
		t.Fatalf("fixed target wrong: %+v", data)
	}
}

func TestEnsureRouterRoleAttributePatchesEachRouter(t *testing.T) {
	patched := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/edge/management/v1/edge-routers" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"data":[{"id":"r1","roleAttributes":[]},{"id":"r2","roleAttributes":["x"]}]}`))
		case r.Method == "PATCH":
			id := r.URL.Path[len("/edge/management/v1/edge-routers/"):]
			patched[id] = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	zm := newTestZitiManager(t, srv.URL)
	if err := zm.EnsureRouterRoleAttribute(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !patched["r1"] || !patched["r2"] {
		t.Fatalf("expected both routers patched with #ziti-routers, got %+v", patched)
	}
}
