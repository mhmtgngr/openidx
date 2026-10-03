package access

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/common/resilience"
	"go.uber.org/zap"
)

// Regression: Guacamole's connection-update handler dereferences the request's
// "attributes" map unconditionally. UpdateConnection used to omit it, so newer
// Guacamole builds returned HTTP 500 ("Cannot invoke Map.get because attributes
// is null") on every reconnect to an existing PAM connection. The PUT body must
// carry a non-null attributes object, symmetric with CreateConnection.
func TestUpdateConnectionSendsNonNilAttributes(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &gotBody)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	gc := &GuacamoleClient{
		baseURL:    srv.URL,
		dataSource: "postgresql",
		authToken:  "test-token",
		httpClient: resilience.NewResilientHTTPClient(srv.Client(), guacBreaker("test", zap.NewNop())),
	}

	if err := gc.UpdateConnection("42", "pam-x", "rdp", "10.0.0.1", 3389, map[string]string{"username": "u"}); err != nil {
		t.Fatalf("UpdateConnection returned error: %v", err)
	}
	attrs, ok := gotBody["attributes"].(map[string]interface{})
	if !ok || attrs == nil {
		t.Fatalf("update body must include a non-null attributes map; got %#v", gotBody["attributes"])
	}
	if attrs["max-connections"] == nil {
		t.Errorf("attributes should carry max-connections (mirrors CreateConnection); got %#v", attrs)
	}
}

// The session-history DTO must expose the legal-hold + recording availability
// booleans the console needs to render place-vs-release controls.
func TestGuacSessionRowExposesLegalHoldFlags(t *testing.T) {
	b, _ := json.Marshal(GuacSessionRow{})
	s := string(b)
	for _, want := range []string{"recording_available", "on_legal_hold"} {
		if !strings.Contains(s, want) {
			t.Fatalf("GuacSessionRow is missing JSON field %q: %s", want, b)
		}
	}
}

// The session-history DTO must expose only a transcript/recording availability
// boolean — never the on-disk recording_path or transcript_path.
func TestGuacSessionRowHidesFilePaths(t *testing.T) {
	b, _ := json.Marshal(GuacSessionRow{})
	lower := strings.ToLower(string(b))
	for _, forbidden := range []string{"recording_path", "transcript_path"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("GuacSessionRow exposes a file-path field %q: %s", forbidden, b)
		}
	}
}
