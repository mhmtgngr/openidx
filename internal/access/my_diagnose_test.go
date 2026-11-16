package access

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/diagnose"
)

func TestDecodeSupportCode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw, err := readAgentSupportCodes()
	if err != nil {
		t.Fatal(err)
	}
	var tunnelDown string
	for code, names := range raw {
		if len(names) == 1 && names[0] == "TUNNEL_DOWN" {
			tunnelDown = code
		}
	}
	if tunnelDown == "" {
		t.Fatal("the agent's golden file has no TUNNEL_DOWN code")
	}
	s := &Service{logger: zap.NewNop()}
	r := gin.New()
	r.POST("/diagnose/decode", s.handleDecodeSupportCode)
	post := func(body string) (int, map[string]any) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/diagnose/decode", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	spoken := strings.ToLower(strings.ReplaceAll(tunnelDown, "-", " "))
	code, out := post(`{"code":"` + spoken + `"}`)
	verdict, _ := out["verdict"].(map[string]any)
	causes, _ := verdict["causes"].([]any)
	if code != http.StatusOK || len(causes) != 1 || causes[0].(map[string]any)["code"] != diagnose.CauseTunnelDown {
		t.Errorf("decode answered %d %v", code, out)
	}
	for _, bad := range []string{`{"code":"OX1-AAAA-AAAA"}`, `{"code":""}`, `{}`, `not json`} {
		if code, _ := post(bad); code != http.StatusBadRequest {
			t.Errorf("%s answered %d, want 400", bad, code)
		}
	}
}

func TestDeviceFacts(t *testing.T) {
	s := &Service{}
	now := time.Now()
	recent, old := now.Add(-time.Minute), now.Add(-time.Hour)
	yes := true
	cases := []struct {
		z      DeviceZiti
		status string
		live   bool
		comp   *bool
	}{
		{DeviceZiti{Status: "active", LastReportAt: &recent, ComplianceStatus: "compliant"}, diagnose.DeviceActive, true, &yes},
		{DeviceZiti{Status: "active", LastReportAt: &old, ComplianceStatus: "unknown"}, diagnose.DeviceActive, false, nil},
		{DeviceZiti{Status: "active", Live: &yes, LastReportAt: &old}, diagnose.DeviceActive, true, nil},
		{DeviceZiti{Status: "retired"}, diagnose.DeviceRevoked, false, nil},
		{DeviceZiti{Status: "revoked"}, diagnose.DeviceRevoked, false, nil},
		{DeviceZiti{Status: "suspended", ComplianceStatus: "grace_period"}, diagnose.DeviceSuspended, false, nil},
		{DeviceZiti{Status: "pending"}, diagnose.DevicePending, false, nil},
	}
	for _, tc := range cases {
		f := s.deviceFacts(&tc.z, now)
		if f.Status != tc.status || f.Live != tc.live || (f.Compliant == nil) != (tc.comp == nil) {
			t.Errorf("%+v → %+v", tc.z, f)
		}
	}
	no := false
	if f := s.deviceFacts(&DeviceZiti{Status: "active", ComplianceStatus: "non_compliant", CredentialRefused: true}, now); f.Compliant == nil || *f.Compliant != no || !f.CredentialRefused {
		t.Errorf("non-compliant, refused device → %+v", f)
	}
}
