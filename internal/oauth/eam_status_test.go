package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// The console card reads what to register in Entra from the status API: the
// same issuer and endpoints the discovery document advertises, and the
// configured tenants, trimmed.
func TestEAMStatusReportsRegistrationValues(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{config: &config.Config{EAMEnabled: true, EAMClientID: "app-1",
		EAMTenantIDs: " t-1 , ,t-2", EAMRequireStrongFactors: true},
		logger: zap.NewNop(), issuer: "https://idp.example.test/"}
	r := gin.New()
	r.GET("/api/v1/oauth/eam/status", s.handleEAMStatus)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oauth/eam/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var st eamStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	iss := s.eamIssuer()
	if !st.Enabled || st.Issuer != iss || st.DiscoveryURL != iss+"/.well-known/openid-configuration" ||
		st.JWKSURL != iss+"/jwks" || st.AuthorizeURL != iss+"/authorize" || st.ClientID != "app-1" || !st.RequireStrongFactors {
		t.Errorf("status = %+v", st)
	}
	if len(st.TenantIDs) != 2 || st.TenantIDs[0] != "t-1" || st.TenantIDs[1] != "t-2" {
		t.Errorf("tenants = %v", st.TenantIDs)
	}
	if st.Keys == nil {
		t.Error("keys must be an empty list, not null")
	}
}

// Off, the status still answers (the console says it is off) with no tenants.
func TestEAMStatusWhenOff(t *testing.T) {
	s := &Service{config: &config.Config{}, logger: zap.NewNop(), issuer: "https://idp.example.test"}
	st := s.eamStatusView()
	if st.Enabled || len(st.TenantIDs) != 0 {
		t.Errorf("status = %+v", st)
	}
}
