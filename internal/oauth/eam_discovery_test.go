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

// The Entra external authentication method's provider document: what Entra
// reads to learn where to send the person and where the keys are. Off unless
// EAM_ENABLED, and then exactly the shape Entra accepts.
func eamDiscoveryRouter(enabled bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	s := &Service{config: &config.Config{EAMEnabled: enabled, EAMClientID: "app-1"}, logger: zap.NewNop(), issuer: "https://idp.example.test/"}
	r := gin.New()
	r.GET("/eam/.well-known/openid-configuration", s.handleEAMDiscovery)
	r.GET("/eam/jwks", s.handleEAMJWKS)
	r.GET("/eam/authorize", s.handleEAMAuthorize)
	r.POST("/eam/verify", s.handleEAMVerify)
	return r
}

func TestEAMIsOffUnlessEnabled(t *testing.T) {
	r := eamDiscoveryRouter(false)
	for _, p := range []string{"/eam/.well-known/openid-configuration", "/eam/jwks", "/eam/authorize"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s with EAM off = %d, want 404", p, w.Code)
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/eam/verify", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("/eam/verify with EAM off = %d, want 404", w.Code)
	}
}

func TestEAMDiscoveryDocument(t *testing.T) {
	w := httptest.NewRecorder()
	eamDiscoveryRouter(true).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/eam/.well-known/openid-configuration", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("discovery = %d %s", w.Code, w.Body.String())
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	const iss = "https://idp.example.test/eam"
	for k, want := range map[string]string{
		"issuer":                 iss,
		"authorization_endpoint": iss + "/authorize",
		"jwks_uri":               iss + "/jwks",
	} {
		if doc[k] != want {
			t.Errorf("%s = %v, want %s", k, doc[k], want)
		}
	}
	for k, want := range map[string]string{
		"response_types_supported":              "id_token",
		"response_modes_supported":              "form_post",
		"scopes_supported":                      "openid",
		"id_token_signing_alg_values_supported": "RS256",
	} {
		l, _ := doc[k].([]interface{})
		if len(l) != 1 || l[0] != want {
			t.Errorf("%s = %v, want [%s]", k, doc[k], want)
		}
	}
	claims, _ := doc["claims_supported"].([]interface{})
	if len(claims) != 3 || claims[0] != "sub" || claims[1] != "acr" || claims[2] != "amr" {
		t.Errorf("claims_supported = %v, want [sub acr amr]", claims)
	}
}

func TestEAMFactorRules(t *testing.T) {
	strict := &Service{config: &config.Config{EAMRequireStrongFactors: true}}
	got := strict.eamAllowedMethods([]string{"totp", "sms", "email", "webauthn", "push", "backup", "bypass"})
	if len(got) != 3 || got[0] != "totp" || got[1] != "webauthn" || got[2] != "push" {
		t.Errorf("strong-only methods = %v, want [totp webauthn push]", got)
	}
	loose := &Service{config: &config.Config{EAMRequireStrongFactors: false}}
	if got := loose.eamAllowedMethods([]string{"sms", "backup"}); len(got) != 1 || got[0] != "sms" {
		t.Errorf("relaxed methods = %v, want [sms]", got)
	}
	for m, want := range map[string]string{"totp": "otp", "webauthn": "fido", "push": "pop"} {
		if eamAMR(m) != want {
			t.Errorf("amr(%s) = %q, want %q", m, eamAMR(m), want)
		}
	}
	if !eamClaimsAcceptable(`{"id_token":{"acr":{"essential":true,"values":["possessionorinherence"]}}}`) {
		t.Error("Entra's own claims request refused")
	}
	if eamClaimsAcceptable(`{"id_token":{"acr":{"values":["knowledge"]}}}`) {
		t.Error("an acr this provider does not assert was accepted")
	}
}
