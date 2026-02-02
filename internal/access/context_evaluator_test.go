package access

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func newTestService() *Service {
	logger, _ := zap.NewDevelopment()
	return &Service{logger: logger}
}

func baseRoute() *ProxyRoute {
	return &ProxyRoute{
		ID:          "route-1",
		Name:        "test-route",
		RequireAuth: true,
		Enabled:     true,
		MaxRiskScore: 100,
	}
}

func baseSession() *ProxySession {
	return &ProxySession{
		ID:        "sess-1",
		UserID:    "user-1",
		Email:     "test@example.com",
		Roles:     []string{"user"},
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}
}

func TestEvaluateAccessContext_IPThreatBlock(t *testing.T) {
	svc := newTestService()
	ac := &AccessContext{
		Session:    baseSession(),
		Route:      baseRoute(),
		ClientIP:   "1.2.3.4",
		UserAgent:  baseSession().UserAgent,
		IPBlocked:  true,
		IPThreatType: "brute_force",
		Timestamp:  time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	assert.False(t, decision.Allowed)
	assert.Equal(t, 100, decision.RiskScore)
	assert.Contains(t, decision.Reason, "blocked")
}

func TestEvaluateAccessContext_IPThreatNotBlocked(t *testing.T) {
	svc := newTestService()
	ac := &AccessContext{
		Session:      baseSession(),
		Route:        baseRoute(),
		ClientIP:     "1.2.3.4",
		UserAgent:    baseSession().UserAgent,
		IPThreatType: "suspicious",
		IPBlocked:    false,
		DeviceTrusted: true,
		Timestamp:    time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	assert.True(t, decision.Allowed)
	assert.GreaterOrEqual(t, decision.RiskScore, 30) // IP threat adds 30
}

func TestEvaluateAccessContext_GeoFenceAllow(t *testing.T) {
	svc := newTestService()
	route := baseRoute()
	route.AllowedCountries = []string{"US", "GB"}

	ac := &AccessContext{
		Session:       baseSession(),
		Route:         route,
		ClientIP:      "1.2.3.4",
		UserAgent:     baseSession().UserAgent,
		GeoCountry:    "US",
		DeviceTrusted: true,
		Timestamp:     time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	assert.True(t, decision.Allowed)
}

func TestEvaluateAccessContext_GeoFenceDeny(t *testing.T) {
	svc := newTestService()
	route := baseRoute()
	route.AllowedCountries = []string{"US", "GB"}

	ac := &AccessContext{
		Session:    baseSession(),
		Route:      route,
		ClientIP:   "1.2.3.4",
		UserAgent:  baseSession().UserAgent,
		GeoCountry: "RU",
		Timestamp:  time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	assert.False(t, decision.Allowed)
	assert.Contains(t, decision.Reason, "country")
	assert.Equal(t, 80, decision.RiskScore)
}

func TestEvaluateAccessContext_GeoFenceCaseInsensitive(t *testing.T) {
	svc := newTestService()
	route := baseRoute()
	route.AllowedCountries = []string{"us"}

	ac := &AccessContext{
		Session:       baseSession(),
		Route:         route,
		ClientIP:      "1.2.3.4",
		UserAgent:     baseSession().UserAgent,
		GeoCountry:    "US",
		DeviceTrusted: true,
		Timestamp:     time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	assert.True(t, decision.Allowed)
}

func TestEvaluateAccessContext_UAMajorChange(t *testing.T) {
	svc := newTestService()
	session := baseSession()
	session.UserAgent = "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36"

	ac := &AccessContext{
		Session:       session,
		Route:         baseRoute(),
		ClientIP:      "1.2.3.4",
		UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/121.0",
		DeviceTrusted: true,
		Timestamp:     time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	assert.True(t, decision.Allowed) // Not blocked, just risk increase
	assert.GreaterOrEqual(t, decision.RiskScore, 35)
}

func TestEvaluateAccessContext_UAMinorChange(t *testing.T) {
	svc := newTestService()
	session := baseSession()
	session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	ac := &AccessContext{
		Session:       session,
		Route:         baseRoute(),
		ClientIP:      "1.2.3.4",
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		DeviceTrusted: true,
		Timestamp:     time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	assert.True(t, decision.Allowed)
	assert.Equal(t, 10, decision.RiskScore) // minor change = +10
}

func TestEvaluateAccessContext_UASame(t *testing.T) {
	svc := newTestService()
	session := baseSession()
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
	session.UserAgent = ua

	ac := &AccessContext{
		Session:       session,
		Route:         baseRoute(),
		ClientIP:      "1.2.3.4",
		UserAgent:     ua,
		DeviceTrusted: true,
		Timestamp:     time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	assert.True(t, decision.Allowed)
	assert.Equal(t, 0, decision.RiskScore)
}

func TestEvaluateAccessContext_DeviceTrustRequired(t *testing.T) {
	svc := newTestService()
	route := baseRoute()
	route.RequireDeviceTrust = true

	ac := &AccessContext{
		Session:       baseSession(),
		Route:         route,
		ClientIP:      "1.2.3.4",
		UserAgent:     baseSession().UserAgent,
		DeviceTrusted: false,
		Timestamp:     time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	assert.False(t, decision.Allowed)
	assert.Contains(t, decision.Reason, "device")
	assert.True(t, decision.StepUpRequired)
}

func TestEvaluateAccessContext_DeviceTrustOptional(t *testing.T) {
	svc := newTestService()
	route := baseRoute()
	route.RequireDeviceTrust = false

	ac := &AccessContext{
		Session:       baseSession(),
		Route:         route,
		ClientIP:      "1.2.3.4",
		UserAgent:     baseSession().UserAgent,
		DeviceTrusted: false,
		Timestamp:     time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	assert.True(t, decision.Allowed)
	assert.Equal(t, 15, decision.RiskScore) // untrusted device adds 15
}

func TestEvaluateAccessContext_PostureScoreZero(t *testing.T) {
	svc := newTestService()
	route := baseRoute()
	route.PostureCheckIDs = []string{"check-1"}

	ac := &AccessContext{
		Session:       baseSession(),
		Route:         route,
		ClientIP:      "1.2.3.4",
		UserAgent:     baseSession().UserAgent,
		DeviceTrusted: true,
		PostureScore:  0,
		Timestamp:     time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	assert.False(t, decision.Allowed)
	assert.Contains(t, decision.Reason, "posture")
}

func TestEvaluateAccessContext_PostureScorePartial(t *testing.T) {
	svc := newTestService()
	route := baseRoute()
	route.PostureCheckIDs = []string{"check-1"}

	ac := &AccessContext{
		Session:       baseSession(),
		Route:         route,
		ClientIP:      "1.2.3.4",
		UserAgent:     baseSession().UserAgent,
		DeviceTrusted: true,
		PostureScore:  0.4,
		Timestamp:     time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	assert.True(t, decision.Allowed) // partial but not zero, risk increases
	assert.GreaterOrEqual(t, decision.RiskScore, 25)
}

func TestEvaluateAccessContext_PostureScoreFull(t *testing.T) {
	svc := newTestService()
	route := baseRoute()
	route.PostureCheckIDs = []string{"check-1"}

	ac := &AccessContext{
		Session:       baseSession(),
		Route:         route,
		ClientIP:      "1.2.3.4",
		UserAgent:     baseSession().UserAgent,
		DeviceTrusted: true,
		PostureScore:  1.0,
		Timestamp:     time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	assert.True(t, decision.Allowed)
	assert.Equal(t, 0, decision.RiskScore)
}

func TestEvaluateAccessContext_RiskScoreThreshold(t *testing.T) {
	svc := newTestService()
	route := baseRoute()
	route.MaxRiskScore = 20

	ac := &AccessContext{
		Session:      baseSession(),
		Route:        route,
		ClientIP:     "1.2.3.4",
		UserAgent:    baseSession().UserAgent,
		IPThreatType: "suspicious", // +30 risk
		IPBlocked:    false,
		DeviceTrusted: true,
		Timestamp:    time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	assert.False(t, decision.Allowed)
	assert.Contains(t, decision.Reason, "risk score")
	assert.True(t, decision.StepUpRequired)
}

func TestEvaluateAccessContext_RiskScoreCapping(t *testing.T) {
	svc := newTestService()
	route := baseRoute()
	route.PostureCheckIDs = []string{"check-1"}
	route.MaxRiskScore = 0 // disable threshold

	session := baseSession()
	session.UserAgent = "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36"

	ac := &AccessContext{
		Session:      session,
		Route:        route,
		ClientIP:     "1.2.3.4",
		UserAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X) Firefox/121.0", // major change +35
		IPThreatType: "suspicious", // +30
		IPBlocked:    false,
		DeviceTrusted: false,  // +15
		PostureScore:  0.3,    // +25
		Timestamp:    time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	// 30 + 35 + 15 + 25 = 105, should be capped to 100
	assert.LessOrEqual(t, decision.RiskScore, 100)
}

func TestEvaluateAccessContext_InlinePolicy(t *testing.T) {
	svc := newTestService()
	route := baseRoute()
	route.InlinePolicy = `user.email == "test@example.com"`

	ac := &AccessContext{
		Session:       baseSession(),
		Route:         route,
		ClientIP:      "1.2.3.4",
		UserAgent:     baseSession().UserAgent,
		DeviceTrusted: true,
		Timestamp:     time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	assert.True(t, decision.Allowed)
}

func TestEvaluateAccessContext_InlinePolicyDeny(t *testing.T) {
	svc := newTestService()
	route := baseRoute()
	route.InlinePolicy = `user.email == "other@example.com"`

	ac := &AccessContext{
		Session:       baseSession(),
		Route:         route,
		ClientIP:      "1.2.3.4",
		UserAgent:     baseSession().UserAgent,
		DeviceTrusted: true,
		Timestamp:     time.Now(),
	}

	decision := svc.evaluateAccessContext(ac)
	assert.False(t, decision.Allowed)
	assert.Contains(t, decision.Reason, "inline policy")
}

func TestEvaluateAccessContext_InlinePolicyWithMethodAndPath(t *testing.T) {
	svc := newTestService()
	route := baseRoute()
	route.InlinePolicy = `request.method == "GET" AND request.path contains "/api"`

	ac := &AccessContext{
		Session:        baseSession(),
		Route:          route,
		ClientIP:       "1.2.3.4",
		UserAgent:      baseSession().UserAgent,
		DeviceTrusted:  true,
		Timestamp:      time.Now(),
		OriginalMethod: "GET",
		OriginalURI:    "/api/v1/users",
	}

	decision := svc.evaluateAccessContext(ac)
	assert.True(t, decision.Allowed)
}

// ---- Unit tests for helper functions ----

func TestExtractBrowserFamily(t *testing.T) {
	tests := []struct {
		name     string
		ua       string
		expected string
	}{
		{"Chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "chrome"},
		{"Firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", "firefox"},
		{"Safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15", "safari"},
		{"Edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91", "edge"},
		{"Opera", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0", "opera"},
		{"curl", "curl/8.4.0", "curl"},
		{"unknown", "SomeRandomBot/1.0", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractBrowserFamily(tt.ua))
		})
	}
}

func TestExtractOSFamily(t *testing.T) {
	tests := []struct {
		name     string
		ua       string
		expected string
	}{
		{"Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows"},
		{"macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2)", "macos"},
		{"Linux", "Mozilla/5.0 (X11; Linux x86_64)", "linux"},
		{"Android", "Mozilla/5.0 (Linux; Android 14; Pixel 7)", "android"},
		{"iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X)", "ios"},
		{"iPad", "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X)", "ios"},
		{"ChromeOS", "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0)", "chromeos"},
		{"unknown", "curl/8.4.0", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractOSFamily(tt.ua))
		})
	}
}

func TestIsMajorUAChange(t *testing.T) {
	tests := []struct {
		name     string
		original string
		current  string
		major    bool
	}{
		{
			"same browser different version",
			"Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0) Chrome/121.0.0.0 Safari/537.36",
			false,
		},
		{
			"different browser",
			"Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; rv:121.0) Gecko/20100101 Firefox/121.0",
			true,
		},
		{
			"different OS same browser",
			"Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) Chrome/120.0.0.0 Safari/537.36",
			true,
		},
		{
			"both unknown",
			"BotAgent/1.0",
			"OtherBot/2.0",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.major, isMajorUAChange(tt.original, tt.current))
		})
	}
}
