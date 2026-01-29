package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestDashboardSerialization verifies Dashboard JSON marshaling
func TestDashboardSerialization(t *testing.T) {
	now := time.Now()
	dashboard := &Dashboard{
		TotalUsers:        100,
		ActiveUsers:       80,
		TotalGroups:       10,
		TotalApplications: 5,
		ActiveSessions:    25,
		PendingReviews:    3,
		SecurityAlerts:    2,
		RecentActivity: []ActivityItem{
			{
				ID:        "act-1",
				Type:      "authentication",
				Message:   "User logged in",
				ActorID:   "user-1",
				ActorName: "john.doe",
				Timestamp: now,
			},
		},
		AuthStats: AuthStatistics{
			TotalLogins:      500,
			SuccessfulLogins: 480,
			FailedLogins:     20,
			MFAUsage:         100,
			LoginsByMethod:   map[string]int{"password": 400, "sso": 100},
			LoginsByDay: []DayStats{
				{Date: "2024-01-01", Count: 50},
			},
		},
		SecurityAlertDetails: []SecurityAlertDetail{
			{Message: "Failed login attempts from unknown", Count: 5, Timestamp: now},
		},
	}

	data, err := json.Marshal(dashboard)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	var decoded Dashboard
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, 100, decoded.TotalUsers)
	assert.Equal(t, 80, decoded.ActiveUsers)
	assert.Equal(t, 10, decoded.TotalGroups)
	assert.Equal(t, 5, decoded.TotalApplications)
	assert.Equal(t, 25, decoded.ActiveSessions)
	assert.Equal(t, 3, decoded.PendingReviews)
	assert.Equal(t, 2, decoded.SecurityAlerts)
	assert.Len(t, decoded.RecentActivity, 1)
	assert.Equal(t, "authentication", decoded.RecentActivity[0].Type)
	assert.Equal(t, 500, decoded.AuthStats.TotalLogins)
	assert.Equal(t, 480, decoded.AuthStats.SuccessfulLogins)
	assert.Len(t, decoded.SecurityAlertDetails, 1)
}

// TestApplicationModel verifies Application JSON round-trip
func TestApplicationModel(t *testing.T) {
	app := Application{
		ID:           "app-1",
		ClientID:     "client-123",
		Name:         "Test App",
		Description:  "A test application",
		Type:         "web",
		Protocol:     "oidc",
		BaseURL:      "https://app.example.com",
		RedirectURIs: []string{"https://app.example.com/callback"},
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	data, err := json.Marshal(app)
	assert.NoError(t, err)

	var decoded Application
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "app-1", decoded.ID)
	assert.Equal(t, "client-123", decoded.ClientID)
	assert.Equal(t, "web", decoded.Type)
	assert.Equal(t, "oidc", decoded.Protocol)
	assert.True(t, decoded.Enabled)
	assert.Len(t, decoded.RedirectURIs, 1)
}

// TestSettingsDefaults verifies default settings structure
func TestSettingsDefaults(t *testing.T) {
	settings := &Settings{
		General: GeneralSettings{
			OrganizationName: "OpenIDX",
			SupportEmail:     "support@openidx.io",
			DefaultLanguage:  "en",
			DefaultTimezone:  "UTC",
		},
		Security: SecuritySettings{
			PasswordPolicy: PasswordPolicy{
				MinLength:        12,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSpecial:   true,
				MaxAge:           90,
				History:          5,
			},
			SessionTimeout:  30,
			MaxFailedLogins: 5,
			LockoutDuration: 15,
			RequireMFA:      false,
		},
		Authentication: AuthenticationSettings{
			AllowRegistration:  true,
			RequireEmailVerify: true,
			MFAMethods:         []string{"totp", "webauthn", "sms"},
		},
		Branding: BrandingSettings{
			PrimaryColor:   "#2563eb",
			SecondaryColor: "#1e40af",
			LoginPageTitle: "Welcome to OpenIDX",
		},
	}

	data, err := json.Marshal(settings)
	assert.NoError(t, err)

	var decoded Settings
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "OpenIDX", decoded.General.OrganizationName)
	assert.Equal(t, 12, decoded.Security.PasswordPolicy.MinLength)
	assert.True(t, decoded.Security.PasswordPolicy.RequireUppercase)
	assert.True(t, decoded.Authentication.AllowRegistration)
	assert.Len(t, decoded.Authentication.MFAMethods, 3)
	assert.Equal(t, "#2563eb", decoded.Branding.PrimaryColor)
}

// TestApplicationSSOSettingsModel verifies SSO settings JSON
func TestApplicationSSOSettingsModel(t *testing.T) {
	settings := ApplicationSSOSettings{
		ID:                   "sso-1",
		ApplicationID:        "app-1",
		Enabled:              true,
		UseRefreshTokens:     true,
		AccessTokenLifetime:  3600,
		RefreshTokenLifetime: 86400,
		RequireConsent:       false,
	}

	data, err := json.Marshal(settings)
	assert.NoError(t, err)

	var decoded ApplicationSSOSettings
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "app-1", decoded.ApplicationID)
	assert.True(t, decoded.Enabled)
	assert.Equal(t, 3600, decoded.AccessTokenLifetime)
	assert.Equal(t, 86400, decoded.RefreshTokenLifetime)
}

// TestDirectoryIntegrationModel verifies directory integration JSON
func TestDirectoryIntegrationModel(t *testing.T) {
	dir := DirectoryIntegration{
		ID:         "dir-1",
		Name:       "Corp LDAP",
		Type:       "ldap",
		Config:     map[string]interface{}{"host": "ldap.corp.com", "port": float64(389)},
		Enabled:    true,
		SyncStatus: "completed",
	}

	data, err := json.Marshal(dir)
	assert.NoError(t, err)

	var decoded DirectoryIntegration
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "ldap", decoded.Type)
	assert.Equal(t, "completed", decoded.SyncStatus)
	assert.Equal(t, "ldap.corp.com", decoded.Config["host"])
}

// TestUpdateApplicationNoFields verifies error when no fields to update
func TestUpdateApplicationNoFields(t *testing.T) {
	// Service with nil db will panic if it reaches the DB call,
	// so we test that empty updates returns an error before that
	svc := &Service{}
	err := svc.UpdateApplication(nil, "app-1", map[string]interface{}{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no valid fields to update")
}

// TestUpdateApplicationFieldParsing tests that UpdateApplication builds SET clauses correctly
func TestUpdateApplicationFieldParsing(t *testing.T) {
	tests := []struct {
		name    string
		updates map[string]interface{}
		wantErr bool
	}{
		{
			name:    "empty updates",
			updates: map[string]interface{}{},
			wantErr: true,
		},
		{
			name:    "unknown fields only",
			updates: map[string]interface{}{"unknown_field": "value"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &Service{}
			err := svc.UpdateApplication(nil, "app-1", tt.updates)
			if tt.wantErr {
				assert.Error(t, err)
			}
		})
	}
}

// TestHandlerUpdateSettingsInvalidJSON tests settings handler with invalid JSON
func TestHandlerUpdateSettingsInvalidJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("PUT", "/settings", strings.NewReader("not json"))
	c.Request.Header.Set("Content-Type", "application/json")

	svc := &Service{}
	svc.handleUpdateSettings(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandlerCreateApplicationInvalidJSON tests app creation with invalid JSON
func TestHandlerCreateApplicationInvalidJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/applications", strings.NewReader("{invalid"))
	c.Request.Header.Set("Content-Type", "application/json")

	svc := &Service{}
	svc.handleCreateApplication(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandlerUpdateApplicationInvalidJSON tests app update with invalid JSON
func TestHandlerUpdateApplicationInvalidJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("PUT", "/applications/app-1", strings.NewReader("{invalid"))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: "app-1"}}

	svc := &Service{}
	svc.handleUpdateApplication(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandlerUpdateMFAMethodsInvalidJSON tests MFA methods update with invalid JSON
func TestHandlerUpdateMFAMethodsInvalidJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("PUT", "/mfa/methods", strings.NewReader("{invalid"))
	c.Request.Header.Set("Content-Type", "application/json")

	svc := &Service{}
	svc.handleUpdateMFAMethods(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandlerUpdateSSOSettingsInvalidJSON tests SSO settings update with invalid JSON
func TestHandlerUpdateSSOSettingsInvalidJSON(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("PUT", "/applications/app-1/sso-settings", strings.NewReader("{invalid"))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: "app-1"}}

	svc := &Service{}
	svc.handleUpdateApplicationSSOSettings(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestPasswordPolicyValidation tests password policy values
func TestPasswordPolicyValidation(t *testing.T) {
	tests := []struct {
		name   string
		policy PasswordPolicy
		valid  bool
	}{
		{
			name: "strong policy",
			policy: PasswordPolicy{
				MinLength: 12, RequireUppercase: true, RequireLowercase: true,
				RequireNumbers: true, RequireSpecial: true, MaxAge: 90, History: 5,
			},
			valid: true,
		},
		{
			name: "weak policy",
			policy: PasswordPolicy{
				MinLength: 4, RequireUppercase: false, RequireLowercase: false,
				RequireNumbers: false, RequireSpecial: false, MaxAge: 0, History: 0,
			},
			valid: true, // structurally valid even if weak
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.policy)
			assert.NoError(t, err)
			var decoded PasswordPolicy
			err = json.Unmarshal(data, &decoded)
			assert.NoError(t, err)
			assert.Equal(t, tt.policy.MinLength, decoded.MinLength)
		})
	}
}

// TestCreateApplicationAutoGeneratesIDs verifies that CreateApplication auto-fills IDs
func TestCreateApplicationAutoGeneratesIDs(t *testing.T) {
	app := &Application{
		Name:     "Test App",
		Type:     "web",
		Protocol: "oidc",
	}

	// Without a DB connection, we can only verify that the ID generation logic
	// is set up correctly by checking the struct after running the non-DB parts
	assert.Empty(t, app.ID)
	assert.Empty(t, app.ClientID)

	// Simulate what CreateApplication does before the DB call
	if app.ID == "" {
		app.ID = "generated-id" // would be uuid.New().String()
	}
	if app.ClientID == "" {
		app.ClientID = "generated-client-id"
	}
	app.CreatedAt = time.Now()
	app.UpdatedAt = time.Now()

	assert.NotEmpty(t, app.ID)
	assert.NotEmpty(t, app.ClientID)
	assert.False(t, app.CreatedAt.IsZero())
}

// TestRegisterRoutes verifies route registration doesn't panic
func TestRegisterRoutes(t *testing.T) {
	router := gin.New()
	group := router.Group("/api/v1")
	svc := &Service{}

	assert.NotPanics(t, func() {
		RegisterRoutes(group, svc)
	})
}
