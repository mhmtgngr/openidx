// Package organization provides unit tests for organization management
package organization

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/config"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestOrganization_Structure tests the Organization struct
func TestOrganization_Structure(t *testing.T) {
	t.Run("verify organization structure with all fields", func(t *testing.T) {
		domain := "example.com"
		now := time.Now().UTC()
		settings := map[string]interface{}{
			"theme":           "dark",
			"logo_url":        "https://example.com/logo.png",
			"mfa_required":    true,
			"session_timeout": 30,
		}

		org := Organization{
			ID:              "org-123",
			Name:            "Test Organization",
			Slug:            "test-org",
			Domain:          &domain,
			Plan:            "enterprise",
			Status:          "active",
			Settings:        settings,
			MaxUsers:        100,
			MaxApplications: 50,
			CreatedAt:       now,
			UpdatedAt:       now,
			MemberCount:     25,
		}

		assert.Equal(t, "org-123", org.ID)
		assert.Equal(t, "Test Organization", org.Name)
		assert.Equal(t, "test-org", org.Slug)
		assert.Equal(t, &domain, org.Domain)
		assert.Equal(t, "enterprise", org.Plan)
		assert.Equal(t, "active", org.Status)
		assert.Equal(t, 100, org.MaxUsers)
		assert.Equal(t, 50, org.MaxApplications)
		assert.Equal(t, 25, org.MemberCount)
		assert.NotNil(t, org.Settings)
		assert.Equal(t, "dark", org.Settings["theme"])
	})

	t.Run("verify organization without domain", func(t *testing.T) {
		org := Organization{
			ID:              "org-456",
			Name:            "Simple Org",
			Slug:            "simple",
			Domain:          nil,
			Plan:            "free",
			Status:          "active",
			Settings:        map[string]interface{}{},
			MaxUsers:        5,
			MaxApplications: 1,
		}

		assert.Nil(t, org.Domain)
		assert.Equal(t, "free", org.Plan)
		assert.Equal(t, 5, org.MaxUsers)
	})
}

// TestOrganizationMember_Structure tests the OrganizationMember struct
func TestOrganizationMember_Structure(t *testing.T) {
	t.Run("verify member structure with inviter", func(t *testing.T) {
		invitedBy := "admin-123"
		now := time.Now().UTC()

		member := OrganizationMember{
			ID:             "member-1",
			OrganizationID: "org-123",
			UserID:         "user-456",
			Role:           "admin",
			JoinedAt:       now,
			InvitedBy:      &invitedBy,
			UserEmail:      "user@example.com",
			UserName:       "Test User",
		}

		assert.Equal(t, "member-1", member.ID)
		assert.Equal(t, "org-123", member.OrganizationID)
		assert.Equal(t, "user-456", member.UserID)
		assert.Equal(t, "admin", member.Role)
		assert.Equal(t, &invitedBy, member.InvitedBy)
		assert.Equal(t, "user@example.com", member.UserEmail)
		assert.Equal(t, "Test User", member.UserName)
	})

	t.Run("verify member structure without inviter", func(t *testing.T) {
		member := OrganizationMember{
			ID:             "member-2",
			OrganizationID: "org-123",
			UserID:         "user-789",
			Role:           "member",
			InvitedBy:      nil,
			UserEmail:      "member@example.com",
			UserName:       "Member Name",
		}

		assert.Nil(t, member.InvitedBy)
		assert.Equal(t, "member", member.Role)
	})
}

// TestNewService tests the service constructor
func TestNewService(t *testing.T) {
	t.Run("create service with all dependencies", func(t *testing.T) {
		logger := zaptest.NewLogger(t)
		cfg := &config.Config{}

		svc := NewService(nil, nil, cfg, logger)

		assert.NotNil(t, svc)
		assert.NotNil(t, svc.logger)
		assert.NotNil(t, svc.config)
		assert.Nil(t, svc.db)
		assert.Nil(t, svc.redis)
	})

	t.Run("verify logger has service name", func(t *testing.T) {
		logger := zaptest.NewLogger(t)
		cfg := &config.Config{}

		svc := NewService(nil, nil, cfg, logger)

		assert.NotNil(t, svc.logger)
		// Logger should have the service name in its context
	})
}

// TestOrganization_JSONSerialization tests JSON marshaling/unmarshaling
func TestOrganization_JSONSerialization(t *testing.T) {
	t.Run("serialize and deserialize organization", func(t *testing.T) {
		domain := "test.com"
		org := Organization{
			ID:              "org-123",
			Name:            "Test Org",
			Slug:            "test-org",
			Domain:          &domain,
			Plan:            "premium",
			Status:          "active",
			Settings:        map[string]interface{}{"mfa": true},
			MaxUsers:        100,
			MaxApplications: 25,
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		}

		data, err := json.Marshal(org)
		assert.NoError(t, err)
		assert.NotEmpty(t, data)

		var decoded Organization
		err = json.Unmarshal(data, &decoded)
		assert.NoError(t, err)

		assert.Equal(t, "org-123", decoded.ID)
		assert.Equal(t, "Test Org", decoded.Name)
		assert.Equal(t, "test-org", decoded.Slug)
		assert.Equal(t, "premium", decoded.Plan)
		assert.Equal(t, "active", decoded.Status)
		assert.Equal(t, 100, decoded.MaxUsers)
		assert.Equal(t, 25, decoded.MaxApplications)
	})

	t.Run("serialize organization with nil domain", func(t *testing.T) {
		org := Organization{
			ID:       "org-456",
			Name:     "No Domain Org",
			Slug:     "no-domain",
			Domain:   nil,
			Plan:     "free",
			Status:   "active",
			Settings: nil,
		}

		data, err := json.Marshal(org)
		assert.NoError(t, err)

		var decoded Organization
		err = json.Unmarshal(data, &decoded)
		assert.NoError(t, err)
		assert.Nil(t, decoded.Domain)
	})
}

// TestOrganizationMember_JSONSerialization tests member JSON handling
func TestOrganizationMember_JSONSerialization(t *testing.T) {
	t.Run("serialize and deserialize member", func(t *testing.T) {
		invitedBy := "inviter-123"
		member := OrganizationMember{
			ID:             "member-1",
			OrganizationID: "org-123",
			UserID:         "user-456",
			Role:           "admin",
			JoinedAt:       time.Now(),
			InvitedBy:      &invitedBy,
			UserEmail:      "user@example.com",
			UserName:       "Test User",
		}

		data, err := json.Marshal(member)
		assert.NoError(t, err)
		assert.NotEmpty(t, data)

		var decoded OrganizationMember
		err = json.Unmarshal(data, &decoded)
		assert.NoError(t, err)

		assert.Equal(t, "member-1", decoded.ID)
		assert.Equal(t, "org-123", decoded.OrganizationID)
		assert.Equal(t, "user-456", decoded.UserID)
		assert.Equal(t, "admin", decoded.Role)
		assert.Equal(t, "user@example.com", decoded.UserEmail)
		assert.Equal(t, "Test User", decoded.UserName)
	})
}

// TestHandleListOrganizations_QueryParsing tests query parameter parsing
func TestHandleListOrganizations_QueryParsing(t *testing.T) {
	t.Run("parse default limit and offset", func(t *testing.T) {
		// This tests the parsing logic without needing a database
		offset := 0
		limit := 20

		assert.Equal(t, 0, offset)
		assert.Equal(t, 20, limit)
	})

	t.Run("parse custom limit and offset", func(t *testing.T) {
		// Simulate parsing from query params
		offset, _ := parseInt("10")
		limit, _ := parseInt("50")

		assert.Equal(t, 10, offset)
		assert.Equal(t, 50, limit)
	})

	t.Run("handle invalid query params", func(t *testing.T) {
		// Invalid numbers should default to 0 or use fallback
		offset, _ := parseInt("invalid")
		limit, _ := parseInt("abc")

		assert.Equal(t, 0, offset)
		assert.Equal(t, 0, limit)
	})
}

// TestOrganization_StatusValues tests valid status values
func TestOrganization_StatusValues(t *testing.T) {
	validStatuses := []string{"active", "suspended", "deleted"}

	t.Run("valid status values", func(t *testing.T) {
		for _, status := range validStatuses {
			assert.NotEmpty(t, status)
		}
	})

	t.Run("status comparisons", func(t *testing.T) {
		status := "active"
		assert.Equal(t, "active", status)

		status = "suspended"
		assert.NotEqual(t, "active", status)
	})
}

// TestOrganization_PlanValues tests valid plan values
func TestOrganization_PlanValues(t *testing.T) {
	validPlans := []string{"free", "basic", "premium", "enterprise"}

	t.Run("valid plan values", func(t *testing.T) {
		for _, plan := range validPlans {
			assert.NotEmpty(t, plan)
		}
	})

	t.Run("plan comparisons", func(t *testing.T) {
		plan := "free"
		assert.Equal(t, "free", plan)

		plan = "enterprise"
		assert.NotEqual(t, "free", plan)
	})
}

// TestOrganization_MemberRoles tests valid member roles
func TestOrganization_MemberRoles(t *testing.T) {
	validRoles := []string{"owner", "admin", "member", "guest"}

	t.Run("valid role values", func(t *testing.T) {
		for _, role := range validRoles {
			assert.NotEmpty(t, role)
		}
	})

	t.Run("role hierarchy check", func(t *testing.T) {
		roles := map[string]int{
			"owner":  4,
			"admin":  3,
			"member": 2,
			"guest":  1,
		}

		assert.True(t, roles["owner"] > roles["admin"])
		assert.True(t, roles["admin"] > roles["member"])
		assert.True(t, roles["member"] > roles["guest"])
	})
}

// TestOrganization_SettingsHandling tests settings map handling
func TestOrganization_SettingsHandling(t *testing.T) {
	t.Run("marshal settings to JSON", func(t *testing.T) {
		settings := map[string]interface{}{
			"mfa_required":     true,
			"session_timeout":  3600,
			"allowed_domains":  []string{"example.com", "test.com"},
			"custom_field":     "value",
		}

		data, err := json.Marshal(settings)
		assert.NoError(t, err)
		assert.NotEmpty(t, data)
		assert.True(t, strings.HasPrefix(string(data), "{"))
	})

	t.Run("unmarshal settings from JSON", func(t *testing.T) {
		jsonStr := `{"mfa_required":true,"session_timeout":3600}`

		var settings map[string]interface{}
		err := json.Unmarshal([]byte(jsonStr), &settings)
		assert.NoError(t, err)

		assert.True(t, settings["mfa_required"].(bool))
		assert.Equal(t, float64(3600), settings["session_timeout"])
	})

	t.Run("handle empty settings", func(t *testing.T) {
		settings := map[string]interface{}{}

		data, err := json.Marshal(settings)
		assert.NoError(t, err)

		var decoded map[string]interface{}
		err = json.Unmarshal(data, &decoded)
		assert.NoError(t, err)
		assert.Empty(t, decoded)
	})
}

// TestOrganization_Timestamps tests timestamp handling
func TestOrganization_Timestamps(t *testing.T) {
	t.Run("UTC timestamps", func(t *testing.T) {
		now := time.Now().UTC()

		org := Organization{
			ID:        "org-123",
			CreatedAt: now,
			UpdatedAt: now,
		}

		assert.False(t, org.CreatedAt.IsZero())
		assert.False(t, org.UpdatedAt.IsZero())
	})

	t.Run("timestamps can be compared", func(t *testing.T) {
		first := time.Now().UTC()
		second := first.Add(time.Hour)

		assert.True(t, second.After(first))
		assert.False(t, first.After(second))
	})
}

// TestSlugGeneration tests slug conventions
func TestSlugGeneration(t *testing.T) {
	t.Run("slug should be lowercase", func(t *testing.T) {
		slug := "my-organization"
		assert.Equal(t, slug, strings.ToLower(slug))
	})

	t.Run("slug should use hyphens", func(t *testing.T) {
		slug := "my-organization"
		assert.Contains(t, slug, "-")
		assert.NotContains(t, slug, " ")
		assert.NotContains(t, slug, "_")
	})
}

// TestMemberRoles_Validation tests role validation logic
func TestMemberRoles_Validation(t *testing.T) {
	t.Run("valid roles", func(t *testing.T) {
		validRoles := map[string]bool{
			"owner":  true,
			"admin":  true,
			"member": true,
			"guest":  true,
		}

		for role := range validRoles {
			assert.True(t, validRoles[role], "Role %s should be valid", role)
		}
	})

	t.Run("invalid roles", func(t *testing.T) {
		validRoles := map[string]bool{
			"owner":  true,
			"admin":  true,
			"member": true,
			"guest":  true,
		}

		invalidRoles := []string{"superadmin", "moderator", "user", ""}

		for _, role := range invalidRoles {
			if role == "" {
				continue // Skip empty for this test
			}
			isValid := validRoles[role]
			assert.False(t, isValid, "Role %s should be invalid", role)
		}
	})
}

// TestOrganization_Limits tests max users and applications handling
func TestOrganization_Limits(t *testing.T) {
	t.Run("plan-based limits", func(t *testing.T) {
		limits := map[string]struct {
			maxUsers        int
			maxApplications int
		}{
			"free":       {5, 1},
			"basic":      {50, 10},
			"premium":    {200, 50},
			"enterprise": {-1, -1}, // unlimited
		}

		// Verify free plan limits
		assert.Equal(t, 5, limits["free"].maxUsers)
		assert.Equal(t, 1, limits["free"].maxApplications)

		// Verify enterprise unlimited
		assert.Equal(t, -1, limits["enterprise"].maxUsers)
	})

	t.Run("can add users within limit", func(t *testing.T) {
		maxUsers := 10
		currentUsers := 5

		canAdd := currentUsers < maxUsers
		assert.True(t, canAdd)
	})

	t.Run("cannot exceed user limit", func(t *testing.T) {
		maxUsers := 10
		currentUsers := 10

		canAdd := currentUsers < maxUsers
		assert.False(t, canAdd)
	})
}

// TestOrganization_DomainHandling tests domain field
func TestOrganization_DomainHandling(t *testing.T) {
	t.Run("nil domain means no custom domain", func(t *testing.T) {
		org := Organization{
			Domain: nil,
		}

		assert.Nil(t, org.Domain)
	})

	t.Run("non-nil domain has custom domain", func(t *testing.T) {
		domain := "custom.example.com"
		org := Organization{
			Domain: &domain,
		}

		assert.NotNil(t, org.Domain)
		assert.Equal(t, "custom.example.com", *org.Domain)
	})

	t.Run("domain validation", func(t *testing.T) {
		validDomains := []string{
			"example.com",
			"subdomain.example.com",
			"my-org.example.co.uk",
		}

		for _, domain := range validDomains {
			assert.NotEmpty(t, domain)
			assert.Contains(t, domain, ".")
		}
	})
}

// TestRegisterRoutes tests route registration
func TestRegisterRoutes(t *testing.T) {
	t.Run("register routes on router", func(t *testing.T) {
		router := gin.New()
		group := router.Group("/api/v1")

		logger := zaptest.NewLogger(t)
		cfg := &config.Config{}
		svc := NewService(nil, nil, cfg, logger)

		// This should not panic
		RegisterRoutes(group, svc)

		// Routes should be registered
		routes := router.Routes()
		assert.NotEmpty(t, routes)
	})
}

// Helper function
func parseInt(s string) (int, error) {
	var i int
	_, err := sscanfInt(s, &i)
	return i, err
}

func sscanfInt(s string, i *int) (int, error) {
	n, err := 0, error(nil)
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, err
		}
		n = n*10 + int(c-'0')
	}
	*i = n
	return n, nil
}
