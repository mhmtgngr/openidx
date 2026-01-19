// Package oauth provides OAuth 2.0 and OpenID Connect provider functionality
package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/identity"
)

// MockIdentityService is a mock implementation of identity.Service
type MockIdentityService struct {
	mock.Mock
}

func (m *MockIdentityService) GetIdentityProvider(ctx context.Context, idpID string) (*identity.IdentityProvider, error) {
	args := m.Called(ctx, idpID)
	return args.Get(0).(*identity.IdentityProvider), args.Error(1)
}

func TestHandleSSOAuthorize(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Sample Identity Provider
	idp := &identity.IdentityProvider{
		ID:           "test-idp",
		Name:         "Test OIDC",
		ProviderType: identity.ProviderTypeOIDC,
		IssuerURL:    "https://test-issuer.com",
		ClientID:     "test-client-id",
		Scopes:       []string{"openid", "profile", "email"},
		Enabled:      true,
	}

	// Setup mock identity service
	mockIdentityService := new(MockIdentityService)
	mockIdentityService.On("GetIdentityProvider", mock.Anything, "test-idp").Return(idp, nil)

	// Setup OAuth service with mock dependencies
	logger := zap.NewNop()
	cfg := &config.Config{}
	// Nil for db and redis as they are not used in this specific handler path
	oauthService, _ := NewService(nil, nil, cfg, logger, mockIdentityService) 
	
	router := gin.New()
	router.GET("/oauth/authorize", oauthService.handleAuthorize)

	t.Run("Successful SSO redirect", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/oauth/authorize?idp_hint=test-idp", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		
		redirectURL := w.Header().Get("Location")
		assert.Contains(t, redirectURL, "https://test-issuer.com/protocol/openid-connect/auth")
		assert.Contains(t, redirectURL, "client_id=test-client-id")
		assert.Contains(t, redirectURL, "scope=openid+profile+email")
	})

	t.Run("IdP not found", func(t *testing.T) {
		mockIdentityService.On("GetIdentityProvider", mock.Anything, "not-found-idp").Return(nil, assert.AnError)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/oauth/authorize?idp_hint=not-found-idp", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
