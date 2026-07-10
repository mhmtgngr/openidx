package apikeys

import (
	"context"

	"github.com/openidx/openidx/internal/common/middleware"
)

// MiddlewareValidator returns an adapter that lets the auth middleware validate
// API keys through this service.
//
// The middleware package deliberately declares its own APIKeyValidator interface
// and APIKeyInfo type so it need not import this package; this adapter bridges
// the two, converting apikeys.APIKeyInfo to middleware.APIKeyInfo. Wire it into
// each service main via middleware.AuthWithAPIKey(jwksURL, svc.MiddlewareValidator())
// so that minted "oidx_"-prefixed keys and PATs actually authenticate requests
// (middleware.Auth passes a nil validator, which rejects every API key as a
// malformed JWT).
func (s *Service) MiddlewareValidator() middleware.APIKeyValidator {
	return middlewareValidator{svc: s}
}

type middlewareValidator struct{ svc *Service }

func (m middlewareValidator) ValidateAPIKey(ctx context.Context, rawKey string) (*middleware.APIKeyInfo, error) {
	info, err := m.svc.ValidateAPIKey(ctx, rawKey)
	if err != nil {
		return nil, err
	}
	return toMiddlewareInfo(info), nil
}

// toMiddlewareInfo maps this package's APIKeyInfo onto the auth middleware's
// decoupled APIKeyInfo (which omits Status). Kept as a pure function so the
// mapping can be tested without a database.
func toMiddlewareInfo(info *APIKeyInfo) *middleware.APIKeyInfo {
	return &middleware.APIKeyInfo{
		KeyID:            info.KeyID,
		UserID:           info.UserID,
		ServiceAccountID: info.ServiceAccountID,
		Scopes:           info.Scopes,
		OrgID:            info.OrgID,
	}
}
