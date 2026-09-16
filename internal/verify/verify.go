// Package verify is the request half of the verification tier: the endpoints a
// relying party calls to check somebody else's token, served by a process with
// no database behind it.
//
// WHAT IS HERE, AND WHY IT IS ONLY THIS.
//
// ADR-2 asks for a tier serving "JWKS, introspection and forward-auth, with no
// PostgreSQL dependency". Measured against the code, two of those three cannot
// be served without PostgreSQL, and neither reason is incidental:
//
//   - Introspection is protected by client authentication, because RFC 7662
//     §2.1 requires it and because this endpoint was once open (see
//     requireTokenEndpointClientAuth in internal/oauth). Authenticating the
//     CALLER means reading oauth_clients. A tier that skipped that check to
//     stay database-free would reopen the hole that middleware was added to
//     close, and one that cached the client registry would be holding client
//     secrets in a tier whose whole claim is that it holds nothing. On top of
//     that, a refresh token is a row in oauth_refresh_tokens -- there is no
//     signature to check, so there is nothing to verify offline.
//   - /access/.auth/* is a login flow, not a verification: /login and /callback
//     run the OIDC exchange, and /idps reads identity_providers and
//     proxy_routes. Only /session is database-free (it reads a Redis blob), and
//     one session-info endpoint is not forward-auth.
//
// So this tier serves JWKS, and the plan records why the rest stayed. That is
// still worth a separate process: JWKS is the highest-fanout endpoint in the
// product -- every relying party and every sidecar verifier polls it -- and
// today it is answered by the same pod that mints tokens and holds the write
// pool. A flood of key fetches should not be able to take connections or
// admission slots from /oauth/token.
package verify

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/jwksverify"
)

// Service answers verification requests from the shared JWKS cache.
type Service struct {
	jwksURL string
	logger  *zap.Logger
}

// New builds the service. jwksURL is the issuer's key set -- an HTTP endpoint,
// which is the entire dependency: this tier holds no pool, no client registry
// and no session store.
func New(jwksURL string, logger *zap.Logger) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Service{jwksURL: jwksURL, logger: logger}
}

// RegisterRoutes mounts the verification endpoints.
func (s *Service) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
}

// handleJWKS re-serves the issuer's key set from the local cache.
//
// The document comes from jwksverify, so what this tier publishes is exactly
// the set it would verify a signature against -- see CachedJWKS. max-age
// matches the issuer's own (internal/oauth handleJWKS) so a rotated-in key
// reaches verifier caches on the same schedule whichever endpoint they poll.
func (s *Service) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	doc, err := jwksverify.CachedJWKS(s.jwksURL)
	if err != nil {
		// 503, NOT an empty key set with a 200. A verifier that receives
		// {"keys":[]} has been told authoritatively that this issuer signs
		// nothing, and the correct thing for it to do with that answer is
		// reject every token presented to it -- including the ones that are
		// perfectly valid. An error says "ask again", which is the truth: the
		// keys exist, this process cannot currently see them.
		s.logger.Error("cannot serve JWKS: no fresh or usable cached key set", zap.Error(err))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "5")
		http.Error(w, `{"error":"jwks_unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		s.logger.Warn("writing the JWKS response failed", zap.Error(err))
	}
}
