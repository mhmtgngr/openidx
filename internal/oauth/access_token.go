package oauth

import (
	"context"
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// newAccessToken returns the unsigned access token for claims, typed as one and
// bound to the organization it is minted in.
//
// Every bearer this package mints is built here -- GenerateJWT,
// generateTokensForUser and issueExchangedToken -- and nothing else is. The
// "at+jwt" header (RFC 9068 §2.1) is what lets a validator tell an access token
// from the ID tokens, logout tokens and Security Event Tokens signed with the
// same key (middleware.IsAccessToken); an ID token carrying it would be
// accepted as a bearer again. access_token_census_test.go holds both halves.
//
// orgID is the organization whose rows produced the token's roles. Validators
// refuse a token that names none and, outside a platform admin, one presented
// to a request for another organization (middleware.CheckTokenOrg), so the
// caller passes the organization it resolved the grant in, never one read out
// of a token it was handed.
//
// apiAccess is whether the application the token is issued to may call
// OpenIDX's own APIs (oauth_clients.api_access, middleware.HasAPIAccess). The
// claim is written only when it is true, so a token that says nothing is a
// token the APIs refuse.
func newAccessToken(claims jwt.MapClaims, kid, orgID string, apiAccess bool) *jwt.Token {
	claims[middleware.OrgIDClaim] = orgID
	if apiAccess {
		claims[middleware.APIAccessClaim] = true
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	tok.Header["typ"] = middleware.AccessTokenType
	return tok
}

// clientMayCallAPI reads, at mint time, whether the client a token is being
// issued to may call OpenIDX's own APIs. It is read from the client row rather
// than passed in by each grant so that no mint site can forget it, and so that
// an administrator's change takes effect at the client's next token. A client
// that cannot be read is treated as one that may not.
func (s *Service) clientMayCallAPI(ctx context.Context, clientID string) bool {
	if s.clients == nil || clientID == "" {
		return false
	}
	client, err := s.GetClient(ctx, clientID)
	return err == nil && client.MayCallAPI()
}

// parseAccessToken verifies a bearer presented to one of this service's own
// endpoints and returns its claims. Beyond parseVerifiedClaims it refuses any
// token that is not an access token: the endpoints that call it act for the
// token's subject, and an ID token -- which every relying party the user signed
// in to holds -- must not be enough to do that. It also refuses a token bound
// to another organization than the request's (tokenOrgForRequest).
func (s *Service) parseAccessToken(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	token, claims, err := s.parseVerifiedToken(tokenString, false)
	if err != nil {
		return nil, err
	}
	if !middleware.IsAccessToken(token.Header, claims) {
		return nil, middleware.ErrNotAccessToken
	}
	if _, err := tokenOrgForRequest(ctx, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// parseAPIToken is parseAccessToken for this service's account endpoints --
// sign-out-everywhere, the session policy read, social account linking --
// which, like the other OpenIDX APIs, a token only carries out for an
// application allowed to call them (middleware.HasAPIAccess). UserInfo is not
// one of them: it is the endpoint every relying party calls.
func (s *Service) parseAPIToken(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	claims, err := s.parseAccessToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}
	if !middleware.HasAPIAccess(claims) {
		return nil, middleware.ErrNoAPIAccess
	}
	return claims, nil
}

// tokenOrgForRequest returns the organization an access token is bound to,
// refusing a token that names none and one bound to an organization other than
// the one the request resolved to.
//
// Unlike the API validators this allows no platform-admin crossing. Every
// endpoint of this service that takes a bearer acts for the token's own
// subject -- their profile, their sessions, their linked accounts, a token
// minted from theirs -- and that account exists in the token's organization
// only.
func tokenOrgForRequest(ctx context.Context, claims jwt.MapClaims) (string, error) {
	orgID, err := middleware.TokenOrgID(claims)
	if err != nil {
		return "", err
	}
	if org, oerr := orgctx.From(ctx); oerr == nil && org.ID != orgID {
		return "", middleware.ErrWrongOrganization
	}
	return orgID, nil
}

// invalidTokenBody is the RFC 6750 §3.1 invalid_token answer for a bearer that
// parseAccessToken or parseAPIToken refused. A correctly signed token refused
// for what it is -- the wrong kind of token, one naming no organization, one of
// another organization, one whose application may not call the API -- is told
// why, so a client can tell "send your access token" or "sign in again" from
// "your token is bad"; every other failure keeps the bare error it always had.
func invalidTokenBody(err error) gin.H {
	if errors.Is(err, middleware.ErrNotAccessToken) || errors.Is(err, middleware.ErrNoOrganization) ||
		errors.Is(err, middleware.ErrWrongOrganization) || errors.Is(err, middleware.ErrNoAPIAccess) {
		return gin.H{"error": "invalid_token", "error_description": err.Error()}
	}
	return gin.H{"error": "invalid_token"}
}
