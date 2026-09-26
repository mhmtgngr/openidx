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
func newAccessToken(claims jwt.MapClaims, kid, orgID string) *jwt.Token {
	claims[middleware.OrgIDClaim] = orgID
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	tok.Header["typ"] = middleware.AccessTokenType
	return tok
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
// parseAccessToken refused. A correctly signed token refused for what it is --
// the wrong kind of token, one naming no organization, one of another
// organization -- is told why, so a client can tell "send your access token"
// or "sign in again" from "your token is bad"; every other failure keeps the
// bare error it always had.
func invalidTokenBody(err error) gin.H {
	if errors.Is(err, middleware.ErrNotAccessToken) || errors.Is(err, middleware.ErrNoOrganization) ||
		errors.Is(err, middleware.ErrWrongOrganization) {
		return gin.H{"error": "invalid_token", "error_description": err.Error()}
	}
	return gin.H{"error": "invalid_token"}
}
