package oauth

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/openidx/openidx/internal/common/middleware"
)

// newAccessToken returns the unsigned access token for claims, typed as one.
//
// Every bearer this package mints is built here -- GenerateJWT,
// generateTokensForUser and issueExchangedToken -- and nothing else is. The
// "at+jwt" header (RFC 9068 §2.1) is what lets a validator tell an access token
// from the ID tokens, logout tokens and Security Event Tokens signed with the
// same key (middleware.IsAccessToken); an ID token carrying it would be
// accepted as a bearer again. access_token_census_test.go holds both halves.
func newAccessToken(claims jwt.MapClaims, kid string) *jwt.Token {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	tok.Header["typ"] = middleware.AccessTokenType
	return tok
}

// parseAccessToken verifies a bearer presented to one of this service's own
// endpoints and returns its claims. Beyond parseVerifiedClaims it refuses any
// token that is not an access token: the endpoints that call it act for the
// token's subject, and an ID token -- which every relying party the user signed
// in to holds -- must not be enough to do that.
func (s *Service) parseAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, claims, err := s.parseVerifiedToken(tokenString, false)
	if err != nil {
		return nil, err
	}
	if !middleware.IsAccessToken(token.Header, claims) {
		return nil, middleware.ErrNotAccessToken
	}
	return claims, nil
}

// invalidTokenBody is the RFC 6750 §3.1 invalid_token answer for a bearer that
// parseAccessToken refused. A correctly signed token of the wrong kind is told
// so, so that a client sending its ID token learns to send its access token;
// every other failure keeps the bare error it always had.
func invalidTokenBody(err error) gin.H {
	if errors.Is(err, middleware.ErrNotAccessToken) {
		return gin.H{"error": "invalid_token", "error_description": err.Error()}
	}
	return gin.H{"error": "invalid_token"}
}
