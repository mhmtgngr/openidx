package oauth

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// Token Exchange (RFC 8693).
//
// grant_type=urn:ietf:params:oauth:grant-type:token-exchange lets a client
// trade one token for another: impersonation (act AS the subject) or delegation
// (act ON BEHALF OF the subject, recording the actor in an `act` claim). This is
// the core of agent identity — a service or autonomous agent obtains a narrowed,
// audience-scoped token to call a downstream API as/for a user, without holding
// the user's long-lived credentials.
//
// Supported token types (subject_token_type / actor_token_type / the issued
// token): urn:ietf:params:oauth:token-type:access_token and :jwt. OpenIDX only
// validates tokens it issued (RS256, its own kid), so cross-issuer federation is
// intentionally out of scope for this build.

const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

	tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	tokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
)

// handleTokenExchangeGrant implements RFC 8693 §2.
func (s *Service) handleTokenExchangeGrant(c *gin.Context) {
	subjectToken := c.PostForm("subject_token")
	subjectTokenType := c.PostForm("subject_token_type")
	actorToken := c.PostForm("actor_token")
	actorTokenType := c.PostForm("actor_token_type")
	requestedAudience := c.PostForm("audience")
	requestedResource := c.PostForm("resource")
	requestedScope := c.PostForm("scope")

	if subjectToken == "" {
		teError(c, "invalid_request", "subject_token is required")
		return
	}
	if subjectTokenType != "" && !isSupportedTokenType(subjectTokenType) {
		teError(c, "invalid_request", "unsupported subject_token_type")
		return
	}

	// Authenticate the requesting client. Token exchange must be done by a
	// registered client (confidential clients present a secret; public clients
	// are allowed but must be registered with the token-exchange grant).
	client, ok := s.authenticateExchangeClient(c)
	if !ok {
		teError(c, "invalid_client", "client authentication failed")
		return
	}
	if !contains(client.GrantTypes, grantTypeTokenExchange) {
		teError(c, "unauthorized_client", "client is not authorized for token exchange")
		return
	}

	// Validate the subject token: it must be a live token this service issued.
	subjectClaims, err := s.validateExchangeToken(subjectToken)
	if err != nil {
		teError(c, "invalid_grant", "subject_token is invalid or expired")
		return
	}
	subject, _ := subjectClaims["sub"].(string)

	// Optional actor token (delegation). When present, it identifies the party
	// acting on the subject's behalf and is recorded in the `act` claim.
	var actorClaims jwt.MapClaims
	if actorToken != "" {
		if actorTokenType != "" && !isSupportedTokenType(actorTokenType) {
			teError(c, "invalid_request", "unsupported actor_token_type")
			return
		}
		actorClaims, err = s.validateExchangeToken(actorToken)
		if err != nil {
			teError(c, "invalid_grant", "actor_token is invalid or expired")
			return
		}
	}

	// Narrow the scope: the issued token may only carry scopes present on the
	// subject token (RFC 8693 lets the AS return a narrower scope). An empty
	// request keeps the subject's scope.
	subjectScope, _ := subjectClaims["scope"].(string)
	grantedScope := narrowScope(subjectScope, requestedScope)

	// Audience: prefer the explicit audience/resource, else the requesting client.
	audience := firstNonEmptyStr(requestedAudience, requestedResource, client.ClientID)

	issued, expiresIn, err := s.issueExchangedToken(c, subject, audience, grantedScope, subjectClaims, actorClaims, client)
	if err != nil {
		s.logger.Error("token exchange: issue failed", zap.Error(err))
		teError(c, "invalid_request", "could not issue token")
		return
	}

	s.logger.Info("token exchange issued",
		zap.String("client_id", client.ClientID),
		zap.String("subject", subject),
		zap.String("audience", audience),
		zap.Bool("delegated", actorClaims != nil))

	// RFC 8693 §2.2.1 success response.
	c.JSON(http.StatusOK, gin.H{
		"access_token":      issued,
		"issued_token_type": tokenTypeAccessToken,
		"token_type":        "Bearer",
		"expires_in":        expiresIn,
		"scope":             grantedScope,
	})
}

// authenticateExchangeClient resolves + authenticates the requesting client
// from client_id/client_secret (form or Basic).
func (s *Service) authenticateExchangeClient(c *gin.Context) (*OAuthClient, bool) {
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	if clientID == "" {
		if id, secret, ok := c.Request.BasicAuth(); ok {
			clientID, clientSecret = id, secret
		}
	}
	if clientID == "" {
		return nil, false
	}
	client, err := s.GetClient(c.Request.Context(), clientID)
	if err != nil {
		return nil, false
	}
	if client.Type == "confidential" {
		if clientSecret == "" || client.ClientSecret != clientSecret {
			return nil, false
		}
	}
	return client, true
}

// validateExchangeToken parses + verifies a token this service issued and
// returns its claims. Rejects expired/invalid signatures.
func (s *Service) validateExchangeToken(token string) (jwt.MapClaims, error) {
	parsed, err := jwt.Parse(token, s.verificationKeyfunc, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, jwt.ErrTokenInvalidClaims
	}
	return claims, nil
}

// issueExchangedToken mints the new access token, carrying an `act` (actor)
// claim for delegation per RFC 8693 §4.1.
func (s *Service) issueExchangedToken(c *gin.Context, subject, audience, scope string, subjectClaims, actorClaims jwt.MapClaims, client *OAuthClient) (string, int, error) {
	now := time.Now()
	expiresIn := client.AccessTokenLifetime
	if expiresIn <= 0 {
		expiresIn = 3600
	}

	claims := jwt.MapClaims{
		"sub":       subject,
		"aud":       audience,
		"client_id": client.ClientID,
		"scope":     scope,
		"iss":       s.issuer,
		"iat":       now.Unix(),
		"exp":       now.Add(time.Duration(expiresIn) * time.Second).Unix(),
	}
	// Preserve identity claims from the subject token when present.
	for _, k := range []string{"email", "name", "roles", "groups"} {
		if v, ok := subjectClaims[k]; ok {
			claims[k] = v
		}
	}

	// Delegation: record the acting party. If the subject token already carried
	// an `act`, nest it (RFC 8693 §4.1 chained delegation).
	if actorClaims != nil {
		act := jwt.MapClaims{"sub": actorClaims["sub"]}
		if cid, ok := actorClaims["client_id"]; ok {
			act["client_id"] = cid
		}
		if prior, ok := subjectClaims["act"]; ok {
			act["act"] = prior
		}
		claims["act"] = act
	}

	kid, signKey := s.signingKey()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(signKey)
	if err != nil {
		return "", 0, err
	}
	return signed, expiresIn, nil
}

// teError writes an RFC 6749 §5.2 / RFC 8693 error response.
func teError(c *gin.Context, code, desc string) {
	c.JSON(http.StatusBadRequest, gin.H{"error": code, "error_description": desc})
}

func isSupportedTokenType(t string) bool {
	return t == tokenTypeAccessToken || t == tokenTypeJWT
}

// narrowScope returns the intersection of the subject's scopes with the
// requested scopes. An empty request keeps the subject's full scope; requesting
// a scope the subject lacks drops it (never escalates).
func narrowScope(subjectScope, requestedScope string) string {
	if strings.TrimSpace(requestedScope) == "" {
		return subjectScope
	}
	have := map[string]bool{}
	for _, s := range strings.Fields(subjectScope) {
		have[s] = true
	}
	var out []string
	for _, s := range strings.Fields(requestedScope) {
		if have[s] {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}
