package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/cell"
	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/revocation"
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
//
// WHO MAY ASK, AND FOR WHAT. The token this mints is a user's token -- their
// subject, roles and groups -- for an audience the request names, so the grant
// is held to three rules. The caller is a confidential client that proves it
// with its secret (authenticateConfidentialClient) and is registered for the
// grant: a public client's id is no secret, and anyone holding a user's token
// could otherwise trade it through one. The audience is the client itself or
// one an administrator listed for it (token_exchange_audiences): a token issued
// to one application does not become a token for another because a request
// named it. And the issued token carries no more than its subject token --
// the same organization, a subset of its scope, the same roles, OpenIDX API
// access only if both it and the client had it, and no longer a life. A
// revoked subject or actor token is refused, and the issued token dates from
// its subject token's grant, so the revocations that reach the one reach the
// other.

const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

	tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	tokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
)

// handleTokenExchangeGrant implements RFC 8693 §2.
func (s *Service) handleTokenExchangeGrant(c *gin.Context) {
	ctx := c.Request.Context()
	subjectToken := c.PostForm("subject_token")
	subjectTokenType := c.PostForm("subject_token_type")
	actorToken := c.PostForm("actor_token")
	actorTokenType := c.PostForm("actor_token_type")
	requestedScope := c.PostForm("scope")

	if subjectToken == "" {
		teError(c, "invalid_request", "subject_token is required")
		return
	}
	if subjectTokenType != "" && !isSupportedTokenType(subjectTokenType) {
		teError(c, "invalid_request", "unsupported subject_token_type")
		return
	}
	if actorToken != "" && actorTokenType != "" && !isSupportedTokenType(actorTokenType) {
		teError(c, "invalid_request", "unsupported actor_token_type")
		return
	}

	// The client first: nothing about the tokens is looked at for a caller that
	// has not proven which client it is.
	client, err := s.authenticateConfidentialClient(c)
	if err != nil {
		writeClientAuthError(c, err)
		return
	}
	if !contains(client.GrantTypes, grantTypeTokenExchange) {
		teError(c, "unauthorized_client", "client is not authorized for token exchange")
		return
	}

	audience, ok := exchangeAudience(c, client)
	if !ok {
		teError(c, "invalid_target", "the requested audience is not one this client may obtain tokens for")
		return
	}

	// Validate the subject token: it must be a live access token this service
	// issued, in the organization this request is for, and not revoked.
	subjectClaims, err := s.validateExchangeToken(ctx, subjectToken)
	if err != nil {
		teError(c, "invalid_grant", "subject_token is invalid or expired")
		return
	}
	if revoked, err := s.presentedTokenRevoked(ctx, subjectToken, subjectClaims); err != nil {
		s.logger.Warn("token exchange: revocation check failed", zap.Error(err))
		writeServerOrUnavailable(c, err)
		return
	} else if revoked {
		teError(c, "invalid_grant", "subject_token has been revoked")
		return
	}
	subject, _ := subjectClaims["sub"].(string)

	// Optional actor token (delegation). When present, it identifies the party
	// acting on the subject's behalf and is recorded in the `act` claim, so it
	// is held to the subject token's rules.
	var actorClaims jwt.MapClaims
	if actorToken != "" {
		actorClaims, err = s.validateExchangeToken(ctx, actorToken)
		if err != nil {
			teError(c, "invalid_grant", "actor_token is invalid or expired")
			return
		}
		if revoked, err := s.presentedTokenRevoked(ctx, actorToken, actorClaims); err != nil {
			s.logger.Warn("token exchange: revocation check failed", zap.Error(err))
			writeServerOrUnavailable(c, err)
			return
		} else if revoked {
			teError(c, "invalid_grant", "actor_token has been revoked")
			return
		}
	}

	// Narrow the scope: the issued token may only carry scopes present on the
	// subject token (RFC 8693 lets the AS return a narrower scope). An empty
	// request keeps the subject's scope.
	subjectScope, _ := subjectClaims["scope"].(string)
	grantedScope := narrowScope(subjectScope, requestedScope)

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

// exchangeAudience is the audience of the token an exchange issues: the one
// target the request names in audience or resource (RFC 8693 §2.1), or the
// requesting client when it names none. ok is false when the request names a
// target the client may not obtain tokens for, or names more than one: the
// issued token carries a single audience, and choosing one of several would
// silently drop the others (RFC 8693 §2.2.2, invalid_target).
func exchangeAudience(c *gin.Context, client *OAuthClient) (string, bool) {
	var target string
	for _, v := range append(c.PostFormArray("audience"), c.PostFormArray("resource")...) {
		if strings.TrimSpace(v) == "" {
			continue
		}
		if target != "" && v != target {
			return "", false
		}
		target = v
	}
	if target == "" {
		return client.ClientID, true
	}
	return target, client.mayExchangeFor(target)
}

// mayExchangeFor reports whether token exchange may issue this client a token
// for audience: its own client id, or one an administrator listed.
func (c *OAuthClient) mayExchangeFor(audience string) bool {
	if audience == c.ClientID {
		return true
	}
	return c.TokenExchangeAudiences != nil && contains(*c.TokenExchangeAudiences, audience)
}

// maxTokenExchangeAudiences and maxTokenExchangeAudienceLength bound the list
// an administrator gives a client. Both are generous for a list typed by hand;
// they exist so the column cannot grow without limit.
const (
	maxTokenExchangeAudiences      = 50
	maxTokenExchangeAudienceLength = 512
)

// ErrInvalidTokenExchangeAudiences refuses a list with an empty entry, an
// entry too long, or too many entries. The client management API answers 400
// on it.
var ErrInvalidTokenExchangeAudiences = errors.New(
	"token_exchange_audiences must hold at most 50 non-empty entries of at most 512 characters each")

func validateTokenExchangeAudiences(audiences *[]string) error {
	if audiences == nil {
		return nil
	}
	if len(*audiences) > maxTokenExchangeAudiences {
		return ErrInvalidTokenExchangeAudiences
	}
	for _, a := range *audiences {
		if a = strings.TrimSpace(a); a == "" || len(a) > maxTokenExchangeAudienceLength {
			return ErrInvalidTokenExchangeAudiences
		}
	}
	return nil
}

// marshalTokenExchangeAudiences renders the list for storage, trimmed and
// without duplicates. A nil list is nil -- SQL NULL, which the update keeps
// the stored value on -- and an empty one is `[]`, which clears it.
func marshalTokenExchangeAudiences(audiences *[]string) []byte {
	if audiences == nil {
		return nil
	}
	cleaned := make([]string, 0, len(*audiences))
	for _, a := range *audiences {
		if a = strings.TrimSpace(a); a != "" && !contains(cleaned, a) {
			cleaned = append(cleaned, a)
		}
	}
	out, err := json.Marshal(cleaned)
	if err != nil {
		return []byte("[]")
	}
	return out
}

// presentedTokenRevoked reports whether a token presented to the exchange was
// revoked: by /oauth/revoke or a sign-out, or by the per-user cutoff a
// sign-out-everywhere, a kill switch or a deprovisioning writes. An error means
// the question could not be answered, and the exchange issues nothing.
func (s *Service) presentedTokenRevoked(ctx context.Context, token string, claims jwt.MapClaims) (bool, error) {
	userID, _ := claims["sub"].(string)
	return s.IsAccessTokenRevoked(ctx, token, userID, tokenIssuedAt(claims))
}

// validateExchangeToken parses + verifies a token this service issued and
// returns its claims. Rejects expired/invalid signatures, any token that is not
// an access token, and one bound to another organization than the request's:
// the token this issues is bound to the request's organization and carries the
// subject's roles, which hold in the subject token's organization only.
//
// The exchange does not offer RFC 8693's id_token token type
// (isSupportedTokenType lists access_token and jwt), and a signature check
// alone cannot tell an ID token from an access token. The difference matters
// here more than anywhere: the exchange copies the subject's roles and groups
// into the access token it issues.
func (s *Service) validateExchangeToken(ctx context.Context, token string) (jwt.MapClaims, error) {
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
	if !middleware.IsAccessToken(parsed.Header, claims) {
		return nil, middleware.ErrNotAccessToken
	}
	if _, err := tokenOrgForRequest(ctx, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// issueExchangedToken mints the new access token, carrying an `act` (actor)
// claim for delegation per RFC 8693 §4.1.
func (s *Service) issueExchangedToken(c *gin.Context, subject, audience, scope string, subjectClaims, actorClaims jwt.MapClaims, client *OAuthClient) (string, int, error) {
	// The organization the exchange was requested in, which the client
	// authenticated in and validateExchangeToken held the subject token to.
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		return "", 0, err
	}
	now := time.Now()
	expiresIn := client.EffectiveAccessTokenLifetime()
	// No longer than the subject token lives. Minting a fresh lifetime made
	// every exchange an extension, and an exchanged token is itself an access
	// token that can be exchanged again: a token that never had to end.
	if exp, err := subjectClaims.GetExpirationTime(); err == nil && exp != nil {
		remaining := int(exp.Unix() - now.Unix())
		if remaining <= 0 {
			return "", 0, jwt.ErrTokenExpired
		}
		if remaining < expiresIn {
			expiresIn = remaining
		}
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

	// The issued token dates from its subject token's grant, not from now
	// (revocation.GrantedAtClaim): a per-user cutoff that revokes the subject
	// token -- a sign-out everywhere, a kill switch, a deprovisioning, even one
	// written between the check above and this line -- revokes this one too.
	if from := tokenIssuedAt(subjectClaims); from.Seconds > 0 {
		claims[revocation.GrantedAtClaim] = from.EarliestMicros()
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

	// The cell stamp is resolved fresh rather than copied from the subject
	// token. The loop above preserves identity claims because they describe the
	// SUBJECT; `cell` describes where the subject's tenant LIVES, and a value
	// copied out of a presented token is a value the presenter chose.
	//
	// It matters more here than on the other two mint paths. oauth-service does
	// not mount cell.Guard (cmd/cell_guard_census_test.go records why), so a
	// subject token minted in another cell can reach this exchange and be
	// verified by the shared key. Stamping this process's own cell would then
	// hand back a token that every guard in THIS cell accepts, for a tenant
	// whose rows are somewhere else -- the same misdirection as a misrouted
	// login, one exchange deeper. Resolving the tenant's home cell means the
	// exchanged token inherits the disagreement instead of laundering it.
	if s.cellID != "" {
		stamp := s.cellID
		if tc := s.tokenCell(c.Request.Context(), org.ID); tc != "" {
			stamp = tc
		}
		claims[cell.Claim] = stamp
	}

	// Whether the issued token may call OpenIDX's own APIs follows the client
	// that asked for it, and never exceeds what the subject token could do:
	// like the scope above, an exchange narrows and does not widen, so it is
	// not a way to turn a third-party application's token into one the APIs
	// accept.
	apiAccess := client.MayCallAPI() && middleware.HasAPIAccess(subjectClaims)

	kid, signKey := s.signingKey()
	signed, err := newAccessToken(claims, kid, org.ID, apiAccess).SignedString(signKey)
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
