// Package oauth - the browser session /oauth/authorize reads (single sign-on).
//
// Until this file existed, every /oauth/authorize request minted a fresh
// login_session and sent the browser to the login page — the second, third and
// tenth application a signed-in user opened each asked for the password again.
// docs/OAUTH-OIDC.md had promised "users log in once and access all connected
// applications" the whole time; nothing behind /oauth/authorize read anything
// a browser could carry between two requests. That is a declared capability
// with no implementation, and the global-scale plan (item 5c) measured it as
// such before deferring it.
//
// The design is the smallest one that makes the sentence true:
//
//   - A login completion (password, MFA, passwordless, social, consent) already
//     creates an identity `sessions` row and passes its id through oauthParams
//     to issueAuthorizationCode. That one function now also sets a browser
//     cookie, openidx_sso, holding a random token that Redis maps to the
//     session id (sso_session:<token>). The cookie carries no session id, no
//     user id, nothing a reader could use elsewhere; it is HttpOnly, SameSite
//     Lax, Secure, and lives as long as the session (24h). Secure is
//     unconditional: the cookie is a credential for /oauth/authorize, the
//     issuer is https wherever it is deployed (the compose stack terminates
//     TLS at oauth.localtest.me:8446), and a plain-http developer instance
//     simply gets no SSO, which is what it had before.
//   - /oauth/authorize, after it has validated client, redirect_uri, scope and
//     response_type exactly as before, reads that cookie. A token that resolves
//     to a live, unrevoked, unexpired session of the request's tenant mints a
//     code through the same gates the login flow uses (assignment/ABAC, then
//     consent) and redirects to the client. Anything less than that — no
//     cookie, a token Redis has forgotten, a session revoked or expired or
//     deleted, a session older than max_age, prompt=login — falls through to
//     the login flow that has always been there. A cookie that resolves to
//     nothing is cleared so the browser stops sending it.
//   - prompt (OIDC Core §3.1.2.1) and max_age are honoured because SSO gives
//     them a meaning: prompt=none MUST NOT show any UI, so without a usable
//     session it answers login_required at the redirect_uri (§3.1.2.6) instead
//     of a login page; prompt=login forces re-authentication; prompt=consent
//     and select_account need a UI and so take the interactive path.
//   - /oauth/logout ends the browser session too: the cookie's session is
//     revoked (DB + revocation marker), the Redis mapping deleted, the cookie
//     cleared — otherwise a user who signed out of one application would be
//     signed straight back in by the next /oauth/authorize.
//
// Consent is enforced by the consent UI the login page renders from the JSON
// challenge beginConsent returns; a top-level GET navigation cannot render that
// JSON. So a session that needs consent takes the login path (which shows the
// consent screen after — not instead of — a credential check the user already
// passed once), and under prompt=none it is consent_required. Forcing consent
// to be re-shown (prompt=consent) is likewise the interactive path's job.
//
// Same-origin only, and said plainly: the cookie is set on the response to the
// login page's fetch of /oauth/login. In the production layout (nginx serves
// the console and the issuer from one origin) that fetch is same-origin and the
// cookie is stored and later sent with the top-level /oauth/authorize
// navigation. In the reference compose stack the console (localhost:3000) and
// the issuer (oauth.localtest.me:8446) are different origins, the login fetch
// is cross-origin without credentials, and the cookie is never stored — SSO is
// simply absent there, which is the status quo, not a regression. Widening
// that would mean Allow-Credentials on the login endpoint, and that is a
// separate decision this file does not take.
package oauth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

const (
	// ssoCookieName is the browser cookie /oauth/authorize reads. It is a
	// random token, never the session id.
	ssoCookieName = "openidx_sso"
	// ssoCookieTTL matches the identity session lifetime the login flows
	// create (24h). The DB row's expires_at is authoritative; this only stops
	// a browser from presenting a cookie that can no longer resolve.
	ssoCookieTTL = 24 * time.Hour
	// ssoRedisPrefix maps token → session id in the session Redis.
	ssoRedisPrefix = "sso_session:"

	// OIDC Core §3.1.2.6 error codes an /authorize request with prompt=none
	// can receive at its redirect_uri.
	ErrorLoginRequired       = "login_required"
	ErrorConsentRequired     = "consent_required"
	ErrorInteractionRequired = "interaction_required"
)

// authorizePrompt is the parsed `prompt` parameter (OIDC Core §3.1.2.1), a
// space-delimited, case-sensitive list of none / login / consent /
// select_account.
type authorizePrompt struct {
	None          bool
	Login         bool
	Consent       bool
	SelectAccount bool
}

// needsUI reports whether the prompt asks for an interaction that only the
// login page can render, so an existing session must not short-circuit it.
func (p authorizePrompt) needsUI() bool {
	return p.Login || p.Consent || p.SelectAccount
}

// parsePrompt parses `prompt`. "none" combined with any other value is an
// error (§3.1.2.1: "If this parameter contains none with any other value, an
// error is returned"). Unknown values are an error too — silently ignoring a
// value we do not implement would make a client believe it was honoured.
func parsePrompt(raw string) (authorizePrompt, error) {
	var p authorizePrompt
	fields := strings.Fields(raw)
	for _, f := range fields {
		switch f {
		case "none":
			p.None = true
		case "login":
			p.Login = true
		case "consent":
			p.Consent = true
		case "select_account":
			p.SelectAccount = true
		default:
			return authorizePrompt{}, errors.New("prompt contains an unsupported value")
		}
	}
	if p.None && p.needsUI() {
		return authorizePrompt{}, errors.New("prompt=none cannot be combined with other values")
	}
	return p, nil
}

// parseMaxAge parses `max_age` (seconds since authentication after which the
// user must re-authenticate). ok is false when the parameter is absent.
func parseMaxAge(raw string) (maxAge time.Duration, ok bool, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false, nil
	}
	secs, perr := strconv.ParseInt(raw, 10, 64)
	if perr != nil || secs < 0 {
		return 0, false, errors.New("max_age must be a non-negative integer")
	}
	return time.Duration(secs) * time.Second, true, nil
}

// browserSession is what an openidx_sso cookie resolves to: a live identity
// session of the request's tenant.
type browserSession struct {
	ID        string
	UserID    string
	StartedAt time.Time
}

// resolveBrowserSession turns a cookie token into a live session. usable is
// false — with err nil — for every stale shape: a token Redis has forgotten,
// a session row that is missing (terminated / offboarded), revoked, expired,
// or belonging to another tenant. A stale Redis mapping is deleted on the way
// out. err is set only for a real dependency failure, which the caller must
// not read as "no session".
func (s *Service) resolveBrowserSession(ctx context.Context, token string) (sess *browserSession, usable bool, err error) {
	if token == "" || !isValidBase64URLToken(token) || s.redis == nil || s.db == nil {
		return nil, false, nil
	}
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, false, nil
	}
	sessionID, rerr := s.redis.Client.Get(ctx, ssoRedisPrefix+token).Result()
	if rerr != nil {
		if errors.Is(rerr, redis.Nil) {
			return nil, false, nil
		}
		return nil, false, rerr
	}

	var (
		userID    string
		startedAt time.Time
		revoked   bool
		expiresAt time.Time
	)
	qerr := s.db.Pool.QueryRow(ctx,
		`SELECT user_id, started_at, COALESCE(revoked, false), expires_at
		   FROM sessions WHERE id = $1 AND org_id = $2`,
		sessionID, org.ID).Scan(&userID, &startedAt, &revoked, &expiresAt)
	if qerr != nil {
		if errors.Is(qerr, pgx.ErrNoRows) {
			s.redis.Client.Del(ctx, ssoRedisPrefix+token)
			return nil, false, nil
		}
		return nil, false, qerr
	}
	if revoked || !expiresAt.After(time.Now()) {
		s.redis.Client.Del(ctx, ssoRedisPrefix+token)
		return nil, false, nil
	}
	return &browserSession{ID: sessionID, UserID: userID, StartedAt: startedAt}, true, nil
}

// sessionBelongsTo reports whether sessionID is a live (unrevoked, unexpired)
// session of userID in the request's tenant. It is the check every path that
// accepts a session id FROM THE CLIENT must make before binding that id to a
// code or a token: the session row is where sid, amr and auth_time come from,
// and a caller must not be able to borrow another user's. A malformed id, a
// missing database or a missing tenant context all answer false — the caller
// then refuses, never guesses.
func (s *Service) sessionBelongsTo(ctx context.Context, sessionID, userID string) bool {
	if sessionID == "" || userID == "" || !isValidSessionID(sessionID) || s.db == nil {
		return false
	}
	org, err := orgctx.From(ctx)
	if err != nil {
		return false
	}
	var one int
	err = s.db.Pool.QueryRow(ctx, `
		SELECT 1 FROM sessions
		 WHERE id = $1 AND user_id = $2 AND org_id = $3
		   AND COALESCE(revoked, false) = false AND expires_at > NOW()`,
		sessionID, userID, org.ID).Scan(&one)
	return err == nil
}

// setBrowserSessionCookie binds a fresh random token to sessionID in Redis and
// sets it as the openidx_sso cookie. Called from the one code-issuance path
// every login completion goes through, so every way of signing in produces a
// browser session and none can forget to.
func (s *Service) setBrowserSessionCookie(c *gin.Context, sessionID string) {
	if sessionID == "" || s.redis == nil {
		return
	}
	token := GenerateRandomToken(32)
	if err := s.redis.Client.Set(c.Request.Context(), ssoRedisPrefix+token, sessionID, ssoCookieTTL).Err(); err != nil {
		// No mapping, no cookie: a cookie nothing can resolve would only be
		// cleared on the next /authorize. The login itself succeeded.
		s.logger.Warn("browser session mapping not stored; SSO cookie not set", zap.Error(err))
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     ssoCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(ssoCookieTTL / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearBrowserSessionCookie tells the browser to drop openidx_sso.
func (s *Service) clearBrowserSessionCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     ssoCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// endBrowserSession is /oauth/logout's half: the session the cookie names is
// revoked (DB + revocation marker), the Redis mapping is deleted and the cookie
// cleared. It returns the id of the session it ended, or "".
func (s *Service) endBrowserSession(c *gin.Context) string {
	token, err := c.Cookie(ssoCookieName)
	if err != nil || token == "" {
		return ""
	}
	// Whatever happens below, the browser must stop presenting this cookie.
	s.clearBrowserSessionCookie(c)
	if !isValidBase64URLToken(token) || s.redis == nil {
		return ""
	}
	ctx := c.Request.Context()
	sessionID, rerr := s.redis.Client.Get(ctx, ssoRedisPrefix+token).Result()
	if rerr != nil {
		return ""
	}
	s.redis.Client.Del(ctx, ssoRedisPrefix+token)
	if s.db == nil || !isValidSessionID(sessionID) {
		return ""
	}
	if err := s.revokeSessionWithRedis(ctx, sessionID); err != nil {
		s.logger.Warn("browser session revoke failed at logout", zap.String("session_id", sessionID), zap.Error(err))
	}
	return sessionID
}

// authorizeFromBrowserSession is the SSO fast path of /oauth/authorize. It runs
// after the request has been validated against the client and returns true
// when it has written the response (a code redirect, or a prompt=none error at
// the redirect_uri, or a dependency failure). false means "no usable session
// for this request": the caller continues into the interactive login flow.
//
// Order matters and mirrors issueAuthorizationCode: the assignment gate runs
// before anything is minted (TestEveryMintSiteCallsAssignmentGate checks the
// wiring in source), then consent, then the code.
func (s *Service) authorizeFromBrowserSession(c *gin.Context, oauthParams map[string]string, prompt authorizePrompt, maxAge time.Duration, maxAgeSet bool) bool {
	redirectURI, state := oauthParams["redirect_uri"], oauthParams["state"]

	// A prompt that needs UI never rides an existing session.
	if prompt.needsUI() {
		return false
	}

	token, cerr := c.Cookie(ssoCookieName)
	if cerr != nil || token == "" {
		if prompt.None {
			s.redirectAuthorizeError(c, redirectURI, state, ErrorLoginRequired, "no authenticated session")
			return true
		}
		return false
	}

	ctx := c.Request.Context()
	sess, usable, err := s.resolveBrowserSession(ctx, token)
	if err != nil {
		writeServerOrUnavailable(c, err)
		return true
	}
	if !usable {
		s.clearBrowserSessionCookie(c)
		if prompt.None {
			s.redirectAuthorizeError(c, redirectURI, state, ErrorLoginRequired, "no authenticated session")
			return true
		}
		return false
	}
	if maxAgeSet && time.Since(sess.StartedAt) > maxAge {
		// The session is real but older than the client will accept: the
		// cookie stays (another client may accept it), the user re-authenticates.
		if prompt.None {
			s.redirectAuthorizeError(c, redirectURI, state, ErrorLoginRequired, "authentication is older than max_age")
			return true
		}
		return false
	}

	oauthParams["session_id"] = sess.ID

	if !s.assignmentGateAllows(c, oauthParams["client_id"], sess.UserID) {
		return true
	}

	required, cerr2 := s.consentRequired(ctx, oauthParams["client_id"], sess.UserID, oauthParams["scope"])
	if cerr2 != nil {
		s.logger.Error("consent check failed", zap.Error(cerr2))
		c.JSON(500, gin.H{"error": ErrorServerError})
		return true
	}
	if required {
		if prompt.None {
			s.redirectAuthorizeError(c, redirectURI, state, ErrorConsentRequired, "consent is required for this client")
			return true
		}
		// The consent screen is rendered by the login page; take that path.
		return false
	}

	code := GenerateRandomToken(32)
	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            oauthParams["client_id"],
		UserID:              sess.UserID,
		RedirectURI:         redirectURI,
		Scope:               oauthParams["scope"],
		State:               state,
		Nonce:               oauthParams["nonce"],
		CodeChallenge:       oauthParams["code_challenge"],
		CodeChallengeMethod: oauthParams["code_challenge_method"],
	}
	if err := s.CreateAuthorizationCode(ctx, authCode); err != nil {
		writeServerOrUnavailable(c, err)
		return true
	}
	s.redis.Client.Set(ctx, "authcode_session:"+code, sess.ID, 5*time.Minute)

	s.logAuditEvent(ctx, "authentication", "oauth", "sso_authorize", "success",
		sess.UserID, c.ClientIP(), oauthParams["client_id"], "client",
		map[string]interface{}{"client_id": oauthParams["client_id"], "session_id": sess.ID})

	c.Redirect(302, authorizationRedirectURL(redirectURI, code, state))
	return true
}
