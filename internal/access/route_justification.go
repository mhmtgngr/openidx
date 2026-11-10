package access

// Purpose justification on proxied applications (migration 244).
//
// A route with require_justification asks a signed-in person, whom the access
// decision has already admitted, why they are opening the application, once
// per proxy session for the route's TTL, before anything is forwarded. The
// reason is audited (proxy.access_justified, in the unified audit log, with
// the person, the route and the text). It is a step after the decision and
// never replaces it: someone the decision refuses never sees the form.
//
// A browser navigation is sent to a form at /access/.auth/justify on the
// application's own host; any other request is answered 403
// justification_required, so an API client is not handed an HTML page. The
// form is bound to the proxy session that asks (a one-use token in Redis
// keyed to that session and route), and served under a policy that admits
// nothing but its own nonce'd style and posting to itself.
//
// A bearer-token caller has no proxy session to remember the answer on, so
// on a route that requires a justification it is refused with
// justification_required; such a route is for people in a browser.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

const (
	justificationMinLen = 10
	justificationMaxLen = 500
	// justificationFormTTL is how long a served form can be submitted.
	justificationFormTTL = 15 * time.Minute
	justifyPath          = "/access/.auth/justify"
	auditAccessJustified = "proxy.access_justified"
)

func justifiedKey(sessionID, routeID string) string {
	return "proxy_justified:" + sessionID + ":" + routeID
}

func justifyFormKey(token string) string { return "proxy_justify_form:" + token }

// wantsHTML reports whether the request is a browser navigation: a GET that
// accepts HTML.
func wantsHTML(c *gin.Context) bool {
	return c.Request.Method == http.MethodGet && strings.Contains(c.GetHeader("Accept"), "text/html")
}

// justificationGate answers a request the decision admitted on a route that
// requires a justification and has none on record for this session. ok is
// false when it has answered (a redirect to the form or a 403).
func (s *Service) justificationGate(c *gin.Context, route *ProxyRoute, session *ProxySession, originalURI string, navigation bool) (ok bool) {
	if route == nil || !route.RequireJustification || session == nil {
		return true
	}
	if session.ID != "" && session.bearer == "" {
		if n, err := s.redis.Client.Exists(c.Request.Context(), justifiedKey(session.ID, route.ID)).Result(); err == nil && n == 1 {
			return true
		}
	}
	if navigation && session.ID != "" && session.bearer == "" {
		if originalURI == "" {
			originalURI = "/"
		}
		c.Redirect(http.StatusFound, justifyPath+"?redirect_url="+url.QueryEscape(originalURI))
		return false
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "this application asks why you are opening it; open it in a browser", "code": "justification_required"})
	return false
}

type justifyPageData struct {
	Nonce, Route, Token, Redirect, Error string
	Min, Max                             int
}

var justifyPageTemplate = template.Must(template.New("justify").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenIDX - Why are you opening {{.Route}}?</title>
<style nonce="{{.Nonce}}">
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;border-radius:12px;padding:2rem;width:100%;max-width:480px}
h1{font-size:1.25rem;margin-bottom:.5rem;color:#f8fafc}
p{color:#94a3b8;font-size:.875rem;margin-bottom:1rem}
textarea{width:100%;min-height:7rem;padding:.75rem;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#f8fafc;font-size:1rem;margin-bottom:1rem}
button{width:100%;padding:.75rem;background:#3b82f6;color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer}
.err{color:#fca5a5}
</style>
</head>
<body>
<form class="card" method="POST" action="/access/.auth/justify">
<h1>Why are you opening {{.Route}}?</h1>
<p>Your reason is recorded with your name before the application opens.</p>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<textarea name="reason" required minlength="{{.Min}}" maxlength="{{.Max}}" aria-label="Reason"></textarea>
<input type="hidden" name="token" value="{{.Token}}">
<input type="hidden" name="redirect_url" value="{{.Redirect}}">
<button type="submit">Continue</button>
</form>
</body>
</html>
`))

func justifyPageCSP(nonce string) string {
	return "default-src 'none'; style-src 'nonce-" + nonce + "'; form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"
}

// justifyContext is the route and cookie session a justify request is for:
// the route its host serves and the proxy session issued for that host. A
// caller with no proxy cookie is refused (401) before anything is read: the
// proxy only sends a signed-in browser here.
func (s *Service) justifyContext(c *gin.Context) (*ProxyRoute, *ProxySession, bool) {
	if cookie, err := c.Cookie(proxySessionCookie); err != nil || cookie == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "sign in to the application first"})
		return nil, nil, false
	}
	host := s.browserHost(c)
	route, err := s.findRouteByHost(c.Request.Context(), host)
	if err != nil || route == nil || !route.RequireJustification {
		c.JSON(http.StatusNotFound, gin.H{"error": "nothing to justify here"})
		return nil, nil, false
	}
	session := sessionOnRoute(s.getSessionFromRequest(c, host), route)
	if session == nil || session.ID == "" {
		c.Redirect(http.StatusFound, "/access/.auth/login?redirect_url="+url.QueryEscape(c.Query("redirect_url")))
		return nil, nil, false
	}
	return route, session, true
}

func (s *Service) serveJustifyPage(c *gin.Context, route *ProxyRoute, session *ProxySession, redirect, problem string, status int) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not render the page"})
		return
	}
	token := hex.EncodeToString(raw[:16])
	nonce := hex.EncodeToString(raw[16:])
	if err := s.redis.Client.Set(c.Request.Context(), justifyFormKey(token), session.ID+"|"+route.ID, justificationFormTTL).Err(); err != nil {
		s.logger.Error("justify: could not store the form token", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "could not render the page"})
		return
	}
	var page bytes.Buffer
	if err := justifyPageTemplate.Execute(&page, justifyPageData{
		Nonce: nonce, Route: route.Name, Token: token, Redirect: redirect, Error: problem,
		Min: justificationMinLen, Max: justificationMaxLen,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not render the page"})
		return
	}
	c.Header("Content-Security-Policy", justifyPageCSP(nonce))
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	c.Data(status, "text/html; charset=utf-8", page.Bytes())
}

// handleJustifyForm — GET /access/.auth/justify: the form, for the proxy
// session of the route this host serves.
func (s *Service) handleJustifyForm(c *gin.Context) {
	route, session, ok := s.justifyContext(c)
	if !ok {
		return
	}
	s.serveJustifyPage(c, route, session, s.redirectTarget(c, c.Query("redirect_url"), "/"), "", http.StatusOK)
}

// handleJustifySubmit — POST /access/.auth/justify: record the reason, then
// go where the person was going.
func (s *Service) handleJustifySubmit(c *gin.Context) {
	route, session, ok := s.justifyContext(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	redirect := s.redirectTarget(c, c.PostForm("redirect_url"), "/")
	token := c.PostForm("token")
	if len(token) != 32 {
		c.JSON(http.StatusForbidden, gin.H{"error": "this form has expired; open the application again"})
		return
	}
	// One use: the token is taken whatever happens next, and must name this
	// session and this route.
	bound, err := s.redis.Client.GetDel(ctx, justifyFormKey(token)).Result()
	if err != nil || bound != session.ID+"|"+route.ID {
		c.JSON(http.StatusForbidden, gin.H{"error": "this form has expired; open the application again"})
		return
	}
	reason := strings.TrimSpace(c.PostForm("reason"))
	if n := utf8.RuneCountInString(reason); n < justificationMinLen || n > justificationMaxLen || !utf8.ValidString(reason) {
		s.serveJustifyPage(c, route, session, redirect,
			fmt.Sprintf("Write a reason of %d to %d characters.", justificationMinLen, justificationMaxLen), http.StatusBadRequest)
		return
	}
	// The audit record first: a reason that is not recorded does not open
	// the application.
	if s.auditService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "the reason could not be recorded"})
		return
	}
	if err := s.auditService.RecordEvent(ctx, "proxy", auditAccessJustified, route.ID, session.UserID, c.ClientIP(),
		map[string]interface{}{"route": route.Name, "reason": reason, "session_id": session.ID,
			"valid_minutes": route.JustificationTTLMinutes}); err != nil {
		s.logger.Error("justify: audit failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "the reason could not be recorded"})
		return
	}
	ttl := time.Duration(route.JustificationTTLMinutes) * time.Minute
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	if err := s.redis.Client.Set(ctx, justifiedKey(session.ID, route.ID), "1", ttl).Err(); err != nil {
		s.logger.Error("justify: could not remember the reason", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "the reason could not be recorded"})
		return
	}
	c.Redirect(http.StatusSeeOther, redirect)
}

// handleSetRouteJustification — PUT /routes/:id/justification (admin): turn
// the question on or off for one route and set how long an answer holds.
// Its own endpoint, audited on its own, rather than one more field of the
// route form: loosening it is a decision worth its own line in the trail.
func (s *Service) handleSetRouteJustification(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var req struct {
		Require    *bool `json:"require_justification"`
		TTLMinutes *int  `json:"justification_ttl_minutes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Require == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "require_justification is required"})
		return
	}
	ttl := 480
	if req.TTLMinutes != nil {
		ttl = *req.TTLMinutes
	}
	if ttl < 5 || ttl > 1440 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "justification_ttl_minutes must be between 5 and 1440"})
		return
	}
	id := c.Param("id")
	tag, err := s.db.Pool.Exec(c.Request.Context(), `UPDATE proxy_routes
		   SET require_justification = $1, justification_ttl_minutes = $2, updated_at = NOW()
		 WHERE id::text = $3 AND org_id = $4`, *req.Require, ttl, id, org.ID)
	if err != nil {
		s.logger.Error("set route justification", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update the route"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
		return
	}
	s.logAuditEvent(c, "proxy_route_justification_set", id, "proxy_route", map[string]interface{}{
		"require_justification": *req.Require, "justification_ttl_minutes": ttl,
	})
	c.JSON(http.StatusOK, gin.H{"id": id, "require_justification": *req.Require, "justification_ttl_minutes": ttl})
}
