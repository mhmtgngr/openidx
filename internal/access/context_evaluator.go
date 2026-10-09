// Package access - Context-aware access evaluation engine for zero-trust proxy decisions
package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// AccessContext holds all contextual data about a request for policy evaluation
type AccessContext struct {
	Session        *ProxySession
	Route          *ProxyRoute
	ClientIP       string
	UserAgent      string
	GeoCountry     string
	GeoCity        string
	IPThreatType   string
	IPBlocked      bool
	DeviceTrusted  bool
	PostureScore   float64
	PostureResults []PostureCheckResult
	Timestamp      time.Time
	OriginalMethod string
	OriginalURI    string
}

// AccessDecision is the result of context-aware evaluation
type AccessDecision struct {
	Allowed        bool   `json:"allowed"`
	Reason         string `json:"reason,omitempty"`
	StepUpRequired bool   `json:"step_up_required,omitempty"`
	RiskScore      int    `json:"risk_score"`
}

// buildAccessContext gathers all contextual information about the current request
func (s *Service) buildAccessContext(c *gin.Context, route *ProxyRoute, session *ProxySession) (*AccessContext, error) {
	ctx := c.Request.Context()
	ac := &AccessContext{
		Session:   session,
		Route:     route,
		ClientIP:  c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		Timestamp: time.Now(),
	}

	// IP geolocation
	country, city := s.lookupIPGeo(ctx, ac.ClientIP)
	ac.GeoCountry = country
	ac.GeoCity = city

	// IP threat check
	threatType, blocked := s.checkIPThreat(ctx, ac.ClientIP)
	ac.IPThreatType = threatType
	ac.IPBlocked = blocked

	// Device trust: is the request's device a trusted known_device? Computed per
	// request and written back to the session so the value also reaches the inline
	// policy DSL and the governance /evaluate call (both read session.DeviceTrusted).
	trusted := s.deviceTrusted(ctx, session.UserID, ac.ClientIP, ac.UserAgent)
	ac.DeviceTrusted = trusted
	session.DeviceTrusted = trusted
	// If an untrusted device is hitting a route that requires device trust, file a
	// pending trust request (best-effort, deduped) so an admin can approve it.
	if !trusted && route.RequireDeviceTrust {
		s.ensureDeviceTrustRequest(ctx, session.UserID, ac.ClientIP, ac.UserAgent)
	}

	// Posture evaluation (if ZitiManager is available and route has posture check IDs)
	if s.ziti() != nil && len(route.PostureCheckIDs) > 0 {
		// Find the Ziti identity for this user
		var identityUUID string
		// Bypass RLS: forward-auth has no resolved org; keyed by the
		// already-authenticated session user_id (globally unique).
		//
		// A user with no Ziti identity yet is the normal negative and arrives as
		// pgx.ErrNoRows. Anything else means the lookup did not run, and the
		// discarded error left identityUUID empty -- so the posture checks this
		// route DECLARES were skipped entirely, silently. device.posture_score
		// stays 0, which a policy requiring posture reads as a failure, so the
		// direction is safe; the silence is not.
		if err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
			//orgscope:ignore proxy data-plane posture eval; resolves the Ziti identity for the already-authenticated session user by user_id on every forward-auth request
			"SELECT id FROM ziti_identities WHERE user_id=$1 LIMIT 1", // id (uuid) — device_posture_results.identity_id is a uuid
			session.UserID).Scan(&identityUUID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Warn("could not resolve the Ziti identity; posture checks were not evaluated",
				logsafe.String("user_id", session.UserID), zap.Error(err))
		}

		if identityUUID != "" {
			passed, results, err := s.ziti().EvaluateIdentityPosture(ctx, identityUUID)
			if err != nil {
				s.logger.Warn("Posture evaluation failed during context build", zap.Error(err))
			} else {
				ac.PostureResults = results
				if passed {
					ac.PostureScore = 1.0
				} else {
					// Compute partial score
					total := len(results)
					passedCount := 0
					for _, r := range results {
						if r.Passed {
							passedCount++
						}
					}
					if total > 0 {
						ac.PostureScore = float64(passedCount) / float64(total)
					}
				}
			}
		}
	}

	return ac, nil
}

// evaluateAccessContext runs all context checks in priority order
// (fail-closed): what the request itself says, then the route's conditions,
// then its inline policy. The two proxy paths call the halves separately,
// with the shared reach decision between them (see handleProxy).
func (s *Service) evaluateAccessContext(ac *AccessContext) *AccessDecision {
	risk, early := s.scoreAccessContext(ac)
	if early != nil {
		return early
	}
	return s.judgeRouteContext(ac, risk, true)
}

// scoreAccessContext is what the request itself says, before any condition
// is read: a blocked address refuses outright; a threat-listed one, a changed
// user agent, an untrusted device and a weak posture raise the risk score; a
// posture score of zero refuses. The score is what the resource's risk
// ceiling is judged against.
func (s *Service) scoreAccessContext(ac *AccessContext) (risk int, early *AccessDecision) {
	riskScore := 0

	// 1. IP threat list — hard block
	if ac.IPBlocked {
		return riskScore, &AccessDecision{
			Allowed:   false,
			Reason:    fmt.Sprintf("access denied: IP %s is blocked (threat type: %s)", ac.ClientIP, ac.IPThreatType),
			RiskScore: 100,
		}
	}
	if ac.IPThreatType != "" {
		riskScore += 30
	}

	// 3. User-Agent pinning — detect session hijacking via UA change
	if ac.Session.UserAgent != "" && ac.UserAgent != "" && ac.UserAgent != ac.Session.UserAgent {
		// Classify severity: major change (different browser/OS) vs minor (version bump)
		if isMajorUAChange(ac.Session.UserAgent, ac.UserAgent) {
			s.logger.Warn("User-Agent major change detected — possible session hijacking",
				zap.String("session_id", ac.Session.ID),
				zap.String("original_ua", ac.Session.UserAgent),
				zap.String("current_ua", ac.UserAgent),
			)
			riskScore += 35
		} else {
			s.logger.Info("User-Agent minor change detected",
				zap.String("session_id", ac.Session.ID),
			)
			riskScore += 10
		}
	}

	if !ac.DeviceTrusted {
		riskScore += 15
	}

	// 5. Posture score check (route must have posture_check_ids configured)
	if len(ac.Route.PostureCheckIDs) > 0 && ac.PostureScore < 0.5 {
		riskScore += 25
		if ac.PostureScore == 0 {
			return riskScore, &AccessDecision{
				Allowed:        false,
				Reason:         "access denied: device posture check failed",
				StepUpRequired: true,
				RiskScore:      75,
			}
		}
	}

	// Cap risk score at 100
	if riskScore > 100 {
		riskScore = 100
	}

	return riskScore, nil
}

// judgeRouteContext applies the route's own conditions — geo-fence, device
// trust, risk ceiling — and then its inline policy. routeConditionsRule is
// false when the route's application declares resource_conditions: the shared
// reach decision judged those with this same situation, and the columns on
// the route are the pre-228 copy kept for rollback, so judging them again
// would let a stale copy overrule the resource. The inline policy has no
// counterpart on the resource and always runs.
func (s *Service) judgeRouteContext(ac *AccessContext, riskScore int, routeConditionsRule bool) *AccessDecision {
	if routeConditionsRule {
		// 2. Geo-fence check
		if len(ac.Route.AllowedCountries) > 0 && ac.GeoCountry != "" {
			allowed := false
			for _, c := range ac.Route.AllowedCountries {
				if strings.EqualFold(c, ac.GeoCountry) {
					allowed = true
					break
				}
			}
			if !allowed {
				return &AccessDecision{
					Allowed:   false,
					Reason:    fmt.Sprintf("access denied: country %s not in allowed list", ac.GeoCountry),
					RiskScore: 80,
				}
			}
		}

		// 4. Device trust check
		if ac.Route.RequireDeviceTrust && !ac.DeviceTrusted {
			return &AccessDecision{
				Allowed:        false,
				Reason:         "access denied: device is not trusted",
				StepUpRequired: true,
				RiskScore:      70,
			}
		}
		// 6. Risk score threshold
		if ac.Route.MaxRiskScore > 0 && riskScore > ac.Route.MaxRiskScore {
			return &AccessDecision{
				Allowed:        false,
				Reason:         fmt.Sprintf("access denied: risk score %d exceeds maximum %d", riskScore, ac.Route.MaxRiskScore),
				StepUpRequired: true,
				RiskScore:      riskScore,
			}
		}

	}

	// 7. Inline policy DSL evaluation
	if ac.Route.InlinePolicy != "" {
		policyCtx := &PolicyContext{
			UserEmail:     ac.Session.Email,
			UserRoles:     ac.Session.Roles,
			RequestIP:     ac.ClientIP,
			DeviceTrusted: ac.DeviceTrusted,
			PostureScore:  ac.PostureScore,
			TimeHour:      ac.Timestamp.Hour(),
			GeoCountry:    ac.GeoCountry,
			RiskScore:     riskScore,
			RequestMethod: ac.OriginalMethod,
			RequestPath:   ac.OriginalURI,
		}

		allowed, err := EvaluatePolicyString(ac.Route.InlinePolicy, policyCtx)
		if err != nil {
			s.logger.Error("Inline policy evaluation error", zap.Error(err))
			// Fail closed
			return &AccessDecision{
				Allowed:   false,
				Reason:    "access denied: policy evaluation error",
				RiskScore: riskScore,
			}
		}
		if !allowed {
			return &AccessDecision{
				Allowed:   false,
				Reason:    "access denied: inline policy denied",
				RiskScore: riskScore,
			}
		}
	}

	return &AccessDecision{
		Allowed:   true,
		RiskScore: riskScore,
	}
}

// refuseOnContext answers a context refusal the way both proxy paths always
// have: the audit row first, the step-up header when a fresh factor or a
// trusted device would change the answer, then the 403.
func (s *Service) refuseOnContext(c *gin.Context, route *ProxyRoute, session *ProxySession, d *AccessDecision, path, method string) {
	details := map[string]interface{}{
		"reason":  d.Reason,
		"user_id": session.UserID,
		"path":    path,
	}
	if method != "" {
		details["method"] = method
	}
	s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", details)
	if d.StepUpRequired {
		c.Header("X-Step-Up-Required", "true")
	}
	c.JSON(http.StatusForbidden, gin.H{"error": d.Reason})
}

// lookupIPGeo returns the country code and city for an IP address, using cache
func (s *Service) lookupIPGeo(ctx context.Context, ip string) (country, city string) {
	if ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return "", ""
	}

	// Check database cache
	err := s.db.Pool.QueryRow(ctx,
		`SELECT country_code, city FROM ip_geolocation_cache WHERE ip_address=$1 AND cached_at > NOW() - INTERVAL '24 hours'`,
		ip).Scan(&country, &city)
	if err == nil {
		return country, city
	}

	// Check request headers (set by upstream proxies/CDNs)
	// These headers are commonly set by APISIX, Cloudflare, AWS ALB, etc.
	if country == "" {
		// Try common geo headers (not available through gin.Context here, store in session later)
		return "", ""
	}

	// If a GeoIP service URL is configured, call it
	if s.config.GeoIPServiceURL != "" {
		geoCountry, geoCity := s.fetchGeoIP(ctx, ip)
		if geoCountry != "" {
			// Cache the result.
			//silentwrite:ok the caller is served the country and city that were just fetched either way; a failed cache write costs one extra call to the GeoIP service on the next lookup for this address, and the row is re-written on that call
			s.db.Pool.Exec(ctx,
				`INSERT INTO ip_geolocation_cache (ip_address, country_code, city, cached_at)
				 VALUES ($1, $2, $3, NOW())
				 ON CONFLICT (ip_address) DO UPDATE SET country_code=$2, city=$3, cached_at=NOW()`,
				ip, geoCountry, geoCity)
			return geoCountry, geoCity
		}
	}

	return "", ""
}

func (s *Service) fetchGeoIP(ctx context.Context, ip string) (country, city string) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/%s", s.config.GeoIPServiceURL, ip), nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", ""
	}

	var result struct {
		CountryCode string `json:"country_code"`
		Country     string `json:"country"`
		City        string `json:"city"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", ""
	}

	if result.CountryCode != "" {
		return result.CountryCode, result.City
	}
	return "", ""
}

// isMajorUAChange detects whether the user-agent changed in a way that indicates
// a different browser or OS entirely (likely session hijacking), as opposed to a
// minor version bump from an auto-update.
//
// Heuristic: extract the browser family token (Chrome, Firefox, Safari, Edge, OPR)
// and the OS family token (Windows, Macintosh, Linux, Android, iPhone, iPad).
// If either the browser or the OS family changed, it's a major change.
func isMajorUAChange(original, current string) bool {
	origBrowser := extractBrowserFamily(original)
	currBrowser := extractBrowserFamily(current)
	origOS := extractOSFamily(original)
	currOS := extractOSFamily(current)

	if origBrowser != "" && currBrowser != "" && origBrowser != currBrowser {
		return true
	}
	if origOS != "" && currOS != "" && origOS != currOS {
		return true
	}
	return false
}

// extractBrowserFamily returns a normalized browser family string from a user-agent.
func extractBrowserFamily(ua string) string {
	lower := strings.ToLower(ua)
	// Order matters: Edge contains "chrome", OPR contains "chrome"
	switch {
	case strings.Contains(lower, "edg/") || strings.Contains(lower, "edga/") || strings.Contains(lower, "edgios/"):
		return "edge"
	case strings.Contains(lower, "opr/") || strings.Contains(lower, "opera"):
		return "opera"
	case strings.Contains(lower, "firefox/"):
		return "firefox"
	case strings.Contains(lower, "chrome/") && strings.Contains(lower, "safari/"):
		return "chrome"
	case strings.Contains(lower, "safari/") && !strings.Contains(lower, "chrome/"):
		return "safari"
	case strings.Contains(lower, "curl/"):
		return "curl"
	default:
		return ""
	}
}

// extractOSFamily returns a normalized OS family string from a user-agent.
func extractOSFamily(ua string) string {
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "windows"):
		return "windows"
	case strings.Contains(lower, "iphone") || strings.Contains(lower, "ipad"):
		return "ios"
	case strings.Contains(lower, "macintosh") || strings.Contains(lower, "mac os"):
		return "macos"
	case strings.Contains(lower, "android"):
		return "android"
	case strings.Contains(lower, "linux"):
		return "linux"
	case strings.Contains(lower, "chromeos") || strings.Contains(lower, "cros"):
		return "chromeos"
	default:
		return ""
	}
}

// checkIPThreat checks if an IP is in the threat list
func (s *Service) checkIPThreat(ctx context.Context, ip string) (threatType string, blocked bool) {
	if ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return "", false
	}

	var threat string
	var isActive bool
	err := s.db.Pool.QueryRow(ctx,
		`SELECT threat_type, is_active FROM ip_threat_list WHERE ip_address=$1`, ip).
		Scan(&threat, &isActive)
	if err != nil {
		// ErrNoRows is the normal case: the IP isn't a listed threat → allow.
		// A real DB error is different: fail OPEN (allow) — ip_threat_list is a
		// secondary deny-list, and failing closed would block ALL proxied traffic
		// on a transient DB error (a worse DoS than admitting a listed IP during
		// an outage) — but never silently: surface it so the gap is visible.
		if !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Warn("ip-threat check failed; allowing (deny-list is best-effort)",
				zap.String("ip", ip), zap.Error(err))
		}
		return "", false
	}

	return threat, isActive
}

// handleAuthDecide is the forward-auth endpoint called by APISIX for every proxied request.
// It evaluates authentication and context, returning 200 (allow) with identity headers or 403 (deny).
func (s *Service) handleAuthDecide(c *gin.Context) {
	// Extract the original request info from headers (set by APISIX forward-auth)
	originalHost := c.GetHeader("X-Forwarded-Host")
	if originalHost == "" {
		// Not c.GetHeader("Host"): the server moves Host out of the header
		// map, so that read was always empty, and findRouteByHost matched an
		// empty host against every route and answered for the first.
		originalHost = c.Request.Host
	}
	originalURI := c.GetHeader("X-Forwarded-Uri")
	originalMethod := c.GetHeader("X-Forwarded-Method")
	if originalMethod == "" {
		originalMethod = c.Request.Method
	}

	// Find the matching route
	route, err := s.findRouteByHost(c.Request.Context(), originalHost)
	if err != nil || route == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no route configured for host"})
		return
	}

	if !route.Enabled {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "route is disabled"})
		return
	}

	// If route doesn't require auth, allow. The identity headers are
	// answered empty, so the edge replaces the caller's copies rather than
	// passing them on.
	if !route.RequireAuth {
		writeForwardAuthHeaders(c, nil, route.Name, "", forwardAuthConsumedAuthorization(c, nil))
		c.Status(http.StatusOK)
		return
	}

	// Authenticate
	session := sessionOnRoute(s.getSessionFromRequest(c, originalHost), route)
	// Enforce the route's idle timeout on the cookie session (bearer tokens carry
	// their own expiry). Mirrors handleProxy.
	if session != nil && isIdleExpired(route, session, time.Now()) {
		s.revokeIdleProxySession(c, session)
		s.logAuditEvent(c, "proxy_session_idle_expired", route.ID, "proxy_route", map[string]interface{}{
			"user_id":      session.UserID,
			"idle_timeout": route.IdleTimeout,
		})
		session = nil
	}
	if session == nil {
		session = s.getSessionFromBearer(c)
	}
	if session == nil {
		// Redirect to login with path-only redirect_url.
		// Using a relative path avoids port-stripping issues (APISIX's X-Forwarded-Host
		// uses nginx $host which drops the port). The browser resolves relative redirects
		// against the current page URL, preserving the correct host:port.
		redirectPath := originalURI
		if redirectPath == "" {
			redirectPath = "/"
		}
		loginURL := fmt.Sprintf("/access/.auth/login?redirect_url=%s", url.QueryEscape(redirectPath))
		c.Redirect(http.StatusFound, loginURL)
		return
	}

	// Check step-up requirement from continuous verification
	stepUpKey := fmt.Sprintf("stepup_required:%s", session.ID)
	if stepUpRequired, _ := s.redis.Client.Get(c.Request.Context(), stepUpKey).Result(); stepUpRequired == "true" {
		c.Header("X-Step-Up-Required", "true")
		c.JSON(http.StatusForbidden, gin.H{"error": "step-up authentication required"})
		return
	}

	// Under enforcement an application-backed route is decided by its
	// application's principals and conditions; the route's roles and groups
	// rule otherwise, exactly as handleProxy does. This path used to check
	// roles and groups and never assignment, so a route the console showed as
	// assigned to three people was open to every signed-in user behind the
	// edge.
	appID, appOrgID := s.appForRoute(c.Request.Context(), route.ID)
	if !(appID != "" && s.config.AccessAssignmentEnforce) {
		// Role check
		if len(route.AllowedRoles) > 0 && !hasAnyRole(session.Roles, route.AllowedRoles) {
			s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", map[string]interface{}{
				"reason":  "insufficient_roles",
				"user_id": session.UserID,
				"path":    originalURI,
			})
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}

		// Group check. allowed_groups is configurable in the admin UI and was
		// previously stored but never evaluated, so a route restricted only by group
		// was open to every authenticated user in the org.
		if len(route.AllowedGroups) > 0 &&
			!routeGroupsAllow(route.AllowedGroups, s.userGroupNames(c.Request.Context(), session.UserID)) {
			s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", map[string]interface{}{
				"reason":  "insufficient_groups",
				"user_id": session.UserID,
				"path":    originalURI,
			})
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
	}
	// The request's situation first — the device, the country, the risk it
	// carries — so the shared decision judges the resource's conditions for
	// real instead of listing them unjudged.
	accessCtx, err := s.buildAccessContext(c, route, session)
	if err != nil {
		s.logger.Error("Failed to build access context", zap.Error(err))
		c.JSON(http.StatusForbidden, gin.H{"error": "context evaluation failed"})
		return
	}
	// Set request method/path in context for DSL evaluation
	accessCtx.OriginalMethod = originalMethod
	accessCtx.OriginalURI = originalURI
	risk, early := s.scoreAccessContext(accessCtx)
	if early != nil {
		s.refuseOnContext(c, route, session, early, originalURI, originalMethod)
		return
	}
	ok, conditionsRuled := s.reachDecision(c, route, session, appID, appOrgID, "forward_auth", situationOf(accessCtx, risk))
	if !ok {
		return
	}
	// The route's own conditions, unless the resource declared its own, and
	// the inline policy.
	decision := s.judgeRouteContext(accessCtx, risk, !conditionsRuled)
	if !decision.Allowed {
		s.refuseOnContext(c, route, session, decision, originalURI, originalMethod)
		return
	}

	// Governance policy evaluation (external)
	if len(route.PolicyIDs) > 0 {
		allowed, err := s.evaluatePolicies(c, route, session)
		if err != nil {
			s.logger.Error("Policy evaluation failed", zap.Error(err))
			c.JSON(http.StatusForbidden, gin.H{"error": "policy evaluation failed"})
			return
		}
		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied by governance policy"})
			return
		}
	}

	// Update session activity (also slides the idle-timeout window)
	s.updateSessionActivity(c, session)

	// Set identity headers for the upstream, and keep the proxy's own
	// credentials from it.
	writeForwardAuthHeaders(c, session, route.Name, fmt.Sprintf("%d", decision.RiskScore),
		forwardAuthConsumedAuthorization(c, session))

	s.logAuditEvent(c, "proxy_access_allowed", route.ID, "proxy_route", map[string]interface{}{
		"user_id":    session.UserID,
		"path":       originalURI,
		"method":     originalMethod,
		"risk_score": decision.RiskScore,
	})

	c.Status(http.StatusOK)
}

// handleValidatePolicy validates a policy DSL expression without evaluating it
func (s *Service) handleValidatePolicy(c *gin.Context) {
	var req struct {
		Policy string `json:"policy" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := ValidatePolicy(req.Policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":   true,
		"message": "policy expression is valid",
	})
}

// forwardAuthConsumedAuthorization reports whether the access service
// authenticated this forward-auth request with its Authorization header:
// through its own bearer session, or through the bearer middleware in front of
// the endpoint, which binds a subject only from a credential it verified.
// Either way the header is an OpenIDX credential, and not the application's.
func forwardAuthConsumedAuthorization(c *gin.Context, session *ProxySession) bool {
	if c.GetHeader("Authorization") == "" {
		return false
	}
	if session != nil && session.bearer != "" {
		return true
	}
	return c.GetString("user_id") != "" || c.GetString("service_account_id") != "" || c.GetString("api_key_id") != ""
}
