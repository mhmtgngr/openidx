package access

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/accessdecision"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/stepup"
)

// stepUpACR is the authentication context a fresh-factor refusal asks the
// OIDC side for.
const stepUpACR = "urn:openidx:mfa:fresh"

// onlyStepUp reports whether a fresh factor is the only thing missing.
func onlyStepUp(reasons []string) bool {
	return len(reasons) == 1 && reasons[0] == accessdecision.ReasonStepUp
}

// stepUpReturnTarget is the page a browser returns to after the step-up
// sign-in: the forwarded one under forward-auth, the request itself on the
// built-in proxy. Only a GET is sent round: a form post would be replayed as
// a GET and lose its body, so it is refused with the header instead.
func stepUpReturnTarget(c *gin.Context) (string, bool) {
	method, target := c.Request.Method, c.Request.URL.RequestURI()
	if fwd := c.GetHeader("X-Forwarded-Uri"); fwd != "" {
		target = fwd
		if m := c.GetHeader("X-Forwarded-Method"); m != "" {
			method = m
		}
	}
	return target, method == http.MethodGet
}

// loginSessionFreshness reads whether the OpenIDX login session behind a
// proxy session proved a second factor within the step-up window. known is
// false when the proxy session names no login session or the row cannot be
// read: the condition is then left unjudged rather than guessed.
func (s *Service) loginSessionFreshness(ctx context.Context, session *ProxySession, orgID string) (known, fresh bool) {
	if session == nil || session.loginSessionID == "" || orgID == "" || s.db == nil {
		return false, false
	}
	bypass := orgctx.WithBypassRLS(ctx)
	at, ok, err := stepup.Freshness(bypass, s.db, orgID, session.loginSessionID)
	if err != nil {
		return false, false
	}
	if !ok {
		return true, false
	}
	var def time.Duration
	if s.config != nil {
		def = s.config.StepUpMaxAge
	}
	return true, time.Since(at) <= stepup.MaxAge(bypass, s.db, def)
}

// ONE DECISION FOR BOTH PROXY PATHS.
//
// handleProxy (the built-in reverse proxy) and handleAuthDecide (the APISIX
// forward-auth hook, which is the path a production edge uses) grew apart:
// the first overlaid application assignment on the route's roles and groups,
// the second never checked assignment at all. A route the console showed as
// assigned to three people was open to every signed-in user behind the edge.
//
// reachDecision is the one call both make. It asks internal/accessdecision
// whether the session's user may reach the route's application in the
// situation at hand, caches the answer per (user, application, situation) for
// decisionTTL so forward-auth's per-request fan-out does not become a
// per-request query, records the decision on both branches the way the
// assignment gate always did, and answers the request when the verdict is a
// refusal. The route's own roles and groups keep ruling in observe mode,
// exactly as before; under enforcement the application's principals and
// conditions are the verdict.

// situation is what the proxy knows about the request at hand, for the
// resource's conditions: the device's trust, the country the address
// resolves to, and the risk the request carries (scoreAccessContext). When
// the proxy session remembers the OpenIDX login session it was signed in from
// (the token's sid), reachDecision also reads when that session last proved a
// second factor, and a fresh-factor condition is judged; without one it stays
// unjudged (Subject.MFAKnown).
type situation struct {
	known         bool
	deviceTrusted bool
	country       string
	risk          int
	mfaKnown      bool
	freshMFA      bool
}

// situationOf reads the situation off a built access context.
func situationOf(ac *AccessContext, risk int) situation {
	return situation{known: true, deviceTrusted: ac.DeviceTrusted, country: ac.GeoCountry, risk: risk}
}

// key tells situations apart in the decision cache: a decision taken for a
// trusted device must not answer for an untrusted one.
func (sit situation) key() string {
	if !sit.known {
		return "-"
	}
	return fmt.Sprintf("%t|%s|%d|%t|%t", sit.deviceTrusted, strings.ToUpper(sit.country), sit.risk, sit.mfaKnown, sit.freshMFA)
}

// reachDecision evaluates, records and, on a refusal, answers. ok is false
// when the caller must return. conditionsRuled is true when the resource
// declared its own conditions and this decision judged them under
// enforcement, so the route's pre-229 copy of them must not be judged again.
func (s *Service) reachDecision(c *gin.Context, route *ProxyRoute, session *ProxySession, appID, appOrgID, point string, sit situation) (ok, conditionsRuled bool) {
	if appID == "" {
		return true, false // no application behind the route: nothing to decide here
	}
	ctx := c.Request.Context()
	if sit.known && !sit.mfaKnown {
		sit.mfaKnown, sit.freshMFA = s.loginSessionFreshness(ctx, session, appOrgID)
	}
	key := session.UserID + "|" + appID + "|" + sit.key()
	fresh := true
	var d accessdecision.Decision
	var cached assignCacheEntry
	if v, hit := s.assignCache.Load(key); hit {
		if e, ok := v.(assignCacheEntry); ok {
			cached = e
			if e.hasDecision && time.Since(e.at) < groupCacheTTL {
				d, fresh = e.decision, false
			}
		}
	}
	if fresh {
		var err error
		// The assignment tables are the tenant's; the lookup runs bypassed
		// because the proxy session's context may not carry the org yet.
		d, err = accessdecision.Evaluate(orgctx.WithBypassRLS(ctx), s.db, s.config.AccessAssignmentEnforce,
			accessdecision.Subject{
				UserID: session.UserID, OrgID: appOrgID, Roles: session.Roles,
				KnowsSituation: sit.known, DeviceTrusted: sit.deviceTrusted, Country: sit.country, RiskScore: sit.risk,
				MFAKnown: sit.mfaKnown, FreshMFA: sit.freshMFA,
			}, appID)
		if err != nil {
			s.logger.Error("reach decision failed", zap.String("application_id", appID), zap.Error(err))
			if s.config.AccessAssignmentEnforce {
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "access could not be verified"})
				return false, false
			}
			return true, false
		}
		cached.decision, cached.hasDecision = d, true
		cached.assigned, cached.at = d.Grant != "", time.Now()
		s.assignCache.Store(key, cached)
	}

	if d.WouldDeny {
		// The durable record, on both branches: enforcement is never quieter
		// than observe mode. Throttled to one per cache TTL per (user, app)
		// in observe mode, where every asset load would otherwise write.
		if !d.Allowed || fresh {
			s.recordAssignmentDecision(ctx, route, session.UserID, appID, c.ClientIP(), !d.Allowed)
		}
		details := map[string]interface{}{
			"enforcement_point": point,
			"user_id":           session.UserID,
			"route":             route.Name,
			"application_id":    appID,
			"explain":           accessdecision.Explain(d),
			"reasons":           d.Reasons,
		}
		if !d.Allowed {
			details["reason"] = d.Reasons[0]
			details["path"] = c.Request.URL.Path
			s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", details)
			if d.StepUp {
				// A trusted device or a fresh factor would change the answer.
				c.Header("X-Step-Up-Required", "true")
				if target, ok := stepUpReturnTarget(c); ok && onlyStepUp(d.Reasons) {
					// Only a fresh factor is missing: send the browser through
					// sign-in again with acr_values=urn:openidx:mfa:fresh, which
					// the OIDC side answers with a second-factor challenge
					// (oauth/acr.go), and back to this page.
					c.Header("X-Step-Up-Acr", stepUpACR)
					c.Redirect(http.StatusFound, "/access/.auth/login?acr_values="+url.QueryEscape(stepUpACR)+
						"&redirect_url="+url.QueryEscape(target))
					return false, false
				}
			}
			if len(d.Reasons) == 1 && d.Reasons[0] == accessdecision.ReasonNotAssigned {
				c.JSON(http.StatusForbidden, gin.H{"error": "not assigned to this application"})
			} else {
				c.JSON(http.StatusForbidden, gin.H{"error": "access denied: " + strings.Join(d.Reasons, ", ")})
			}
			return false, false
		} else if fresh {
			s.logAuditEvent(c, "access.assignment.would_deny", appID, "application", details)
		}
	}
	return true, d.ConditionsDeclared && s.config.AccessAssignmentEnforce
}

// explainReach answers GET /decisions/explain?user=&app= for an
// administrator: the decision the enforcement points would take for that
// person on that application, with the grant and every condition named.
//
// The situation (device, risk, country, a fresh second factor) is not known
// here, so by default those conditions are listed as unjudged and the audit
// log carries the judged ones. An administrator can instead state one, as a
// policy tester ("what if this person came from DE on an untrusted device at
// risk 60?"): device_trusted, risk and optionally country, and with them
// fresh_mfa. The answer is then the same Evaluate the proxy and the forward-auth
// hook call, judging every condition for that situation. It decides from the
// application's principals and conditions; a route's inline policy and the
// governance policies it names are not part of it, and the answer says so.
func (s *Service) handleExplainReach(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "org context required"})
		return
	}
	userID, appID := c.Query("user"), c.Query("app")
	if userID == "" || appID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user and app are required"})
		return
	}
	roles, err := s.userRoleNames(c.Request.Context(), userID, org.ID)
	if err != nil {
		s.logger.Warn("explain: roles", zap.Error(err))
	}
	subject := accessdecision.Subject{UserID: userID, OrgID: org.ID, Roles: roles}
	whatIf, msg := whatIfSituation(c, &subject)
	if msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}
	d, err := accessdecision.Evaluate(c.Request.Context(), s.db, s.config.AccessAssignmentEnforce, subject, appID)
	if err != nil {
		s.logger.Error("explain: evaluate", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "evaluation failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"decision": d, "explain": accessdecision.Explain(d),
		"what_if":    whatIf,
		"not_judged": []string{"route_inline_policy", "governance_policies"},
	})
}

// whatIfSituation reads the stated situation off the query, when there is
// one, into s. device_trusted, country and risk come together: judging device
// trust from a stated country alone would report an untrusted device nobody
// stated, and for the same reason fresh_mfa comes only with them. Inputs are
// bounded, and anything else is a message for a 400.
func whatIfSituation(c *gin.Context, s *accessdecision.Subject) (bool, string) {
	dev, cc, risk, mfa := c.Query("device_trusted"), c.Query("country"), c.Query("risk"), c.Query("fresh_mfa")
	whatIf := false
	if dev != "" || cc != "" || risk != "" {
		if dev == "" || risk == "" {
			return false, "a stated situation needs device_trusted and risk (country is optional)"
		}
		trusted, err := strconv.ParseBool(dev)
		if err != nil {
			return false, "device_trusted must be true or false"
		}
		r, err := strconv.Atoi(risk)
		if err != nil || r < 0 || r > 100 {
			return false, "risk must be a whole number from 0 to 100"
		}
		if cc != "" && !isCountryCode(cc) {
			return false, "country must be a two-letter code"
		}
		s.KnowsSituation, s.DeviceTrusted, s.RiskScore, s.Country = true, trusted, r, strings.ToUpper(cc)
		whatIf = true
	}
	if mfa != "" {
		// A fresh factor is judged only inside a known situation, so it is
		// stated with one: on its own it would make the unstated device
		// trust and risk read as false and zero.
		if !whatIf {
			return false, "fresh_mfa is stated with device_trusted and risk"
		}
		fresh, err := strconv.ParseBool(mfa)
		if err != nil {
			return false, "fresh_mfa must be true or false"
		}
		s.MFAKnown, s.FreshMFA = true, fresh
	}
	return whatIf, ""
}

// isCountryCode reports whether v is two ASCII letters.
func isCountryCode(v string) bool {
	if len(v) != 2 {
		return false
	}
	for _, r := range v {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

// userRoleNames is the user's role names in the organization, for legacy
// roles kept on a resource's conditions.
func (s *Service) userRoleNames(ctx context.Context, userID, orgID string) ([]string, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		 WHERE ur.user_id = $1 AND ur.org_id = $2
		   AND (ur.expires_at IS NULL OR ur.expires_at > NOW())`, userID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return out, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
