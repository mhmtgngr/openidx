package access

// Service tokens on proxied applications (migration 245).
//
// A machine reaches a route only by name. The route lists the service
// accounts it admits (proxy_route_service_accounts); the caller presents an
// API key of one of them, `Authorization: Bearer oidx_...`, which api_keys
// stores hashed, shows once, expires and revokes. The key must be active and
// unexpired, its service account active, both in the route's organization,
// and listed on that route. Anything else about the key is refused before
// the request goes anywhere.
//
// A machine is not a person, so the decisions made for people are not made
// for it, and a route that asks for something only a person has does not
// admit one at all: a trusted device, a reason (require_justification), an
// application with assigned people, governance policies, an inline policy,
// device posture checks, a country fence or a risk ceiling. The IP threat
// list still applies. Upstream, the caller is named
// X-Forwarded-User=service-account:<id> and X-Forwarded-Roles=service_account,
// written by the proxy alone like every identity header, and the key itself
// is not forwarded.
//
// Each allowed request is audited as proxy_access_allowed with
// service_account_id; each refusal as proxy_access_denied with the reason.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

const serviceTokenPrefix = "oidx_"

// serviceTokenIdentity is a machine caller the route admits.
type serviceTokenIdentity struct {
	KeyID, ServiceAccountID, Name, OrgID string
	bearer                               string
}

// presentedServiceToken is the API key in the Authorization header, or "".
func presentedServiceToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	tok := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	if !strings.HasPrefix(tok, serviceTokenPrefix) || len(tok) != len(serviceTokenPrefix)+64 {
		return ""
	}
	return tok
}

// routeNeedsAPerson names what on route only a person can satisfy, or "".
func routeNeedsAPerson(route *ProxyRoute, appID string) string {
	switch {
	case appID != "":
		return "an application with assigned people"
	case route.RequireJustification:
		return "a reason"
	case route.RequireDeviceTrust:
		return "a trusted device"
	case len(route.PolicyIDs) > 0:
		return "governance policies"
	case route.InlinePolicy != "":
		return "an inline policy"
	case len(route.PostureCheckIDs) > 0:
		return "device posture"
	case len(route.AllowedCountries) > 0:
		return "a country fence"
	case route.MaxRiskScore > 0 && route.MaxRiskScore < 100:
		return "a risk ceiling"
	case len(route.AllowedRoles) > 0 || len(route.AllowedGroups) > 0:
		return "roles or groups"
	}
	return ""
}

// serviceTokenReach decides a request carrying a service token on route. It
// answers the request when it refuses (ok false). handled is false when the
// request carries no service token, and the person paths decide it.
func (s *Service) serviceTokenReach(c *gin.Context, route *ProxyRoute) (id *serviceTokenIdentity, handled, ok bool) {
	raw := presentedServiceToken(c)
	if raw == "" {
		return nil, false, false
	}
	refuse := func(status int, reason, msg string, extra map[string]interface{}) (*serviceTokenIdentity, bool, bool) {
		details := map[string]interface{}{"reason": reason, "credential": "service_token", "path": c.Request.URL.Path}
		for k, v := range extra {
			details[k] = v
		}
		s.logAuditEvent(c, "proxy_access_denied", route.ID, "proxy_route", details)
		c.JSON(status, gin.H{"error": msg, "code": reason})
		return nil, true, false
	}
	ctx := c.Request.Context()
	sum := sha256.Sum256([]byte(raw))
	var keyID, saID, saName, keyOrg, keyStatus, saStatus string
	var expires *time.Time
	// The key is the identity, looked up by its hash before a tenant is
	// known; every value read here is then held to the route's organization.
	err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore data-plane credential lookup by globally-unique key_hash; the org read out is compared with the route's below
		`SELECT k.id::text, COALESCE(k.service_account_id::text, ''), COALESCE(sa.name, ''), COALESCE(k.org_id::text, ''),
		        COALESCE(k.status, ''), COALESCE(sa.status, ''), k.expires_at
		   FROM api_keys k LEFT JOIN service_accounts sa ON sa.id = k.service_account_id AND sa.org_id = k.org_id
		  WHERE k.key_hash = $1`, hex.EncodeToString(sum[:])).
		Scan(&keyID, &saID, &saName, &keyOrg, &keyStatus, &saStatus, &expires)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Error("service token lookup failed", zap.Error(err))
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "access could not be verified"})
			return nil, true, false
		}
		return refuse(http.StatusUnauthorized, "service_token_invalid", "invalid service token", nil)
	}
	who := map[string]interface{}{"api_key_id": keyID, "service_account_id": saID}
	switch {
	case keyStatus != "active" || (expires != nil && expires.Before(time.Now())):
		return refuse(http.StatusUnauthorized, "service_token_inactive", "this service token is revoked or expired", who)
	case saID == "" || saStatus != "active":
		return refuse(http.StatusUnauthorized, "service_token_not_a_service_account", "this key does not belong to an active service account", who)
	case keyOrg != route.OrgID:
		return refuse(http.StatusUnauthorized, "service_token_invalid", "invalid service token", nil)
	}
	appID, _ := s.appForRoute(ctx, route.ID)
	if why := routeNeedsAPerson(route, appID); why != "" {
		return refuse(http.StatusForbidden, "service_token_route_needs_a_person",
			"this application needs "+why+"; a service token cannot reach it", who)
	}
	var listed bool
	if err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		`SELECT EXISTS (SELECT 1 FROM proxy_route_service_accounts
		                 WHERE route_id = $1::uuid AND service_account_id = $2::uuid AND org_id = $3::uuid)`,
		route.ID, saID, route.OrgID).Scan(&listed); err != nil {
		s.logger.Error("service token route lookup failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "access could not be verified"})
		return nil, true, false
	}
	if !listed {
		return refuse(http.StatusForbidden, "service_token_not_admitted", "this service account may not reach this application", who)
	}
	if threat, blocked := s.checkIPThreat(ctx, c.ClientIP()); blocked {
		return refuse(http.StatusForbidden, "ip_blocked", "access denied", map[string]interface{}{"service_account_id": saID, "threat": threat})
	}
	go s.touchServiceToken(keyID)
	return &serviceTokenIdentity{KeyID: keyID, ServiceAccountID: saID, Name: saName, OrgID: keyOrg, bearer: c.GetHeader("Authorization")}, true, true
}

func (s *Service) touchServiceToken(keyID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	//silentwrite:ok last_used_at is a display column on the API keys page; a lost stamp shows an older time and nothing decides from it
	_, _ = s.db.Pool.Exec(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore background stamp keyed by the key's globally-unique id, just verified against the route's org
		`UPDATE api_keys SET last_used_at = NOW() WHERE id = $1::uuid`, keyID)
}

// asProxySession is the identity the upstream is told about: a machine,
// named as one, carrying the key only so the proxy can strip it.
func (id *serviceTokenIdentity) asProxySession() *ProxySession {
	return &ProxySession{
		UserID: "service-account:" + id.ServiceAccountID,
		Name:   id.Name,
		Roles:  []string{"service_account"},
		bearer: id.bearer,
		orgID:  id.OrgID,
	}
}

// handleListRouteServiceAccounts — GET /routes/:id/service-accounts (admin).
func (s *Service) handleListRouteServiceAccounts(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT sa.id::text, sa.name, COALESCE(sa.status, ''), rsa.created_at
		  FROM proxy_route_service_accounts rsa
		  JOIN service_accounts sa ON sa.id = rsa.service_account_id AND sa.org_id = rsa.org_id
		 WHERE rsa.route_id::text = $1 AND rsa.org_id = $2
		 ORDER BY sa.name`, c.Param("id"), org.ID)
	if err != nil {
		s.logger.Error("list route service accounts", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list"})
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id, name, status string
		var at time.Time
		if rows.Scan(&id, &name, &status, &at) == nil {
			out = append(out, gin.H{"service_account_id": id, "name": name, "status": status, "admitted_at": at})
		}
	}
	c.JSON(http.StatusOK, gin.H{"service_accounts": out})
}

// handleAddRouteServiceAccount — POST /routes/:id/service-accounts (admin):
// admit one service account of this organization to this route. The route
// must be one a machine can reach (routeNeedsAPerson).
func (s *Service) handleAddRouteServiceAccount(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var req struct {
		ServiceAccountID string `json:"service_account_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.ServiceAccountID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "service_account_id is required"})
		return
	}
	ctx := c.Request.Context()
	route, err := s.getRouteByID(ctx, c.Param("id"))
	if err != nil || route == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
		return
	}
	appID, _ := s.appForRoute(ctx, route.ID)
	if why := routeNeedsAPerson(route, appID); why != "" {
		c.JSON(http.StatusConflict, gin.H{"error": "this route needs " + why + "; a service token could never reach it", "code": "route_needs_a_person"})
		return
	}
	var saOK bool
	if err := s.db.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM service_accounts WHERE id::text = $1 AND org_id = $2)`,
		req.ServiceAccountID, org.ID).Scan(&saOK); err != nil || !saOK {
		c.JSON(http.StatusNotFound, gin.H{"error": "service account not found"})
		return
	}
	if _, err := s.db.Pool.Exec(ctx, `INSERT INTO proxy_route_service_accounts (route_id, service_account_id, org_id, created_by)
		VALUES ($1::uuid, $2::uuid, $3, NULLIF($4, '')::uuid) ON CONFLICT DO NOTHING`,
		route.ID, req.ServiceAccountID, org.ID, getUserID(c)); err != nil {
		s.logger.Error("admit service account", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to admit the service account"})
		return
	}
	s.logAuditEvent(c, "proxy_route_service_account_admitted", route.ID, "proxy_route", map[string]interface{}{
		"service_account_id": req.ServiceAccountID,
	})
	c.JSON(http.StatusCreated, gin.H{"route_id": route.ID, "service_account_id": req.ServiceAccountID})
}

// handleRemoveRouteServiceAccount — DELETE /routes/:id/service-accounts/:sa (admin).
func (s *Service) handleRemoveRouteServiceAccount(c *gin.Context) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	tag, err := s.db.Pool.Exec(c.Request.Context(), `DELETE FROM proxy_route_service_accounts
		WHERE route_id::text = $1 AND service_account_id::text = $2 AND org_id = $3`, c.Param("id"), c.Param("sa"), org.ID)
	if err != nil {
		s.logger.Error("remove route service account", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not admitted"})
		return
	}
	s.logAuditEvent(c, "proxy_route_service_account_removed", c.Param("id"), "proxy_route", map[string]interface{}{
		"service_account_id": c.Param("sa"),
	})
	c.Status(http.StatusNoContent)
}
