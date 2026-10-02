// Package access — end-user (self-service) Guacamole PAM endpoints.
//
// The admin console's Privileged Sessions page manages requests and sessions;
// these handlers give non-admin users their own view: which brokered
// connections exist in their org, and the status of their own session
// requests — so they can request approval, watch for the decision, and
// launch once approved (the connect handler consumes the approval).
package access

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// GuacUserConnection is the end-user representation of a brokered connection:
// enough to render a launch/request card, never the vault secret id or the
// Guacamole-internal connection identifier.
type GuacUserConnection struct {
	RouteID            string `json:"route_id"`
	Name               string `json:"name"`
	Protocol           string `json:"protocol"`
	Hostname           string `json:"hostname"`
	Port               int    `json:"port"`
	RequireApproval    bool   `json:"require_approval"`
	RecordSession      bool   `json:"record_session"`
	CredentialInjected bool   `json:"credential_injected"`
}

// GuacMySessionRequest is a session request joined with its connection info so
// the requester can see what the request was for and launch once approved.
type GuacMySessionRequest struct {
	ID        string     `json:"id"`
	RouteID   string     `json:"route_id"`
	RouteName string     `json:"route_name"`
	Protocol  string     `json:"protocol"`
	Reason    string     `json:"reason,omitempty"`
	Status    string     `json:"status"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// ---- handleListMyGuacConnections ----
// GET /api/v1/access/guacamole/my-connections (any authenticated user)
//
// Lists the brokered connections the caller may launch: enabled routes whose
// entry (guacamole_route_entry.go) the caller holds a connect grant on, or
// every one for an administrator, with the PAM flags the launcher UI needs
// read from the entry, since the entry is what the launch enforces. The
// per-row decision is pamEntryAllowed, the same call connect makes, so the
// list offers exactly what connect does.
//
// The predicate is the scope. This comment used to read "RLS scopes
// guacamole_connections via the request context; the explicit pr.org_id
// predicate is defence in depth" — exactly backwards: until v151 the table had
// no org_id and no policy, so the belt it credited did not exist and the
// predicate it called defence in depth was the entire defence. Since v151 the
// table is belted and gc.org_id is checked alongside the route's, so the
// sentence is finally true in both halves.
func (s *Service) handleListMyGuacConnections(c *gin.Context) {
	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	caller, ok := s.resolvePamCaller(c, org.ID)
	if !ok {
		return // resolvePamCaller already wrote the error
	}
	userID, isAdmin := caller.UserID, caller.Admin
	roles := pamCallerRoles(c)

	rows, err := s.db.Pool.Query(ctx,
		`SELECT gc.route_id, pr.name, gc.protocol, gc.hostname, gc.port, e.id::text,
		        e.require_approval, e.record_session,
		        (e.vault_secret_id IS NOT NULL) AS credential_injected
		   FROM guacamole_connections gc
		   JOIN proxy_routes pr ON pr.id = gc.route_id
		   JOIN pam_entries e ON e.proxy_route_id = gc.route_id AND e.org_id = gc.org_id
		  WHERE gc.org_id = $1 AND pr.org_id = $1 AND pr.enabled = true
		  ORDER BY pr.name`,
		org.ID)
	if err != nil {
		s.logger.Error("handleListMyGuacConnections: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list connections"})
		return
	}
	defer rows.Close()

	type candidate struct {
		conn    GuacUserConnection
		entryID string
	}
	var all []candidate
	for rows.Next() {
		var r GuacUserConnection
		var entryID string
		if err := rows.Scan(
			&r.RouteID, &r.Name, &r.Protocol, &r.Hostname, &r.Port, &entryID,
			&r.RequireApproval, &r.RecordSession, &r.CredentialInjected,
		); err != nil {
			s.logger.Warn("handleListMyGuacConnections: scan failed", zap.Error(err))
			continue
		}
		all = append(all, candidate{conn: r, entryID: entryID})
	}
	if err := rows.Err(); err != nil {
		s.logger.Error("handleListMyGuacConnections: rows iteration failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list connections"})
		return
	}

	open, err := s.closedListEntries(ctx, org.ID, caller)
	if err != nil {
		s.logger.Error("handleListMyGuacConnections: vendor list query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list connections"})
		return
	}
	conns := []GuacUserConnection{}
	for _, cand := range all {
		if open != nil && !open[cand.entryID] {
			continue // not open to the caller's vendor (I11)
		}
		if !isAdmin {
			allowed, aclErr := s.pamEntryAllowed(ctx, org.ID, cand.entryID, userID, roles, "connect")
			if aclErr != nil {
				s.logger.Error("handleListMyGuacConnections: ACL check failed", zap.Error(aclErr))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list connections"})
				return
			}
			if !allowed {
				continue
			}
		}
		// An external user's launch is approved and recorded whatever the
		// entry says (I5), and the list says so.
		if caller.External {
			cand.conn.RequireApproval, cand.conn.RecordSession = true, true
		}
		conns = append(conns, cand.conn)
	}

	c.JSON(http.StatusOK, gin.H{"connections": conns})
}

// ---- handleListMyGuacSessionRequests ----
// GET /api/v1/access/guacamole/my-session-requests (any authenticated user)
//
// Lists the caller's own requests on route-backed entries (all statuses, most
// recent first) joined with route info, so the end-user UI can show pending /
// approved / denied state and offer Launch for approved requests. Scoped to
// the caller's user id and org.
func (s *Service) handleListMyGuacSessionRequests(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	ctx := c.Request.Context()

	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(ctx,
		`SELECT r.id, gc.route_id, pr.name, gc.protocol,
		        COALESCE(r.reason,''), r.status, r.decided_at, r.expires_at, r.created_at
		   FROM pam_entry_access_requests r
		   JOIN pam_entries e ON e.id = r.entry_id AND e.org_id = r.org_id
		   JOIN guacamole_connections gc ON gc.route_id = e.proxy_route_id AND gc.org_id = e.org_id
		   JOIN proxy_routes pr ON pr.id = gc.route_id
		  WHERE r.org_id = $1 AND r.requester_id = $2
		  ORDER BY r.created_at DESC
		  LIMIT 100`,
		org.ID, userID)
	if err != nil {
		s.logger.Error("handleListMyGuacSessionRequests: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list session requests"})
		return
	}
	defer rows.Close()

	requests := []GuacMySessionRequest{}
	for rows.Next() {
		var r GuacMySessionRequest
		if err := rows.Scan(
			&r.ID, &r.RouteID, &r.RouteName, &r.Protocol,
			&r.Reason, &r.Status, &r.DecidedAt, &r.ExpiresAt, &r.CreatedAt,
		); err != nil {
			s.logger.Warn("handleListMyGuacSessionRequests: scan failed", zap.Error(err))
			continue
		}
		requests = append(requests, r)
	}
	if err := rows.Err(); err != nil {
		s.logger.Error("handleListMyGuacSessionRequests: rows iteration failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list session requests"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"requests": requests})
}
