// Package access provides unified audit logging across OpenIDX, Ziti, and Guacamole
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	apperrors "github.com/openidx/openidx/internal/common/errors"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// UnifiedAuditEvent represents an audit event from any source
type UnifiedAuditEvent struct {
	ID        string                 `json:"id"`
	Source    string                 `json:"source"` // openidx, ziti, guacamole
	EventType string                 `json:"event_type"`
	RouteID   string                 `json:"route_id,omitempty"`
	RouteName string                 `json:"route_name,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
	UserEmail string                 `json:"user_email,omitempty"`
	ActorIP   string                 `json:"actor_ip,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// UnifiedAuditService handles unified audit log operations
type UnifiedAuditService struct {
	db              *database.PostgresDB
	logger          *zap.Logger
	zitiProvider    *ZitiProvider
	guacamoleClient *GuacamoleClient
}

// ziti returns the live OpenZiti manager (nil when disconnected).
func (uas *UnifiedAuditService) ziti() *ZitiManager { return uas.zitiProvider.Get() }

// NewUnifiedAuditService creates a new UnifiedAuditService
func NewUnifiedAuditService(db *database.PostgresDB, logger *zap.Logger) *UnifiedAuditService {
	return &UnifiedAuditService{
		db:     db,
		logger: logger.With(zap.String("component", "unified_audit")),
	}
}

// SetZitiProvider wires the shared provider.
func (uas *UnifiedAuditService) SetZitiProvider(p *ZitiProvider) { uas.zitiProvider = p }

// SetZitiManager installs a manager into the provider (compat shim for tests).
func (uas *UnifiedAuditService) SetZitiManager(zm *ZitiManager) {
	if uas.zitiProvider == nil {
		uas.zitiProvider = NewZitiProvider()
	}
	uas.zitiProvider.Store(zm)
}

// SetGuacamoleClient sets the Guacamole client for audit sync
func (uas *UnifiedAuditService) SetGuacamoleClient(gc *GuacamoleClient) {
	uas.guacamoleClient = gc
}

// RecordEvent records a unified audit event.
//
// Every write goes through here except the two external syncs below and three
// package-local inserts (the agent lifecycle log, the MCP gateway, and the
// oauth service's own gate records), so this is where the tenant is stamped for
// the proxy's assignment and ABAC decisions, the kill switch, device
// revocation, kiosk and remote-support lifecycle. Since v142 the row carries
// org_id and the table is under FORCE RLS: a write with the wrong org fails its
// WITH CHECK rather than landing where nobody will find it.
func (uas *UnifiedAuditService) RecordEvent(ctx context.Context, source, eventType string, routeID, userID, actorIP string, details map[string]interface{}) error {
	detailsJSON, _ := json.Marshal(details)

	var routeIDPtr, userIDPtr *string
	if routeID != "" {
		routeIDPtr = &routeID
	}
	if userID != "" {
		userIDPtr = &userID
	}

	orgID, resolved := orgctx.AuditOrgID(ctx)
	if !resolved {
		// Not fatal — an audit write must never fail the thing it records — but
		// on a multi-tenant install this row has just been filed under the
		// primary org, which is a defect in the caller's plumbing.
		uas.logger.Warn("unified audit event has no org context; filed under the primary organization",
			zap.String("source", source), zap.String("event_type", eventType))
	}

	_, err := uas.db.Pool.Exec(ctx, `
		INSERT INTO unified_audit_events (id, org_id, source, event_type, route_id, user_id, actor_ip, details, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
	`, uuid.New().String(), orgID, source, eventType, routeIDPtr, userIDPtr, actorIP, detailsJSON)

	return err
}

// QueryEvents queries unified audit events with filters.
//
// The org predicate is not optional and is not a filter: before v142 this
// opened `WHERE 1=1`, so the console's Unified Audit page showed every tenant's
// audit trail to every tenant's admin — including, through the users JOIN,
// other tenants' e-mail addresses. RLS now backs this up, but the predicate
// stays explicit so the query says what it returns without the reader having to
// know the schema's policies.
func (uas *UnifiedAuditService) QueryEvents(ctx context.Context, filters *AuditQueryFilters) (*AuditQueryResult, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// Build query
	query := `
		SELECT e.id, e.source, e.event_type, e.route_id, e.user_id, e.actor_ip, e.details, e.created_at,
		       r.name as route_name, u.email as user_email
		FROM unified_audit_events e
		LEFT JOIN proxy_routes r ON e.route_id = r.id
		LEFT JOIN users u ON e.user_id = u.id
		WHERE e.org_id = $1
	`
	args := []interface{}{org.ID}
	argIndex := 2

	if len(filters.Sources) > 0 {
		placeholders := make([]string, len(filters.Sources))
		for i, src := range filters.Sources {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, src)
			argIndex++
		}
		query += fmt.Sprintf(" AND e.source IN (%s)", strings.Join(placeholders, ","))
	}

	if filters.RouteID != "" {
		query += fmt.Sprintf(" AND e.route_id = $%d", argIndex)
		args = append(args, filters.RouteID)
		argIndex++
	}

	if filters.UserID != "" {
		query += fmt.Sprintf(" AND e.user_id = $%d", argIndex)
		args = append(args, filters.UserID)
		argIndex++
	}

	if len(filters.EventTypes) > 0 {
		placeholders := make([]string, len(filters.EventTypes))
		for i, et := range filters.EventTypes {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, et)
			argIndex++
		}
		query += fmt.Sprintf(" AND e.event_type IN (%s)", strings.Join(placeholders, ","))
	}

	if !filters.StartTime.IsZero() {
		query += fmt.Sprintf(" AND e.created_at >= $%d", argIndex)
		args = append(args, filters.StartTime)
		argIndex++
	}

	if !filters.EndTime.IsZero() {
		query += fmt.Sprintf(" AND e.created_at <= $%d", argIndex)
		args = append(args, filters.EndTime)
		argIndex++
	}

	// Count total
	countQuery := strings.Replace(query, "SELECT e.id, e.source, e.event_type, e.route_id, e.user_id, e.actor_ip, e.details, e.created_at,\n\t\t       r.name as route_name, u.email as user_email", "SELECT COUNT(*)", 1)
	var total int
	uas.db.Pool.QueryRow(ctx, countQuery, args...).Scan(&total)

	// Add pagination
	query += " ORDER BY e.created_at DESC"
	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, filters.Limit, filters.Offset)

	rows, err := uas.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []UnifiedAuditEvent
	for rows.Next() {
		var e UnifiedAuditEvent
		var routeID, userID, routeName, userEmail, actorIP *string
		var detailsJSON []byte

		err := rows.Scan(&e.ID, &e.Source, &e.EventType, &routeID, &userID, &actorIP, &detailsJSON, &e.CreatedAt, &routeName, &userEmail)
		if err != nil {
			continue
		}

		if routeID != nil {
			e.RouteID = *routeID
		}
		if userID != nil {
			e.UserID = *userID
		}
		if routeName != nil {
			e.RouteName = *routeName
		}
		if userEmail != nil {
			e.UserEmail = *userEmail
		}
		if actorIP != nil {
			e.ActorIP = *actorIP
		}
		if detailsJSON != nil {
			json.Unmarshal(detailsJSON, &e.Details)
		}

		events = append(events, e)
	}

	// Get distinct sources. Scoped too: the source list drives the page's filter
	// chips, and an unscoped one told a tenant which subsystems other tenants
	// were running.
	sourcesRows, _ := uas.db.Pool.Query(ctx,
		"SELECT DISTINCT source FROM unified_audit_events WHERE org_id = $1", org.ID)
	var sources []string
	if sourcesRows != nil {
		defer sourcesRows.Close()
		for sourcesRows.Next() {
			var src string
			if sourcesRows.Scan(&src) == nil {
				sources = append(sources, src)
			}
		}
	}

	return &AuditQueryResult{
		Events:  events,
		Total:   total,
		Sources: sources,
	}, nil
}

// AuditQueryFilters contains filters for querying audit events
type AuditQueryFilters struct {
	Sources    []string
	RouteID    string
	UserID     string
	EventTypes []string
	StartTime  time.Time
	EndTime    time.Time
	Limit      int
	Offset     int
}

// AuditQueryResult contains the results of an audit query
type AuditQueryResult struct {
	Events  []UnifiedAuditEvent `json:"events"`
	Total   int                 `json:"total"`
	Sources []string            `json:"sources"`
}

// SyncExternalAuditEvents syncs audit events from Ziti and Guacamole
func (uas *UnifiedAuditService) SyncExternalAuditEvents(ctx context.Context) error {
	// Sync Ziti events
	if uas.ziti() != nil && uas.ziti().IsInitialized() {
		if err := uas.syncZitiAuditEvents(ctx); err != nil {
			uas.logger.Warn("Failed to sync Ziti audit events", zap.Error(err))
		}
	}

	// Sync Guacamole events
	if uas.guacamoleClient != nil {
		if err := uas.syncGuacamoleAuditEvents(ctx); err != nil {
			uas.logger.Warn("Failed to sync Guacamole audit events", zap.Error(err))
		}
	}

	return nil
}

func (uas *UnifiedAuditService) syncZitiAuditEvents(ctx context.Context) error {
	// Get last sync state
	var lastSyncAt *time.Time
	var lastEventID *string
	uas.db.Pool.QueryRow(ctx,
		`SELECT last_sync_at, last_event_id FROM external_audit_sync_state WHERE source = 'ziti'`).
		Scan(&lastSyncAt, &lastEventID)

	// Fetch events from Ziti (api-session logins + service dials from the
	// controller's management API — see ZitiManager.GetAuditEvents).
	events, err := uas.ziti().GetAuditEvents(ctx, lastSyncAt)
	if err != nil {
		return err
	}

	// Insert events, deduping by the Ziti event id (stored in details) so a
	// re-poll never creates duplicate rows — the unified_audit_events PK is a
	// random UUID, so ON CONFLICT alone can't dedup controller events.
	var newestTS time.Time
	var newLastEventID string
	for _, event := range events {
		// Map Ziti event to unified format
		details := map[string]interface{}{
			"ziti_event_id":   event.ID,
			"ziti_event_type": event.Type,
		}
		if event.Identity != "" {
			details["identity"] = event.Identity
		}
		if event.Service != "" {
			details["service"] = event.Service
		}
		if event.Router != "" {
			details["router"] = event.Router
		}

		// Find route by ziti service name. The route also decides the tenant:
		// a controller event names a service, and the service's route knows
		// whose it is. This runs bypassed (SyncExternalAuditEvents is called
		// under WithBypassRLS), so the lookup and the insert both span orgs —
		// which is why the org has to be derived per event rather than taken
		// from a context that deliberately has none.
		var routeID *string
		orgID := orgctx.DefaultOrgID
		if event.Service != "" {
			var rid, rorg string
			err := uas.db.Pool.QueryRow(ctx,
				//orgscope:ignore external audit sync correlation; maps a Ziti controller event to its route by globally-unique ziti_service_name, and reads that route's org to attribute the event
				`SELECT id, org_id::text FROM proxy_routes WHERE ziti_service_name = $1`, event.Service).Scan(&rid, &rorg)
			if err == nil {
				routeID = &rid
				if rorg != "" {
					orgID = rorg
				}
			}
		}

		detailsJSON, _ := json.Marshal(details)
		// Insert only if no row with this ziti_event_id already exists.
		//orgscope:ignore install-wide fabric ingest running under WithBypassRLS; org_id is derived per event from the route above, and the dedup predicate must see every org's rows or a re-poll duplicates them
		uas.db.Pool.Exec(ctx, `
			INSERT INTO unified_audit_events (id, org_id, source, event_type, route_id, actor_ip, details, created_at)
			SELECT $1, $2, 'ziti', $3, $4, $5, $6, $7
			 WHERE NOT EXISTS (
			     SELECT 1 FROM unified_audit_events
			      WHERE source = 'ziti' AND details->>'ziti_event_id' = $8
			 )
		`, uuid.New().String(), orgID, event.Type, routeID, event.SourceIP, detailsJSON, event.Timestamp, event.ID)

		if event.Timestamp.After(newestTS) {
			newestTS = event.Timestamp
		}
		newLastEventID = event.ID
	}

	// Upsert the cursor so `since` advances (the row may not exist yet on first
	// sync). Advance last_sync_at to the newest event timestamp, not NOW(), so
	// the timestamp cursor passed to GetAuditEvents is exact.
	if newLastEventID != "" {
		uas.db.Pool.Exec(ctx, `
			INSERT INTO external_audit_sync_state (source, last_sync_at, last_event_id, updated_at)
			VALUES ('ziti', $1, $2, NOW())
			ON CONFLICT (source) DO UPDATE
			   SET last_sync_at = EXCLUDED.last_sync_at,
			       last_event_id = EXCLUDED.last_event_id,
			       updated_at = NOW()
		`, newestTS, newLastEventID)
	}

	return nil
}

func (uas *UnifiedAuditService) syncGuacamoleAuditEvents(ctx context.Context) error {
	// Get last sync state
	var lastSyncAt *time.Time
	uas.db.Pool.QueryRow(ctx,
		`SELECT last_sync_at FROM external_audit_sync_state WHERE source = 'guacamole'`).
		Scan(&lastSyncAt)

	// Fetch session history from Guacamole
	// Note: This would use Guacamole's history API
	sessions, err := uas.guacamoleClient.GetSessionHistory(ctx, lastSyncAt)
	if err != nil {
		return err
	}

	for _, session := range sessions {
		details := map[string]interface{}{
			"guacamole_connection_id": session.ConnectionID,
			"protocol":                session.Protocol,
			"start_time":              session.StartTime,
			"end_time":                session.EndTime,
			"duration_seconds":        session.DurationSeconds,
		}
		if session.Username != "" {
			details["username"] = session.Username
		}

		// Find route by guacamole connection ID, and with it the tenant: a
		// Guacamole session belongs to whoever owns the route it was brokered
		// through. Same bypassed-sync reasoning as the Ziti path above.
		var routeID *string
		orgID := orgctx.DefaultOrgID
		if session.ConnectionID != "" {
			var rid, rorg string
			err := uas.db.Pool.QueryRow(ctx,
				//orgscope:ignore external audit sync correlation; maps a Guacamole session to its route by the broker's own connection id, and reads that route's org to attribute the event
				`SELECT gc.route_id, r.org_id::text
				   FROM guacamole_connections gc
				   JOIN proxy_routes r ON r.id = gc.route_id
				  WHERE gc.guacamole_connection_id = $1`,
				session.ConnectionID).Scan(&rid, &rorg)
			if err == nil {
				routeID = &rid
				if rorg != "" {
					orgID = rorg
				}
			}
		}

		eventType := "connection.start"
		if session.EndTime != nil {
			eventType = "connection.end"
		}

		detailsJSON, _ := json.Marshal(details)
		//orgscope:ignore install-wide session-history ingest running under WithBypassRLS; org_id is derived per session from the route above
		uas.db.Pool.Exec(ctx, `
			INSERT INTO unified_audit_events (id, org_id, source, event_type, route_id, actor_ip, details, created_at)
			VALUES ($1, $2, 'guacamole', $3, $4, $5, $6, $7)
			ON CONFLICT DO NOTHING
		`, uuid.New().String(), orgID, eventType, routeID, session.RemoteIP, detailsJSON, session.StartTime)
	}

	// Update sync state
	uas.db.Pool.Exec(ctx, `
		UPDATE external_audit_sync_state
		SET last_sync_at = NOW(), updated_at = NOW()
		WHERE source = 'guacamole'
	`)

	return nil
}

// ---- HTTP Handlers ----

// handleGetUnifiedAuditEvents returns combined audit events
func (s *Service) handleGetUnifiedAuditEvents(c *gin.Context) {
	if s.auditService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "audit service not initialized"})
		return
	}

	filters := &AuditQueryFilters{
		Limit:  100,
		Offset: 0,
	}

	// Parse query parameters
	if sources := c.Query("source"); sources != "" {
		filters.Sources = strings.Split(sources, ",")
	}
	if routeID := c.Query("route_id"); routeID != "" {
		filters.RouteID = routeID
	}
	if userID := c.Query("user_id"); userID != "" {
		filters.UserID = userID
	}
	if eventTypes := c.Query("event_type"); eventTypes != "" {
		filters.EventTypes = strings.Split(eventTypes, ",")
	}
	if start := c.Query("start"); start != "" {
		if t, err := time.Parse(time.RFC3339, start); err == nil {
			filters.StartTime = t
		}
	}
	if end := c.Query("end"); end != "" {
		if t, err := time.Parse(time.RFC3339, end); err == nil {
			filters.EndTime = t
		}
	}
	if limit := c.Query("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 && l <= 1000 {
			filters.Limit = l
		}
	}
	if offset := c.Query("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil && o >= 0 {
			filters.Offset = o
		}
	}

	result, err := s.auditService.QueryEvents(c.Request.Context(), filters)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("Failed to query audit events", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, result)
}

// handleGetServiceAuditEvents returns audit events for a specific service
func (s *Service) handleGetServiceAuditEvents(c *gin.Context) {
	if s.auditService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "audit service not initialized"})
		return
	}

	routeID := c.Param("id")

	filters := &AuditQueryFilters{
		RouteID: routeID,
		Limit:   50,
		Offset:  0,
	}

	if limit := c.Query("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 && l <= 1000 {
			filters.Limit = l
		}
	}

	result, err := s.auditService.QueryEvents(c.Request.Context(), filters)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("Failed to query service audit events", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, result)
}

// handleSyncExternalAuditEvents triggers a sync of external audit events
func (s *Service) handleSyncExternalAuditEvents(c *gin.Context) {
	if s.auditService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "audit service not initialized"})
		return
	}

	// Bypass RLS: external-audit correlation maps controller events to routes by
	// globally-unique ziti_service_name across all tenants (the background caller
	// already runs bypassed; this is the admin HTTP trigger).
	err := s.auditService.SyncExternalAuditEvents(orgctx.WithBypassRLS(c.Request.Context()))
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("sync external audit events", err), s.logger)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "sync completed"})
}

// handleGetAuditEventsSummary returns a summary of audit events
func (s *Service) handleGetAuditEventsSummary(c *gin.Context) {
	if s.auditService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "audit service not initialized"})
		return
	}

	// Every count here is one tenant's. Before v142 all three spanned the
	// install, so the "last 24h" headline on one tenant's audit page was the
	// sum of everybody's activity.
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get audit events summary", err), s.logger)
		return
	}

	// Get counts by source
	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT source, COUNT(*) as count
		FROM unified_audit_events
		WHERE org_id = $1 AND created_at > NOW() - INTERVAL '24 hours'
		GROUP BY source
	`, org.ID)
	if err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get audit events summary", err), s.logger)
		return
	}
	defer rows.Close()

	countsBySource := make(map[string]int)
	for rows.Next() {
		var source string
		var count int
		if rows.Scan(&source, &count) == nil {
			countsBySource[source] = count
		}
	}

	// Get recent event types
	typeRows, _ := s.db.Pool.Query(c.Request.Context(), `
		SELECT event_type, COUNT(*) as count
		FROM unified_audit_events
		WHERE org_id = $1 AND created_at > NOW() - INTERVAL '24 hours'
		GROUP BY event_type
		ORDER BY count DESC
		LIMIT 10
	`, org.ID)
	countsByType := make(map[string]int)
	if typeRows != nil {
		defer typeRows.Close()
		for typeRows.Next() {
			var eventType string
			var count int
			if typeRows.Scan(&eventType, &count) == nil {
				countsByType[eventType] = count
			}
		}
	}

	// Get total count
	var total int
	s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM unified_audit_events
		  WHERE org_id = $1 AND created_at > NOW() - INTERVAL '24 hours'`, org.ID).
		Scan(&total)

	c.JSON(http.StatusOK, gin.H{
		"total_last_24h": total,
		"by_source":      countsBySource,
		"by_event_type":  countsByType,
		"timestamp":      time.Now(),
	})
}
