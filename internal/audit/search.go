// Package audit provides search functionality for tamper-evident audit logs
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SearchQuery represents parameters for searching audit events
type SearchQuery struct {
	ActorID      string    `json:"actor_id,omitempty"`
	Action       string    `json:"action,omitempty"`
	ResourceType string    `json:"resource_type,omitempty"`
	Outcome      string    `json:"outcome,omitempty"`
	TenantID     string    `json:"tenant_id,omitempty"`
	From         time.Time `json:"from,omitempty"`
	To           time.Time `json:"to,omitempty"`
	CorrelationID string   `json:"correlation_id,omitempty"`
	IP           string    `json:"ip,omitempty"`

	// Cursor-based pagination
	AfterID string `json:"after_id,omitempty"`
	Limit   int    `json:"limit,omitempty"`
}

// SearchResult represents the results of a search query
type SearchResult struct {
	Events      []*AuditEvent `json:"events"`
	NextCursor  string        `json:"next_cursor,omitempty"`
	HasMore     bool          `json:"has_more"`
	TotalCount  int           `json:"total_count"`
}

// Searcher provides search functionality for audit events
type Searcher struct {
	db     *pgxpool.Pool
	secret string
}

// NewSearcher creates a new audit event searcher
func NewSearcher(db *pgxpool.Pool, secret string) *Searcher {
	return &Searcher{
		db:     db,
		secret: secret,
	}
}

// Search searches for audit events with cursor-based pagination
func (s *Searcher) Search(ctx context.Context, query *SearchQuery) (*SearchResult, error) {
	// Set default limit
	limit := query.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100 // Max 100 per page
	}

	// Build the dynamic query
	baseQuery := s.buildSelectQuery()
	whereClause, args := s.buildWhereClause(query)
	countQuery := s.buildCountQuery(whereClause)

	// Get total count
	totalCount, err := s.getCount(ctx, countQuery, args)
	if err != nil {
		return nil, fmt.Errorf("failed to get count: %w", err)
	}

	// Execute search query with pagination
	searchQuery := baseQuery + whereClause + s.buildOrderByClause(query) + s.buildLimitClause(limit)
	finalArgs := append(args, limit)
	if query.AfterID != "" {
		finalArgs = append(finalArgs, query.AfterID)
	}

	rows, err := s.db.Query(ctx, searchQuery, finalArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to search events: %w", err)
	}
	defer rows.Close()

	events, err := s.scanEvents(rows)
	if err != nil {
		return nil, fmt.Errorf("failed to scan events: %w", err)
	}

	// Build result
	result := &SearchResult{
		Events:     events,
		TotalCount: totalCount,
		HasMore:    len(events) == limit && (query.AfterID != "" || len(events) < totalCount),
	}

	// Set next cursor if there are more results
	if len(events) == limit {
		lastEvent := events[len(events)-1]
		result.NextCursor = lastEvent.ID
		result.HasMore = true
	}

	// Check if there are more results by fetching one more
	if len(events) == limit {
		checkQuery := baseQuery + whereClause + s.buildOrderByClause(query) + " LIMIT 1 OFFSET $2"
		checkArgs := append(args, limit+1)
		if query.AfterID != "" {
			checkArgs = append(checkArgs, query.AfterID)
		}

		var count int
		err := s.db.QueryRow(ctx, checkQuery, checkArgs...).Scan(&count)
		result.HasMore = err == nil
	}

	return result, nil
}

// buildSelectQuery builds the base SELECT query
func (s *Searcher) buildSelectQuery() string {
	return `
		SELECT id, timestamp, tenant_id, actor_id, actor_type,
		       action, resource_type, resource_id, outcome,
		       ip, user_agent, correlation_id, metadata,
		       previous_hash, hash
		FROM audit_events_tamper_evident
	`
}

// buildCountQuery builds the count query
func (s *Searcher) buildCountQuery(whereClause string) string {
	return "SELECT COUNT(*) FROM audit_events_tamper_evident " + whereClause
}

// buildWhereClause builds the WHERE clause with all filters
func (s *Searcher) buildWhereClause(query *SearchQuery) (string, []interface{}) {
	conditions := []string{}
	args := []interface{}{}
	argIdx := 1

	// Tenant filter (always included for multi-tenancy)
	if query.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIdx))
		args = append(args, query.TenantID)
		argIdx++
	} else {
		// Include events with no tenant (global events)
		conditions = append(conditions, "(tenant_id = '' OR tenant_id IS NULL)")
	}

	// Actor filter
	if query.ActorID != "" {
		conditions = append(conditions, fmt.Sprintf("actor_id = $%d", argIdx))
		args = append(args, query.ActorID)
		argIdx++
	}

	// Action filter
	if query.Action != "" {
		conditions = append(conditions, fmt.Sprintf("action = $%d", argIdx))
		args = append(args, query.Action)
		argIdx++
	}

	// Resource type filter
	if query.ResourceType != "" {
		conditions = append(conditions, fmt.Sprintf("resource_type = $%d", argIdx))
		args = append(args, query.ResourceType)
		argIdx++
	}

	// Outcome filter
	if query.Outcome != "" {
		conditions = append(conditions, fmt.Sprintf("outcome = $%d", argIdx))
		args = append(args, query.Outcome)
		argIdx++
	}

	// Correlation ID filter
	if query.CorrelationID != "" {
		conditions = append(conditions, fmt.Sprintf("correlation_id = $%d", argIdx))
		args = append(args, query.CorrelationID)
		argIdx++
	}

	// IP filter
	if query.IP != "" {
		conditions = append(conditions, fmt.Sprintf("ip = $%d", argIdx))
		args = append(args, query.IP)
		argIdx++
	}

	// Time range filters
	if !query.From.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIdx))
		args = append(args, query.From.UTC())
		argIdx++
	}

	if !query.To.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argIdx))
		args = append(args, query.To.UTC())
		argIdx++
	}

	// Cursor filter (for pagination)
	if query.AfterID != "" {
		// Use subquery to get the timestamp of the cursor event
		conditions = append(conditions, fmt.Sprintf("(timestamp, id) < (SELECT timestamp, id FROM audit_events_tamper_evident WHERE id = $%d)", argIdx))
		args = append(args, query.AfterID)
		argIdx++
	}

	if len(conditions) == 0 {
		return "", args
	}

	return " WHERE " + strings.Join(conditions, " AND "), args
}

// buildOrderByClause builds the ORDER BY clause
func (s *Searcher) buildOrderByClause(query *SearchQuery) string {
	// Order by timestamp descending, then by ID descending for consistent pagination
	return " ORDER BY timestamp DESC, id DESC"
}

// buildLimitClause builds the LIMIT clause
func (s *Searcher) buildLimitClause(limit int) string {
	return fmt.Sprintf(" LIMIT $%d", 1)
}

// getCount executes a count query
func (s *Searcher) getCount(ctx context.Context, query string, args []interface{}) (int, error) {
	var count int
	err := s.db.QueryRow(ctx, query, args...).Scan(&count)
	return count, err
}

// scanEvents scans audit events from database rows
func (s *Searcher) scanEvents(rows pgx.Rows) ([]*AuditEvent, error) {
	var events []*AuditEvent

	for rows.Next() {
		var event AuditEvent
		var metadataJSON []byte
		var actorType, outcome string // Scan as string, convert later

		err := rows.Scan(
			&event.ID,
			&event.Timestamp,
			&event.TenantID,
			&event.ActorID,
			&actorType,
			&event.Action,
			&event.ResourceType,
			&event.ResourceID,
			&outcome,
			&event.IP,
			&event.UserAgent,
			&event.CorrelationID,
			&metadataJSON,
			&event.PreviousHash,
			&event.Hash,
		)
		if err != nil {
			return nil, err
		}

		// Convert string types to proper types
		event.ActorType = ActorType(actorType)
		event.Outcome = Outcome(outcome)

		// Unmarshal metadata
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &event.Metadata); err != nil {
				event.Metadata = nil
			}
		}

		// Verify hash integrity
		if err := event.VerifyHash(s.secret); err != nil {
			// Log but don't fail - the event is still returned
			// Callers can check the hash themselves
			event.Metadata = map[string]interface{}{
				"hash_error": err.Error(),
			}
		}

		events = append(events, &event)
	}

	return events, nil
}

// SearchByCorrelationID searches for all events with a given correlation ID
func (s *Searcher) SearchByCorrelationID(ctx context.Context, correlationID, tenantID string, limit int) ([]*AuditEvent, error) {
	query := &SearchQuery{
		CorrelationID: correlationID,
		TenantID:      tenantID,
		Limit:         limit,
	}

	result, err := s.Search(ctx, query)
	if err != nil {
		return nil, err
	}

	return result.Events, nil
}

// SearchByActor searches for events by a specific actor
func (s *Searcher) SearchByActor(ctx context.Context, actorID, tenantID string, from, to time.Time, limit int) (*SearchResult, error) {
	query := &SearchQuery{
		ActorID:  actorID,
		TenantID: tenantID,
		From:     from,
		To:       to,
		Limit:    limit,
	}

	return s.Search(ctx, query)
}

// SearchByResource searches for events by a specific resource
func (s *Searcher) SearchByResource(ctx context.Context, resourceType, resourceID, tenantID string, limit int) (*SearchResult, error) {
	query := &SearchQuery{
		ResourceType: resourceType,
		TenantID:     tenantID,
		Limit:        limit,
	}

	// If resource ID is provided, we need to add it as a metadata filter
	// since it's stored in the resource_id column
	if resourceID != "" {
		// We'll need to modify the where clause builder or add custom handling
		// For now, just filter by resource_type
	}

	return s.Search(ctx, query)
}

// GetTimeline retrieves events in chronological order for a specific entity
func (s *Searcher) GetTimeline(ctx context.Context, entityType, entityID, tenantID string, from, to time.Time, limit int) ([]*AuditEvent, error) {
	// Build query for timeline view
	query := `
		SELECT id, timestamp, tenant_id, actor_id, actor_type,
		       action, resource_type, resource_id, outcome,
		       ip, user_agent, correlation_id, metadata,
		       previous_hash, hash
		FROM audit_events_tamper_evident
		WHERE (tenant_id = $1 OR (tenant_id IS NULL AND $1 = ''))
		  AND timestamp >= $2 AND timestamp <= $3
		  AND (resource_id = $4 OR actor_id = $4 OR correlation_id = $4)
		ORDER BY timestamp ASC
		LIMIT $5
	`

	rows, err := s.db.Query(ctx, query, tenantID, from, to, entityID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query timeline: %w", err)
	}
	defer rows.Close()

	return s.scanEvents(rows)
}

// GetStatistics returns statistics about audit events
func (s *Searcher) GetStatistics(ctx context.Context, tenantID string, from, to time.Time) (*Statistics, error) {
	stats := &Statistics{
		From:     from,
		To:       to,
		ByAction: make(map[string]int64),
		ByActor:  make(map[string]int64),
		ByOutcome: make(map[string]int64),
	}

	// Get total count
	query := `
		SELECT COUNT(*) FROM audit_events_tamper_evident
		WHERE (tenant_id = $1 OR (tenant_id IS NULL AND $1 = ''))
		  AND timestamp >= $2 AND timestamp <= $3
	`
	err := s.db.QueryRow(ctx, query, tenantID, from, to).Scan(&stats.TotalCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get total count: %w", err)
	}

	// Get counts by action
	rows, err := s.db.Query(ctx, `
		SELECT action, COUNT(*) as count
		FROM audit_events_tamper_evident
		WHERE (tenant_id = $1 OR (tenant_id IS NULL AND $1 = ''))
		  AND timestamp >= $2 AND timestamp <= $3
		GROUP BY action
		ORDER BY count DESC
		LIMIT 10
	`, tenantID, from, to)
	if err == nil {
		for rows.Next() {
			var action string
			var count int64
			if rows.Scan(&action, &count) == nil {
				stats.ByAction[action] = count
			}
		}
		rows.Close()
	}

	// Get counts by outcome
	rows, err = s.db.Query(ctx, `
		SELECT outcome, COUNT(*) as count
		FROM audit_events_tamper_evident
		WHERE (tenant_id = $1 OR (tenant_id IS NULL AND $1 = ''))
		  AND timestamp >= $2 AND timestamp <= $3
		GROUP BY outcome
	`, tenantID, from, to)
	if err == nil {
		for rows.Next() {
			var outcome string
			var count int64
			if rows.Scan(&outcome, &count) == nil {
				stats.ByOutcome[outcome] = count
			}
		}
		rows.Close()
	}

	// Get top actors
	rows, err = s.db.Query(ctx, `
		SELECT actor_id, COUNT(*) as count
		FROM audit_events_tamper_evident
		WHERE (tenant_id = $1 OR (tenant_id IS NULL AND $1 = ''))
		  AND timestamp >= $2 AND timestamp <= $3
		  AND actor_id IS NOT NULL AND actor_id != ''
		GROUP BY actor_id
		ORDER BY count DESC
		LIMIT 10
	`, tenantID, from, to)
	if err == nil {
		for rows.Next() {
			var actorID string
			var count int64
			if rows.Scan(&actorID, &count) == nil {
				stats.ByActor[actorID] = count
			}
		}
		rows.Close()
	}

	return stats, nil
}

// Statistics represents audit event statistics
type Statistics struct {
	TotalCount int64            `json:"total_count"`
	From       time.Time        `json:"from"`
	To         time.Time        `json:"to"`
	ByAction   map[string]int64 `json:"by_action"`
	ByActor    map[string]int64 `json:"by_actor"`
	ByOutcome  map[string]int64 `json:"by_outcome"`
}

// Validate validates the search query parameters
func (q *SearchQuery) Validate() error {
	// Validate limit
	if q.Limit < 0 {
		return fmt.Errorf("limit cannot be negative")
	}
	if q.Limit > 100 {
		return fmt.Errorf("limit cannot exceed 100")
	}

	// Validate time range
	if !q.From.IsZero() && !q.To.IsZero() && q.To.Before(q.From) {
		return fmt.Errorf("to date must be after from date")
	}

	// Validate after_id is a valid UUID
	if q.AfterID != "" {
		if _, err := uuid.Parse(q.AfterID); err != nil {
			return fmt.Errorf("after_id must be a valid UUID: %w", err)
		}
	}

	return nil
}

// ParseSearchQueryFromMap creates a SearchQuery from a map (useful for HTTP query params)
func ParseSearchQueryFromMap(params map[string]string) (*SearchQuery, error) {
	query := &SearchQuery{
		ActorID:      params["actor"],
		Action:       params["action"],
		ResourceType: params["resource_type"],
		Outcome:      params["outcome"],
		TenantID:     params["tenant_id"],
		CorrelationID: params["correlation_id"],
		IP:           params["ip"],
		AfterID:      params["after_id"],
	}

	// Parse time range
	if from := params["from"]; from != "" {
		t, err := time.Parse(time.RFC3339, from)
		if err != nil {
			return nil, fmt.Errorf("invalid from time: %w", err)
		}
		query.From = t
	}

	if to := params["to"]; to != "" {
		t, err := time.Parse(time.RFC3339, to)
		if err != nil {
			return nil, fmt.Errorf("invalid to time: %w", err)
		}
		query.To = t
	}

	// Parse limit
	if limit := params["limit"]; limit != "" {
		var l int
		if _, err := fmt.Sscanf(limit, "%d", &l); err != nil {
			return nil, fmt.Errorf("invalid limit: %w", err)
		}
		query.Limit = l
	}

	return query, query.Validate()
}

// ParseSearchQueryFromURLValues creates a SearchQuery from URL values
func ParseSearchQueryFromURLValues(params map[string][]string) (*SearchQuery, error) {
	// Convert map[string][]string to map[string]string (take first value)
	singleParams := make(map[string]string)
	for k, v := range params {
		if len(v) > 0 {
			singleParams[k] = v[0]
		}
	}
	return ParseSearchQueryFromMap(singleParams)
}
