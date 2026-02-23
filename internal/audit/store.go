// Package audit provides tamper-evident audit logging storage with PostgreSQL
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// Store provides tamper-evident audit event storage with batch writing
type Store struct {
	db         *pgxpool.Pool
	logger     *Logger
	log        *zap.Logger
	buffer     []*AuditEvent
	bufferMu   sync.Mutex
	flushTimer *time.Timer
	stopChan   chan struct{}
	secret     string

	// Batch configuration
	batchSize int
	flushInterval time.Duration
}

// StoreConfig holds configuration for the audit store
type StoreConfig struct {
	BatchSize     int           // Number of events to buffer before auto-flush
	FlushInterval time.Duration // Maximum time before flushing buffer
	Secret        string        // HMAC secret for hash chain
}

// DefaultStoreConfig returns default store configuration
func DefaultStoreConfig() StoreConfig {
	return StoreConfig{
		BatchSize:     100,
		FlushInterval: 5 * time.Second,
		Secret:        "", // Must be set by caller
	}
}

// NewStore creates a new audit store with batch writing
func NewStore(db *pgxpool.Pool, config StoreConfig, logger *zap.Logger) (*Store, error) {
	if config.Secret == "" {
		return nil, fmt.Errorf("audit store secret cannot be empty")
	}

	if config.BatchSize <= 0 {
		config.BatchSize = 100
	}
	if config.FlushInterval <= 0 {
		config.FlushInterval = 5 * time.Second
	}

	store := &Store{
		db:            db,
		logger:        NewLogger(config.Secret),
		log:           logger.With(zap.String("component", "audit-store")),
		buffer:        make([]*AuditEvent, 0, config.BatchSize),
		stopChan:      make(chan struct{}),
		secret:        config.Secret,
		batchSize:     config.BatchSize,
		flushInterval: config.FlushInterval,
	}

	// Start background flush timer
	store.flushTimer = time.AfterFunc(config.FlushInterval, store.flushTick)

	return store, nil
}

// Write writes an audit event to the buffer for batch insertion
func (s *Store) Write(ctx context.Context, event *AuditEvent) error {
	// Get the last hash for chain linking
	lastHash, err := s.getLastHash(ctx, event.TenantID)
	if err != nil {
		return fmt.Errorf("failed to get last hash: %w", err)
	}

	// Prepare event with hash chain
	if err := s.logger.PrepareForStorage(event, lastHash); err != nil {
		return fmt.Errorf("failed to prepare event: %w", err)
	}

	// Add to buffer
	s.bufferMu.Lock()
	shouldFlush := len(s.buffer) >= s.batchSize-1
	s.buffer = append(s.buffer, event)
	s.bufferMu.Unlock()

	// Flush if buffer is full
	if shouldFlush {
		return s.Flush(ctx)
	}

	return nil
}

// Flush writes all buffered events to the database
func (s *Store) Flush(ctx context.Context) error {
	s.bufferMu.Lock()
	if len(s.buffer) == 0 {
		s.bufferMu.Unlock()
		return nil
	}

	// Copy buffer and clear
	events := make([]*AuditEvent, len(s.buffer))
	copy(events, s.buffer)
	s.buffer = s.buffer[:0]
	s.bufferMu.Unlock()

	// Reset timer
	s.flushTimer.Reset(s.flushInterval)

	// Batch insert
	if err := s.batchInsert(ctx, events); err != nil {
		s.log.Error("failed to batch insert audit events",
			zap.Int("count", len(events)),
			zap.Error(err))
		return err
	}

	s.log.Debug("flushed audit events", zap.Int("count", len(events)))
	return nil
}

// flushTick is called by the timer to flush the buffer
func (s *Store) flushTick() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_ = s.Flush(ctx)
}

// batchInsert inserts a batch of events using PostgreSQL COPY
func (s *Store) batchInsert(ctx context.Context, events []*AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	// Begin transaction
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Use batch insert with prepared statement
	// First ensure partition exists
	for _, event := range events {
		partitionName := GetPartitionName(event.Timestamp)
		if err := s.ensurePartition(ctx, tx, partitionName); err != nil {
			return fmt.Errorf("failed to ensure partition: %w", err)
		}
	}

	// Prepare batch insert statement
	stmt := `
		INSERT INTO audit_events_tamper_evident (
			id, timestamp, tenant_id, actor_id, actor_type,
			action, resource_type, resource_id, outcome,
			ip, user_agent, correlation_id, metadata,
			previous_hash, hash
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
		)
	`

	// Batch insert all events
	for _, event := range events {
		var metadataJSON []byte
		if event.Metadata != nil {
			metadataJSON, _ = json.Marshal(event.Metadata)
		}

		targetPartition := GetPartitionName(event.Timestamp)
		partitionStmt := fmt.Sprintf("INSERT INTO %s %s", targetPartition, stmt[13:])

		_, err := tx.Exec(ctx, partitionStmt,
			event.ID,
			event.Timestamp,
			event.TenantID,
			event.ActorID,
			string(event.ActorType),
			event.Action,
			event.ResourceType,
			event.ResourceID,
			string(event.Outcome),
			event.IP,
			event.UserAgent,
			event.CorrelationID,
			metadataJSON,
			event.PreviousHash,
			event.Hash,
		)
		if err != nil {
			return fmt.Errorf("failed to insert event %s: %w", event.ID, err)
		}
	}

	// Update chain state for each tenant
	if err := s.updateChainStates(ctx, tx, events); err != nil {
		return fmt.Errorf("failed to update chain states: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// updateChainStates updates the chain state for affected tenants
func (s *Store) updateChainStates(ctx context.Context, tx pgx.Tx, events []*AuditEvent) error {
	// Group events by tenant
	tenants := make(map[string]*AuditEvent)
	for _, event := range events {
		tenantKey := event.TenantID
		if tenantKey == "" {
			tenantKey = "default"
		}
		// Keep the last event for each tenant
		tenants[tenantKey] = event
	}

	// Update chain state for each tenant
	for tenantID, event := range tenants {
		upsertStmt := `
			INSERT INTO audit_chain_state (tenant_id, last_hash, last_event_id, last_sequence, updated_at)
			VALUES ($1, $2, $3, (
				SELECT COALESCE(MAX(sequence), 0) + 1 FROM audit_chain_state WHERE tenant_id = $1
			), NOW())
			ON CONFLICT (tenant_id) DO UPDATE
			SET last_hash = EXCLUDED.last_hash,
			    last_event_id = EXCLUDED.last_event_id,
			    last_sequence = audit_chain_state.last_sequence + 1,
			    updated_at = NOW()
		`

		_, err := tx.Exec(ctx, upsertStmt, tenantID, event.Hash, event.ID)
		if err != nil {
			return fmt.Errorf("failed to update chain state for tenant %s: %w", tenantID, err)
		}
	}

	return nil
}

// getLastHash retrieves the last hash in the chain for a tenant
func (s *Store) getLastHash(ctx context.Context, tenantID string) (string, error) {
	var lastHash string

	query := `SELECT last_hash FROM audit_chain_state WHERE tenant_id = $1`
	if tenantID == "" {
		query = `SELECT last_hash FROM audit_chain_state WHERE tenant_id = 'default'`
	} else {
		query = `SELECT last_hash FROM audit_chain_state WHERE tenant_id = $1`
	}

	err := s.db.QueryRow(ctx, query, tenantID).Scan(&lastHash)
	if err == pgx.ErrNoRows {
		// No previous hash - this is the first event
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to get last hash: %w", err)
	}

	return lastHash, nil
}

// ensurePartition ensures the monthly partition exists
func (s *Store) ensurePartition(ctx context.Context, tx pgx.Tx, partitionName string) error {
	// Check if partition exists
	var exists bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_tables WHERE tablename = $1
		)
	`, partitionName).Scan(&exists)

	if err != nil {
		return fmt.Errorf("failed to check partition: %w", err)
	}

	if exists {
		return nil
	}

	// Create partition
	_, err = tx.Exec(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s PARTITION OF audit_events_tamper_evident
		FOR VALUES FROM ('%s') TO ('%s')
	`, partitionName, getPartitionStart(partitionName), getPartitionEnd(partitionName)))

	if err != nil {
		return fmt.Errorf("failed to create partition: %w", err)
	}

	s.log.Info("created audit events partition", zap.String("partition", partitionName))
	return nil
}

// GetPartitionName returns the partition name for a given timestamp
func GetPartitionName(t time.Time) string {
	return fmt.Sprintf("audit_events_%s", t.Format("2006_01"))
}

// getPartitionStart returns the start date for a partition
func getPartitionStart(partitionName string) string {
	// Extract year and month from partition name like "audit_events_2024_01"
	var year, month int
	fmt.Sscanf(partitionName, "audit_events_%d_%d", &year, &month)
	return fmt.Sprintf("%04d-%02d-01", year, month)
}

// getPartitionEnd returns the end date for a partition
func getPartitionEnd(partitionName string) string {
	var year, month int
	fmt.Sscanf(partitionName, "audit_events_%d_%d", &year, &month)
	// Add one month
	if month == 12 {
		year++
		month = 1
	} else {
		month++
	}
	return fmt.Sprintf("%04d-%02d-01", year, month)
}

// ReadByID reads an audit event by ID, verifying its hash
func (s *Store) ReadByID(ctx context.Context, eventID string) (*AuditEvent, error) {
	var event AuditEvent
	var metadataJSON []byte

	query := `
		SELECT id, timestamp, tenant_id, actor_id, actor_type,
		       action, resource_type, resource_id, outcome,
		       ip, user_agent, correlation_id, metadata,
		       previous_hash, hash
		FROM audit_events_tamper_evident
		WHERE id = $1
	`

	err := s.db.QueryRow(ctx, query, eventID).Scan(
		&event.ID,
		&event.Timestamp,
		&event.TenantID,
		&event.ActorID,
		&event.ActorType,
		&event.Action,
		&event.ResourceType,
		&event.ResourceID,
		&event.Outcome,
		&event.IP,
		&event.UserAgent,
		&event.CorrelationID,
		&metadataJSON,
		&event.PreviousHash,
		&event.Hash,
	)

	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("audit event not found: %s", eventID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read event: %w", err)
	}

	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &event.Metadata); err != nil {
			s.log.Warn("failed to unmarshal metadata", zap.String("event_id", eventID), zap.Error(err))
		}
	}

	// Verify hash integrity
	if err := event.VerifyHash(s.secret); err != nil {
		s.log.Error("audit event hash verification failed",
			zap.String("event_id", eventID),
			zap.Error(err))
		return nil, fmt.Errorf("event integrity check failed: %w", err)
	}

	return &event, nil
}

// ReadChain reads a chain of events for verification
func (s *Store) ReadChain(ctx context.Context, tenantID string, limit int) ([]*AuditEvent, error) {
	query := `
		SELECT id, timestamp, tenant_id, actor_id, actor_type,
		       action, resource_type, resource_id, outcome,
		       ip, user_agent, correlation_id, metadata,
		       previous_hash, hash
		FROM audit_events_tamper_evident
		WHERE tenant_id = $1 OR (tenant_id IS NULL AND $1 = '')
		ORDER BY timestamp ASC
		LIMIT $2
	`

	rows, err := s.db.Query(ctx, query, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query chain: %w", err)
	}
	defer rows.Close()

	var events []*AuditEvent
	for rows.Next() {
		var event AuditEvent
		var metadataJSON []byte

		err := rows.Scan(
			&event.ID,
			&event.Timestamp,
			&event.TenantID,
			&event.ActorID,
			&event.ActorType,
			&event.Action,
			&event.ResourceType,
			&event.ResourceID,
			&event.Outcome,
			&event.IP,
			&event.UserAgent,
			&event.CorrelationID,
			&metadataJSON,
			&event.PreviousHash,
			&event.Hash,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}

		if len(metadataJSON) > 0 {
			json.Unmarshal(metadataJSON, &event.Metadata)
		}

		events = append(events, &event)
	}

	// Verify chain integrity
	if err := s.logger.VerifyEventList(events); err != nil {
		s.log.Error("audit chain verification failed", zap.Error(err))
		return nil, fmt.Errorf("chain verification failed: %w", err)
	}

	return events, nil
}

// VerifyIntegrity verifies the integrity of the audit chain for a tenant
func (s *Store) VerifyIntegrity(ctx context.Context, tenantID string) (*IntegrityReport, error) {
	report := &IntegrityReport{
		TenantID:    tenantID,
		VerifiedAt:  time.Now().UTC(),
		IsIntact:    true,
		Issues:      []string{},
		EventCount:  0,
	}

	// Get chain state for tenant
	var chainState ChainState
	err := s.db.QueryRow(ctx, `
		SELECT last_hash, last_event_id, last_sequence, updated_at
		FROM audit_chain_state
		WHERE tenant_id = $1
	`, tenantID).Scan(&chainState.LastHash, &chainState.LastEventID, &chainState.LastSequence, &chainState.UpdatedAt)

	if err == pgx.ErrNoRows {
		report.Issues = append(report.Issues, "no chain state found for tenant")
		return report, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get chain state: %w", err)
	}

	report.LastEventID = chainState.LastEventID
	report.LastSequence = chainState.LastSequence

	// Read and verify chain
	events, err := s.ReadChain(ctx, tenantID, 1000)
	if err != nil {
		if IsChainBreak(err) || IsTampered(err) {
			report.IsIntact = false
			report.Issues = append(report.Issues, err.Error())
			return report, nil
		}
		return nil, err
	}

	report.EventCount = len(events)

	if len(events) > 0 {
		lastEvent := events[len(events)-1]
		if lastEvent.Hash != chainState.LastHash {
			report.IsIntact = false
			report.Issues = append(report.Issues,
				fmt.Sprintf("chain state hash mismatch: state=%s, last_event=%s",
					chainState.LastHash, lastEvent.Hash))
		}
	}

	return report, nil
}

// IntegrityReport represents the result of an integrity verification
type IntegrityReport struct {
	TenantID     string    `json:"tenant_id"`
	IsIntact     bool      `json:"is_intact"`
	EventCount   int       `json:"event_count"`
	LastEventID  string    `json:"last_event_id,omitempty"`
	LastSequence int64     `json:"last_sequence,omitempty"`
	VerifiedAt   time.Time `json:"verified_at"`
	Issues       []string  `json:"issues,omitempty"`
}

// Close stops the background flusher and flushes remaining events
func (s *Store) Close(ctx context.Context) error {
	close(s.stopChan)

	// Stop timer
	if s.flushTimer != nil {
		s.flushTimer.Stop()
	}

	// Flush remaining events
	return s.Flush(ctx)
}

// InitializeSchema creates the necessary tables for tamper-evident audit logging
func InitializeSchema(ctx context.Context, db *pgxpool.Pool) error {
	// Create main partitioned table
	_, err := db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS audit_events_tamper_evident (
			id UUID PRIMARY KEY,
			timestamp TIMESTAMP NOT NULL,
			tenant_id VARCHAR(255),
			actor_id VARCHAR(255),
			actor_type VARCHAR(50),
			action VARCHAR(255) NOT NULL,
			resource_type VARCHAR(100),
			resource_id VARCHAR(255),
			outcome VARCHAR(50),
			ip VARCHAR(45),
			user_agent TEXT,
			correlation_id VARCHAR(255),
			metadata JSONB,
			previous_hash VARCHAR(128),
			hash VARCHAR(128) NOT NULL
		) PARTITION BY RANGE (timestamp);

		CREATE INDEX IF NOT EXISTS idx_audit_events_tamper_tenant ON audit_events_tamper_evident(tenant_id);
		CREATE INDEX IF NOT EXISTS idx_audit_events_tamper_timestamp ON audit_events_tamper_evident(timestamp);
		CREATE INDEX IF NOT EXISTS idx_audit_events_tamper_actor_id ON audit_events_tamper_evident(actor_id);
		CREATE INDEX IF NOT EXISTS idx_audit_events_tamper_action ON audit_events_tamper_evident(action);
		CREATE INDEX IF NOT EXISTS idx_audit_events_tamper_resource_type ON audit_events_tamper_evident(resource_type);
		CREATE INDEX IF NOT EXISTS idx_audit_events_tamper_hash ON audit_events_tamper_evident(hash);
	`)

	if err != nil {
		return fmt.Errorf("failed to create main table: %w", err)
	}

	// Create chain state table
	_, err = db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS audit_chain_state (
			tenant_id VARCHAR(255) PRIMARY KEY,
			last_hash VARCHAR(128) NOT NULL,
			last_event_id VARCHAR(128) NOT NULL,
			last_sequence BIGINT NOT NULL DEFAULT 0,
			updated_at TIMESTAMP NOT NULL
		);
	`)

	if err != nil {
		return fmt.Errorf("failed to create chain state table: %w", err)
	}

	// Create current month's partition
	now := time.Now().UTC()
	partitionName := GetPartitionName(now)
	startDate := fmt.Sprintf("%04d-%02d-01", now.Year(), now.Month())
	var endDate string
	if now.Month() == 12 {
		endDate = fmt.Sprintf("%04d-01-01", now.Year()+1)
	} else {
		endDate = fmt.Sprintf("%04d-%02d-01", now.Year(), now.Month()+1)
	}

	_, err = db.Exec(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s PARTITION OF audit_events_tamper_evident
		FOR VALUES FROM ('%s') TO ('%s')
	`, partitionName, startDate, endDate))

	if err != nil {
		return fmt.Errorf("failed to create initial partition: %w", err)
	}

	return nil
}
