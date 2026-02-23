// Package governance provides Zero Trust policy storage with PostgreSQL and versioning
package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// ZTPolicyStore handles policy persistence with versioning and audit trail
type ZTPolicyStore struct {
	db     *database.PostgresDB
	logger *zap.Logger
}

// NewZTPolicyStore creates a new policy store
func NewZTPolicyStore(db *database.PostgresDB, logger *zap.Logger) *ZTPolicyStore {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ZTPolicyStore{
		db:     db,
		logger: logger.With(zap.String("component", "zt_policy_store")),
	}
}

// initSchema initializes the database schema for Zero Trust policies
func (s *ZTPolicyStore) initSchema(ctx context.Context) error {
	queries := []string{
		// Main policies table
		`CREATE TABLE IF NOT EXISTS zt_policies (
			id UUID PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			description TEXT,
			effect VARCHAR(20) NOT NULL CHECK (effect IN ('allow', 'deny')),
			conditions JSONB NOT NULL,
			priority INTEGER DEFAULT 0,
			enabled BOOLEAN DEFAULT true,
			tenant_id VARCHAR(255),
			version INTEGER DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by VARCHAR(255),
			updated_by VARCHAR(255),
			metadata JSONB
		)`,

		// Policy versions table for audit trail
		`CREATE TABLE IF NOT EXISTS zt_policy_versions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			policy_id UUID NOT NULL,
			version INTEGER NOT NULL,
			policy_data JSONB NOT NULL,
			change_type VARCHAR(50) NOT NULL,
			changed_by VARCHAR(255),
			change_reason TEXT,
			changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (policy_id) REFERENCES zt_policies(id) ON DELETE CASCADE
		)`,

		// Indexes
		`CREATE INDEX IF NOT EXISTS idx_zt_policies_tenant_id ON zt_policies(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_zt_policies_enabled ON zt_policies(enabled)`,
		`CREATE INDEX IF NOT EXISTS idx_zt_policies_priority ON zt_policies(priority DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_zt_policies_effect ON zt_policies(effect)`,
		`CREATE INDEX IF NOT EXISTS idx_zt_policy_versions_policy_id ON zt_policy_versions(policy_id)`,
		`CREATE INDEX IF NOT EXISTS idx_zt_policy_versions_changed_at ON zt_policy_versions(changed_at DESC)`,
	}

	for _, query := range queries {
		if _, err := s.db.Pool.Exec(ctx, query); err != nil {
			return fmt.Errorf("failed to execute schema query: %w", err)
		}
	}

	return nil
}

// Create creates a new policy
func (s *ZTPolicyStore) Create(ctx context.Context, policy ZTPolicy, changedBy string) (*ZTPolicy, error) {
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}

	// Generate ID if not provided
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}

	// Set timestamps
	now := time.Now()
	policy.CreatedAt = now
	policy.UpdatedAt = now
	policy.Version = 1
	policy.CreatedBy = changedBy
	policy.UpdatedBy = changedBy

	// Serialize conditions
	conditionsJSON, err := json.Marshal(policy.Conditions)
	if err != nil {
		return nil, fmt.Errorf("marshal conditions: %w", err)
	}

	// Serialize metadata
	var metadataJSON []byte
	if policy.Metadata != nil {
		metadataJSON = policy.Metadata
	} else {
		metadataJSON = []byte("{}")
	}

	// Insert policy
	query := `
		INSERT INTO zt_policies (
			id, name, description, effect, conditions, priority, enabled,
			tenant_id, version, created_at, updated_at, created_by, updated_by, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id, version, created_at, updated_at
	`

	row := s.db.Pool.QueryRow(ctx, query,
		policy.ID, policy.Name, policy.Description, policy.Effect,
		conditionsJSON, policy.Priority, policy.Enabled, policy.TenantID,
		policy.Version, policy.CreatedAt, policy.UpdatedAt,
		policy.CreatedBy, policy.UpdatedBy, metadataJSON,
	)

	if err := row.Scan(&policy.ID, &policy.Version, &policy.CreatedAt, &policy.UpdatedAt); err != nil {
		return nil, fmt.Errorf("insert policy: %w", err)
	}

	// Create version record
	if err := s.createVersion(ctx, policy, "created", changedBy, ""); err != nil {
		s.logger.Error("Failed to create version record", zap.Error(err))
	}

	s.logger.Info("Policy created",
		zap.String("policy_id", policy.ID),
		zap.String("name", policy.Name),
		zap.Int("version", policy.Version),
	)

	return &policy, nil
}

// Get retrieves a policy by ID (latest version)
func (s *ZTPolicyStore) Get(ctx context.Context, id string) (*ZTPolicy, error) {
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}

	query := `
		SELECT id, name, description, effect, conditions, priority, enabled,
		       tenant_id, version, created_at, updated_at, created_by, updated_by, metadata
		FROM zt_policies
		WHERE id = $1
	`

	policy := &ZTPolicy{}
	var conditionsJSON, metadataJSON []byte

	err := s.db.Pool.QueryRow(ctx, query, id).Scan(
		&policy.ID, &policy.Name, &policy.Description, &policy.Effect,
		&conditionsJSON, &policy.Priority, &policy.Enabled, &policy.TenantID,
		&policy.Version, &policy.CreatedAt, &policy.UpdatedAt,
		&policy.CreatedBy, &policy.UpdatedBy, &metadataJSON,
	)

	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("policy not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("query policy: %w", err)
	}

	// Deserialize conditions
	if err := json.Unmarshal(conditionsJSON, &policy.Conditions); err != nil {
		return nil, fmt.Errorf("unmarshal conditions: %w", err)
	}

	// Deserialize metadata
	if len(metadataJSON) > 0 {
		policy.Metadata = metadataJSON
	}

	return policy, nil
}

// GetByVersion retrieves a specific version of a policy
func (s *ZTPolicyStore) GetByVersion(ctx context.Context, policyID string, version int) (*ZTPolicy, error) {
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}

	query := `
		SELECT policy_data
		FROM zt_policy_versions
		WHERE policy_id = $1 AND version = $2
		ORDER BY changed_at DESC
		LIMIT 1
	`

	var policyDataJSON []byte
	err := s.db.Pool.QueryRow(ctx, query, policyID, version).Scan(&policyDataJSON)

	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("policy version not found: %s@%d", policyID, version)
	}
	if err != nil {
		return nil, fmt.Errorf("query policy version: %w", err)
	}

	var policy ZTPolicy
	if err := json.Unmarshal(policyDataJSON, &policy); err != nil {
		return nil, fmt.Errorf("unmarshal policy data: %w", err)
	}

	return &policy, nil
}

// List retrieves all policies, optionally filtered
func (s *ZTPolicyStore) List(ctx context.Context, filter *PolicyFilter) ([]ZTPolicy, error) {
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}

	query := `
		SELECT id, name, description, effect, conditions, priority, enabled,
		       tenant_id, version, created_at, updated_at, created_by, updated_by, metadata
		FROM zt_policies
		WHERE 1=1
	`
	args := []interface{}{}
	argPos := 1

	if filter != nil {
		if filter.TenantID != "" {
			query += fmt.Sprintf(" AND tenant_id = $%d", argPos)
			args = append(args, filter.TenantID)
			argPos++
		}
		if filter.Enabled != nil {
			query += fmt.Sprintf(" AND enabled = $%d", argPos)
			args = append(args, *filter.Enabled)
			argPos++
		}
		if filter.Effect != "" {
			query += fmt.Sprintf(" AND effect = $%d", argPos)
			args = append(args, filter.Effect)
			argPos++
		}
	}

	query += " ORDER BY priority DESC, created_at ASC"

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query policies: %w", err)
	}
	defer rows.Close()

	policies := make([]ZTPolicy, 0)
	for rows.Next() {
		policy := ZTPolicy{}
		var conditionsJSON, metadataJSON []byte

		if err := rows.Scan(
			&policy.ID, &policy.Name, &policy.Description, &policy.Effect,
			&conditionsJSON, &policy.Priority, &policy.Enabled, &policy.TenantID,
			&policy.Version, &policy.CreatedAt, &policy.UpdatedAt,
			&policy.CreatedBy, &policy.UpdatedBy, &metadataJSON,
		); err != nil {
			return nil, fmt.Errorf("scan policy row: %w", err)
		}

		if err := json.Unmarshal(conditionsJSON, &policy.Conditions); err != nil {
			return nil, fmt.Errorf("unmarshal conditions: %w", err)
		}

		if len(metadataJSON) > 0 {
			policy.Metadata = metadataJSON
		}

		policies = append(policies, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy rows: %w", err)
	}

	return policies, nil
}

// Update updates an existing policy (creates new version)
func (s *ZTPolicyStore) Update(ctx context.Context, policy ZTPolicy, changedBy string) (*ZTPolicy, error) {
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}

	// Get current version to increment
	current, err := s.Get(ctx, policy.ID)
	if err != nil {
		return nil, fmt.Errorf("get current policy: %w", err)
	}

	// Increment version
	policy.Version = current.Version + 1
	policy.CreatedAt = current.CreatedAt
	policy.CreatedBy = current.CreatedBy
	policy.UpdatedAt = time.Now()
	policy.UpdatedBy = changedBy

	// Serialize data
	conditionsJSON, err := json.Marshal(policy.Conditions)
	if err != nil {
		return nil, fmt.Errorf("marshal conditions: %w", err)
	}

	var metadataJSON []byte
	if policy.Metadata != nil {
		metadataJSON = policy.Metadata
	} else {
		metadataJSON = []byte("{}")
	}

	// Update policy
	query := `
		UPDATE zt_policies
		SET name = $2, description = $3, effect = $4, conditions = $5,
		    priority = $6, enabled = $7, tenant_id = $8, version = $9,
		    updated_at = $10, updated_by = $11, metadata = $12
		WHERE id = $1
		RETURNING version, updated_at
	`

	row := s.db.Pool.QueryRow(ctx, query,
		policy.ID, policy.Name, policy.Description, policy.Effect,
		conditionsJSON, policy.Priority, policy.Enabled, policy.TenantID,
		policy.Version, policy.UpdatedAt, policy.UpdatedBy, metadataJSON,
	)

	if err := row.Scan(&policy.Version, &policy.UpdatedAt); err != nil {
		return nil, fmt.Errorf("update policy: %w", err)
	}

	// Create version record
	if err := s.createVersion(ctx, policy, "updated", changedBy, ""); err != nil {
		s.logger.Error("Failed to create version record", zap.Error(err))
	}

	s.logger.Info("Policy updated",
		zap.String("policy_id", policy.ID),
		zap.String("name", policy.Name),
		zap.Int("version", policy.Version),
	)

	return &policy, nil
}

// Delete soft-deletes a policy (sets enabled = false)
func (s *ZTPolicyStore) Delete(ctx context.Context, id string, changedBy string) error {
	if err := s.initSchema(ctx); err != nil {
		return fmt.Errorf("init schema: %w", err)
	}

	// Get policy before deleting
	policy, err := s.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("get policy: %w", err)
	}

	// Soft delete by disabling
	query := `UPDATE zt_policies SET enabled = false, updated_at = $1, updated_by = $2 WHERE id = $3`
	if _, err := s.db.Pool.Exec(ctx, query, time.Now(), changedBy, id); err != nil {
		return fmt.Errorf("soft delete policy: %w", err)
	}

	// Create version record
	policy.Enabled = false
	if err := s.createVersion(ctx, *policy, "deleted", changedBy, ""); err != nil {
		s.logger.Error("Failed to create version record", zap.Error(err))
	}

	s.logger.Info("Policy deleted", zap.String("policy_id", id))
	return nil
}

// DeleteHard permanently deletes a policy
func (s *ZTPolicyStore) DeleteHard(ctx context.Context, id string) error {
	if err := s.initSchema(ctx); err != nil {
		return fmt.Errorf("init schema: %w", err)
	}

	// Get policy before deleting for version record
	policy, err := s.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("get policy: %w", err)
	}

	// Create version record before hard delete
	if err := s.createVersion(ctx, *policy, "hard_deleted", "", ""); err != nil {
		s.logger.Error("Failed to create version record", zap.Error(err))
	}

	// Hard delete
	query := `DELETE FROM zt_policies WHERE id = $1`
	if _, err := s.db.Pool.Exec(ctx, query, id); err != nil {
		return fmt.Errorf("hard delete policy: %w", err)
	}

	s.logger.Info("Policy hard deleted", zap.String("policy_id", id))
	return nil
}

// GetHistory retrieves the version history of a policy
func (s *ZTPolicyStore) GetHistory(ctx context.Context, policyID string) ([]PolicyVersion, error) {
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}

	query := `
		SELECT id, policy_id, version, policy_data, change_type,
		       changed_by, change_reason, changed_at
		FROM zt_policy_versions
		WHERE policy_id = $1
		ORDER BY changed_at DESC
	`

	rows, err := s.db.Pool.Query(ctx, query, policyID)
	if err != nil {
		return nil, fmt.Errorf("query policy versions: %w", err)
	}
	defer rows.Close()

	versions := make([]PolicyVersion, 0)
	for rows.Next() {
		v := PolicyVersion{}
		if err := rows.Scan(
			&v.ID, &v.PolicyID, &v.Version, &v.PolicyData,
			&v.ChangeType, &v.ChangedBy, &v.ChangeReason, &v.ChangedAt,
		); err != nil {
			return nil, fmt.Errorf("scan version row: %w", err)
		}
		versions = append(versions, v)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate version rows: %w", err)
	}

	return versions, nil
}

// createVersion creates a version record for audit trail
func (s *ZTPolicyStore) createVersion(ctx context.Context, policy ZTPolicy, changeType, changedBy, reason string) error {
	policyData, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("marshal policy data: %w", err)
	}

	query := `
		INSERT INTO zt_policy_versions (
			policy_id, version, policy_data, change_type, changed_by, change_reason
		) VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err = s.db.Pool.Exec(ctx, query,
		policy.ID, policy.Version, policyData, changeType, changedBy, reason,
	)

	return err
}

// PolicyFilter defines filter options for listing policies
type PolicyFilter struct {
	TenantID string
	Enabled  *bool
	Effect   string
}

// LoadAllEvaluator loads all enabled policies into an evaluator
func (s *ZTPolicyStore) LoadAllEvaluator(ctx context.Context) (*ZTPolicyEvaluator, error) {
	enabled := true
	policies, err := s.List(ctx, &PolicyFilter{Enabled: &enabled})
	if err != nil {
		return nil, fmt.Errorf("list enabled policies: %w", err)
	}

	eval := NewZTPolicyEvaluator()
	eval.SetPolicies(policies)

	s.logger.Info("Loaded policies into evaluator",
		zap.Int("count", len(policies)),
	)

	return eval, nil
}

// LoadByTenant loads policies for a specific tenant into an evaluator
func (s *ZTPolicyStore) LoadByTenant(ctx context.Context, tenantID string) (*ZTPolicyEvaluator, error) {
	enabled := true
	policies, err := s.List(ctx, &PolicyFilter{TenantID: tenantID, Enabled: &enabled})
	if err != nil {
		return nil, fmt.Errorf("list tenant policies: %w", err)
	}

	eval := NewZTPolicyEvaluator()
	eval.SetPolicies(policies)

	return eval, nil
}

// SetEnabled enables or disables a policy
func (s *ZTPolicyStore) SetEnabled(ctx context.Context, id string, enabled bool, changedBy string) error {
	if err := s.initSchema(ctx); err != nil {
		return fmt.Errorf("init schema: %w", err)
	}

	// Get current policy
	policy, err := s.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("get policy: %w", err)
	}

	// Update enabled status
	query := `UPDATE zt_policies SET enabled = $1, updated_at = $2, updated_by = $3 WHERE id = $4`
	result, err := s.db.Pool.Exec(ctx, query, enabled, time.Now(), changedBy, id)
	if err != nil {
		return fmt.Errorf("update enabled status: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("policy not found: %s", id)
	}

	// Create version record
	policy.Enabled = enabled
	changeType := "enabled"
	if !enabled {
		changeType = "disabled"
	}
	if err := s.createVersion(ctx, *policy, changeType, changedBy, ""); err != nil {
		s.logger.Error("Failed to create version record", zap.Error(err))
	}

	return nil
}

// Count returns the count of policies matching the filter
func (s *ZTPolicyStore) Count(ctx context.Context, filter *PolicyFilter) (int, error) {
	if err := s.initSchema(ctx); err != nil {
		return 0, fmt.Errorf("init schema: %w", err)
	}

	query := `SELECT COUNT(*) FROM zt_policies WHERE 1=1`
	args := []interface{}{}
	argPos := 1

	if filter != nil {
		if filter.TenantID != "" {
			query += fmt.Sprintf(" AND tenant_id = $%d", argPos)
			args = append(args, filter.TenantID)
			argPos++
		}
		if filter.Enabled != nil {
			query += fmt.Sprintf(" AND enabled = $%d", argPos)
			args = append(args, *filter.Enabled)
			argPos++
		}
		if filter.Effect != "" {
			query += fmt.Sprintf(" AND effect = $%d", argPos)
			args = append(args, filter.Effect)
			argPos++
		}
	}

	var count int
	if err := s.db.Pool.QueryRow(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("query count: %w", err)
	}

	return count, nil
}

// GetByEffect retrieves policies by their effect (allow/deny)
func (s *ZTPolicyStore) GetByEffect(ctx context.Context, effect PolicyEffect, tenantID string) ([]ZTPolicy, error) {
	return s.List(ctx, &PolicyFilter{
		Effect:   string(effect),
		TenantID: tenantID,
	})
}

// GetByName retrieves a policy by name
func (s *ZTPolicyStore) GetByName(ctx context.Context, name string, tenantID string) (*ZTPolicy, error) {
	if err := s.initSchema(ctx); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}

	query := `
		SELECT id, name, description, effect, conditions, priority, enabled,
		       tenant_id, version, created_at, updated_at, created_by, updated_by, metadata
		FROM zt_policies
		WHERE name = $1
	`
	args := []interface{}{name}
	argPos := 2

	if tenantID != "" {
		query += fmt.Sprintf(" AND tenant_id = $%d", argPos)
		args = append(args, tenantID)
	}

	policy := &ZTPolicy{}
	var conditionsJSON, metadataJSON []byte

	err := s.db.Pool.QueryRow(ctx, query, args...).Scan(
		&policy.ID, &policy.Name, &policy.Description, &policy.Effect,
		&conditionsJSON, &policy.Priority, &policy.Enabled, &policy.TenantID,
		&policy.Version, &policy.CreatedAt, &policy.UpdatedAt,
		&policy.CreatedBy, &policy.UpdatedBy, &metadataJSON,
	)

	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("policy not found: %s", name)
	}
	if err != nil {
		return nil, fmt.Errorf("query policy by name: %w", err)
	}

	if err := json.Unmarshal(conditionsJSON, &policy.Conditions); err != nil {
		return nil, fmt.Errorf("unmarshal conditions: %w", err)
	}

	if len(metadataJSON) > 0 {
		policy.Metadata = metadataJSON
	}

	return policy, nil
}

// BulkUpdate updates multiple policies in a transaction
func (s *ZTPolicyStore) BulkUpdate(ctx context.Context, policies []ZTPolicy, changedBy string) ([]ZTPolicy, error) {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Use a wrapper that implements the same interface but uses the transaction
	updated := make([]ZTPolicy, 0, len(policies))

	for _, policy := range policies {
		// For each policy, we need to update using the transaction
		current, err := s.Get(ctx, policy.ID)
		if err != nil {
			return nil, fmt.Errorf("get policy %s: %w", policy.ID, err)
		}

		policy.Version = current.Version + 1
		policy.CreatedAt = current.CreatedAt
		policy.CreatedBy = current.CreatedBy
		policy.UpdatedAt = time.Now()
		policy.UpdatedBy = changedBy

		conditionsJSON, err := json.Marshal(policy.Conditions)
		if err != nil {
			return nil, fmt.Errorf("marshal conditions: %w", err)
		}

		var metadataJSON []byte
		if policy.Metadata != nil {
			metadataJSON = policy.Metadata
		} else {
			metadataJSON = []byte("{}")
		}

		query := `
			UPDATE zt_policies
			SET name = $2, description = $3, effect = $4, conditions = $5,
			    priority = $6, enabled = $7, tenant_id = $8, version = $9,
			    updated_at = $10, updated_by = $11, metadata = $12
			WHERE id = $1
			RETURNING version, updated_at
		`

		row := tx.QueryRow(ctx, query,
			policy.ID, policy.Name, policy.Description, policy.Effect,
			conditionsJSON, policy.Priority, policy.Enabled, policy.TenantID,
			policy.Version, policy.UpdatedAt, policy.UpdatedBy, metadataJSON,
		)

		if err := row.Scan(&policy.Version, &policy.UpdatedAt); err != nil {
			return nil, fmt.Errorf("update policy %s: %w", policy.ID, err)
		}

		updated = append(updated, policy)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	// Create version records after commit
	for _, policy := range updated {
		if err := s.createVersion(ctx, policy, "bulk_updated", changedBy, ""); err != nil {
			s.logger.Error("Failed to create version record",
				zap.String("policy_id", policy.ID),
				zap.Error(err),
			)
		}
	}

	s.logger.Info("Bulk updated policies",
		zap.Int("count", len(updated)),
		zap.String("changed_by", changedBy),
	)

	return updated, nil
}
