package directory

import (
	"context"
	"encoding/json"
	"fmt"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// Service is the directory sync service facade
type Service struct {
	db        *database.PostgresDB
	logger    *zap.Logger
	scheduler *Scheduler
	engine    *SyncEngine
	cancelFn  context.CancelFunc
}

// NewService creates a new directory service
func NewService(db *database.PostgresDB, logger *zap.Logger) *Service {
	engine := NewSyncEngine(db, logger)
	scheduler := NewScheduler(db, engine, logger)

	return &Service{
		db:        db,
		logger:    logger.With(zap.String("service", "directory")),
		scheduler: scheduler,
		engine:    engine,
	}
}

// Start launches the background scheduler
func (s *Service) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancelFn = cancel
	go s.scheduler.Start(ctx)
	s.logger.Info("Directory service started")
	return nil
}

// Stop halts the scheduler
func (s *Service) Stop() {
	if s.cancelFn != nil {
		s.cancelFn()
	}
	s.scheduler.Stop()
	s.logger.Info("Directory service stopped")
}

// TestConnection tests LDAP connectivity for a given config
func (s *Service) TestConnection(ctx context.Context, cfg LDAPConfig) error {
	connector := NewLDAPConnector(cfg, s.logger)
	return connector.TestConnection()
}

// TriggerSync manually starts a sync for a directory
func (s *Service) TriggerSync(ctx context.Context, directoryID string, fullSync bool) error {
	return s.scheduler.TriggerSync(ctx, directoryID, fullSync)
}

// AuthenticateUser authenticates a user against their directory's LDAP
func (s *Service) AuthenticateUser(ctx context.Context, directoryID, username, password string) error {
	cfg, err := s.loadDirectoryConfig(ctx, directoryID)
	if err != nil {
		return err
	}
	connector := NewLDAPConnector(*cfg, s.logger)
	return connector.AuthenticateUser(username, password)
}

// ChangePassword changes a user's password in their directory (user-initiated, requires old password)
func (s *Service) ChangePassword(ctx context.Context, directoryID, username, oldPassword, newPassword string) error {
	cfg, err := s.loadDirectoryConfig(ctx, directoryID)
	if err != nil {
		return err
	}
	connector := NewLDAPConnector(*cfg, s.logger)
	return connector.ChangePassword(username, oldPassword, newPassword)
}

// ResetPassword resets a user's password in their directory (admin-initiated, no old password needed)
func (s *Service) ResetPassword(ctx context.Context, directoryID, username, newPassword string) error {
	cfg, err := s.loadDirectoryConfig(ctx, directoryID)
	if err != nil {
		return err
	}
	connector := NewLDAPConnector(*cfg, s.logger)
	return connector.ResetPassword(username, newPassword)
}

// loadDirectoryConfig loads and parses the LDAP config for a directory integration
func (s *Service) loadDirectoryConfig(ctx context.Context, directoryID string) (*LDAPConfig, error) {
	var configBytes []byte
	err := s.db.Pool.QueryRow(ctx,
		`SELECT config FROM directory_integrations WHERE id = $1 AND enabled = true`,
		directoryID).Scan(&configBytes)
	if err != nil {
		return nil, fmt.Errorf("directory not found or disabled: %w", err)
	}

	var cfg LDAPConfig
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		return nil, fmt.Errorf("invalid directory config: %w", err)
	}
	return &cfg, nil
}

// GetSyncLogs returns recent sync logs for a directory
func (s *Service) GetSyncLogs(ctx context.Context, directoryID string, limit int) ([]SyncLog, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, directory_id, sync_type, status, started_at, completed_at,
		        users_added, users_updated, users_disabled, groups_added, groups_updated, groups_deleted, error_message
		 FROM directory_sync_logs
		 WHERE directory_id = $1
		 ORDER BY started_at DESC
		 LIMIT $2`, directoryID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []SyncLog
	for rows.Next() {
		var l SyncLog
		if err := rows.Scan(&l.ID, &l.DirectoryID, &l.SyncType, &l.Status, &l.StartedAt, &l.CompletedAt,
			&l.UsersAdded, &l.UsersUpdated, &l.UsersDisabled, &l.GroupsAdded, &l.GroupsUpdated, &l.GroupsDeleted, &l.ErrorMessage); err != nil {
			continue
		}
		logs = append(logs, l)
	}

	if logs == nil {
		logs = []SyncLog{}
	}
	return logs, nil
}

// GetSyncState returns the current sync state for a directory
func (s *Service) GetSyncState(ctx context.Context, directoryID string) (*SyncState, error) {
	var state SyncState
	state.DirectoryID = directoryID

	err := s.db.Pool.QueryRow(ctx,
		`SELECT last_sync_at, last_usn_changed, last_modify_timestamp, users_synced, groups_synced, errors_count, sync_duration_ms
		 FROM directory_sync_state WHERE directory_id = $1`, directoryID).Scan(
		&state.LastSyncAt, &state.LastUSNChanged, &state.LastModifyTimestamp,
		&state.UsersSynced, &state.GroupsSynced, &state.ErrorsCount, &state.SyncDurationMs)
	if err != nil {
		// No sync state yet — return empty
		return &state, nil
	}

	return &state, nil
}
