package access

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// SyncResult represents the result of syncing a single user to Ziti.
type SyncResult struct {
	UserID     string   `json:"user_id"`
	ZitiID     string   `json:"ziti_id"`
	Created    bool     `json:"created"`
	Attributes []string `json:"attributes"`
	Error      string   `json:"error,omitempty"`
}

// BatchSyncResult represents the result of a batch sync operation.
type BatchSyncResult struct {
	UsersSynced  int `json:"users_synced"`
	UsersFailed  int `json:"users_failed"`
	GroupsSynced int `json:"groups_synced"`
}

// SyncStatus represents the current state of user-to-Ziti sync.
type SyncStatus struct {
	Status          string     `json:"status"`
	LastFullSyncAt  *time.Time `json:"last_full_sync_at,omitempty"`
	LastAutoSyncAt  *time.Time `json:"last_auto_sync_at,omitempty"`
	UsersSynced     int        `json:"users_synced"`
	UsersFailed     int        `json:"users_failed"`
	GroupsSynced    int        `json:"groups_synced"`
	UnsyncedUsers   int        `json:"unsynced_users"`
	TotalUsers      int        `json:"total_users"`
	TotalIdentities int        `json:"total_identities"`
}

// getUserGroupNames returns the names of all groups a user belongs to.
func (zm *ZitiManager) getUserGroupNames(ctx context.Context, userID string) ([]string, error) {
	rows, err := zm.db.Pool.Query(ctx,
		`SELECT g.name FROM groups g
		 JOIN group_memberships gm ON gm.group_id = g.id
		 WHERE gm.user_id = $1
		 ORDER BY g.name`, userID)
	if err != nil {
		return nil, fmt.Errorf("query group memberships: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		names = append(names, name)
	}
	return names, nil
}

// SyncUserToZiti creates a Ziti identity for a user if one doesn't exist,
// and syncs their group memberships as role attributes.
func (zm *ZitiManager) SyncUserToZiti(ctx context.Context, userID string) (*SyncResult, error) {
	// Check if user already has a Ziti identity
	var existingID string
	err := zm.db.Pool.QueryRow(ctx,
		`SELECT id FROM ziti_identities WHERE user_id = $1`, userID).Scan(&existingID)
	if err == nil {
		// Already has identity — just sync group attributes
		if syncErr := zm.SyncGroupAttributesForUser(ctx, userID); syncErr != nil {
			return &SyncResult{UserID: userID, Created: false, Error: syncErr.Error()}, syncErr
		}
		return &SyncResult{UserID: userID, Created: false}, nil
	}

	// Fetch user info to verify user exists
	var username string
	err = zm.db.Pool.QueryRow(ctx,
		`SELECT username FROM users WHERE id = $1 AND enabled = true`, userID).Scan(&username)
	if err != nil {
		return nil, fmt.Errorf("user %s not found or disabled: %w", userID, err)
	}

	// Get group names for initial role attributes
	attrs, err := zm.getUserGroupNames(ctx, userID)
	if err != nil {
		zm.logger.Warn("Failed to get group names for user", zap.String("user_id", userID), zap.Error(err))
		attrs = []string{}
	}

	// Create Ziti identity (name = userID for unique linking)
	zitiID, enrollmentJWT, err := zm.CreateIdentity(ctx, userID, "User", attrs)
	if err != nil {
		return nil, fmt.Errorf("create ziti identity for user %s: %w", userID, err)
	}

	// Persist to DB
	attrsJSON, _ := json.Marshal(attrs)
	_, err = zm.db.Pool.Exec(ctx,
		`INSERT INTO ziti_identities (ziti_id, name, identity_type, user_id, enrollment_jwt, attributes, group_attrs_synced_at)
		 VALUES ($1, $2, 'User', $3, $4, $5, NOW())`,
		zitiID, userID, userID, enrollmentJWT, attrsJSON)
	if err != nil {
		return nil, fmt.Errorf("persist ziti identity for user %s: %w", userID, err)
	}

	zm.logger.Info("Auto-synced user to Ziti identity",
		zap.String("user_id", userID),
		zap.String("username", username),
		zap.String("ziti_id", zitiID),
		zap.Strings("attributes", attrs))

	return &SyncResult{
		UserID:     userID,
		ZitiID:     zitiID,
		Created:    true,
		Attributes: attrs,
	}, nil
}

// SyncAllUsersToZiti creates Ziti identities for all users that don't have one,
// and refreshes group attributes for all linked identities.
func (zm *ZitiManager) SyncAllUsersToZiti(ctx context.Context) (*BatchSyncResult, error) {
	// Mark sync as running
	zm.db.Pool.Exec(ctx,
		`UPDATE ziti_user_sync SET status='running', updated_at=NOW()
		 WHERE id = (SELECT id FROM ziti_user_sync LIMIT 1)`)

	// Find all enabled users without Ziti identities
	rows, err := zm.db.Pool.Query(ctx,
		`SELECT u.id FROM users u
		 LEFT JOIN ziti_identities zi ON zi.user_id = u.id
		 WHERE zi.id IS NULL AND u.enabled = true`)
	if err != nil {
		zm.db.Pool.Exec(ctx,
			`UPDATE ziti_user_sync SET status='failed', updated_at=NOW()
			 WHERE id = (SELECT id FROM ziti_user_sync LIMIT 1)`)
		return nil, fmt.Errorf("query unsynced users: %w", err)
	}
	defer rows.Close()

	var userIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			userIDs = append(userIDs, id)
		}
	}

	var synced, failed int
	for _, userID := range userIDs {
		if _, err := zm.SyncUserToZiti(ctx, userID); err != nil {
			failed++
			zm.logger.Warn("Failed to sync user to Ziti", zap.String("user_id", userID), zap.Error(err))
		} else {
			synced++
		}
	}

	// Also refresh group attributes for all existing linked identities
	groupResult, _ := zm.SyncAllGroupAttributes(ctx)
	groupsSynced := 0
	if groupResult != nil {
		groupsSynced = groupResult.GroupsSynced
	}

	// Update sync status
	zm.db.Pool.Exec(ctx,
		`UPDATE ziti_user_sync SET status='completed', last_full_sync_at=NOW(),
		 users_synced=$1, users_failed=$2, groups_synced=$3, updated_at=NOW()
		 WHERE id = (SELECT id FROM ziti_user_sync LIMIT 1)`,
		synced, failed, groupsSynced)

	zm.logger.Info("Batch user sync completed",
		zap.Int("synced", synced), zap.Int("failed", failed), zap.Int("groups_synced", groupsSynced))

	return &BatchSyncResult{
		UsersSynced:  synced,
		UsersFailed:  failed,
		GroupsSynced: groupsSynced,
	}, nil
}

// SyncGroupAttributesForUser fetches the user's current group memberships
// and patches their Ziti identity's role attributes to match.
func (zm *ZitiManager) SyncGroupAttributesForUser(ctx context.Context, userID string) error {
	// Get the user's Ziti identity
	var zitiIdentityID, zitiID string
	err := zm.db.Pool.QueryRow(ctx,
		`SELECT id, ziti_id FROM ziti_identities WHERE user_id = $1`, userID).Scan(&zitiIdentityID, &zitiID)
	if err != nil {
		return fmt.Errorf("no ziti identity for user %s: %w", userID, err)
	}

	// Get current group memberships
	attrs, err := zm.getUserGroupNames(ctx, userID)
	if err != nil {
		return fmt.Errorf("get groups for user %s: %w", userID, err)
	}
	if attrs == nil {
		attrs = []string{}
	}

	// Patch Ziti controller
	if err := zm.PatchIdentityRoleAttributes(ctx, zitiID, attrs); err != nil {
		return fmt.Errorf("patch ziti identity attributes: %w", err)
	}

	// Update local DB
	attrsJSON, _ := json.Marshal(attrs)
	zm.db.Pool.Exec(ctx,
		`UPDATE ziti_identities SET attributes=$1, group_attrs_synced_at=NOW(), updated_at=NOW()
		 WHERE id=$2`, attrsJSON, zitiIdentityID)

	return nil
}

// SyncAllGroupAttributes updates role attributes for all identities linked to users.
func (zm *ZitiManager) SyncAllGroupAttributes(ctx context.Context) (*BatchSyncResult, error) {
	rows, err := zm.db.Pool.Query(ctx,
		`SELECT user_id FROM ziti_identities WHERE user_id IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("query linked identities: %w", err)
	}
	defer rows.Close()

	var synced, failed int
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			continue
		}
		if err := zm.SyncGroupAttributesForUser(ctx, userID); err != nil {
			failed++
			zm.logger.Warn("Failed to sync group attributes", zap.String("user_id", userID), zap.Error(err))
		} else {
			synced++
		}
	}

	return &BatchSyncResult{GroupsSynced: synced, UsersFailed: failed}, nil
}

// GetSyncStatus returns the current sync state with live counts.
func (zm *ZitiManager) GetSyncStatus(ctx context.Context) (*SyncStatus, error) {
	var status SyncStatus
	var lastFull, lastAuto *time.Time

	err := zm.db.Pool.QueryRow(ctx,
		`SELECT zus.status, zus.last_full_sync_at, zus.last_auto_sync_at,
		        zus.users_synced, zus.users_failed, zus.groups_synced,
		        (SELECT COUNT(*) FROM users u LEFT JOIN ziti_identities zi ON zi.user_id = u.id
		         WHERE zi.id IS NULL AND u.enabled = true),
		        (SELECT COUNT(*) FROM users WHERE enabled = true),
		        (SELECT COUNT(*) FROM ziti_identities)
		 FROM ziti_user_sync zus LIMIT 1`).Scan(
		&status.Status, &lastFull, &lastAuto,
		&status.UsersSynced, &status.UsersFailed, &status.GroupsSynced,
		&status.UnsyncedUsers, &status.TotalUsers, &status.TotalIdentities)
	if err != nil {
		// Table may not exist yet or be empty — return defaults
		return &SyncStatus{Status: "idle"}, nil
	}

	status.LastFullSyncAt = lastFull
	status.LastAutoSyncAt = lastAuto
	return &status, nil
}

// StartUserSyncPoller starts a background goroutine that periodically checks
// for users without Ziti identities and creates them.
func (zm *ZitiManager) StartUserSyncPoller(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		zm.logger.Info("Ziti user sync poller started", zap.Duration("interval", 30*time.Second))

		// Initial delay to let services stabilize
		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Second):
		}

		for {
			select {
			case <-ctx.Done():
				zm.logger.Info("Ziti user sync poller stopped")
				return
			case <-ticker.C:
				zm.runAutoSync(ctx)
			}
		}
	}()
}

// runAutoSync is called each tick to sync new users and refresh stale group attributes.
func (zm *ZitiManager) runAutoSync(ctx context.Context) {
	// Find up to 10 users without Ziti identities
	rows, err := zm.db.Pool.Query(ctx,
		`SELECT u.id FROM users u
		 LEFT JOIN ziti_identities zi ON zi.user_id = u.id
		 WHERE zi.id IS NULL AND u.enabled = true
		 LIMIT 10`)
	if err != nil {
		zm.logger.Warn("Auto-sync query failed", zap.Error(err))
		return
	}
	defer rows.Close()

	var synced int
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			continue
		}
		if _, err := zm.SyncUserToZiti(ctx, userID); err != nil {
			zm.logger.Warn("Auto-sync failed for user", zap.String("user_id", userID), zap.Error(err))
		} else {
			synced++
		}
	}

	if synced > 0 {
		zm.logger.Info("Auto-synced users to Ziti", zap.Int("count", synced))
		zm.db.Pool.Exec(ctx,
			`UPDATE ziti_user_sync SET last_auto_sync_at=NOW(), updated_at=NOW()
			 WHERE id = (SELECT id FROM ziti_user_sync LIMIT 1)`)
	}

	// Re-sync stale group attributes (older than 5 minutes)
	staleRows, err := zm.db.Pool.Query(ctx,
		`SELECT zi.user_id FROM ziti_identities zi
		 WHERE zi.user_id IS NOT NULL
		 AND (zi.group_attrs_synced_at IS NULL OR zi.group_attrs_synced_at < NOW() - INTERVAL '5 minutes')
		 LIMIT 10`)
	if err != nil {
		return
	}
	defer staleRows.Close()

	for staleRows.Next() {
		var userID string
		if err := staleRows.Scan(&userID); err != nil {
			continue
		}
		zm.SyncGroupAttributesForUser(ctx, userID)
	}
}
