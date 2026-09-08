package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/openidx/openidx/internal/common/database"
)

// SyncEngine performs directory synchronization
type SyncEngine struct {
	db     *database.PostgresDB
	logger *zap.Logger
}

// NewSyncEngine creates a new sync engine
func NewSyncEngine(db *database.PostgresDB, logger *zap.Logger) *SyncEngine {
	return &SyncEngine{
		db:     db,
		logger: logger.With(zap.String("component", "sync-engine")),
	}
}

// replaceDirectoryMemberships makes a group's directory-managed membership
// match what the directory just said, atomically.
//
// It replaces two unchecked statements that both LDAP and Entra ID sync ran per
// group: a DELETE of the directory-managed rows, then an INSERT per current
// member. Neither error was looked at, and the pair was not a transaction, so
// three things could go wrong and none of them was reported:
//
//   - The DELETE fails and the INSERTs succeed. A membership the directory
//     REMOVED survives, and the sync goes on to report success. That is
//     deprovisioning that did not happen, on the schedule an operator relies on
//     to take access away when somebody leaves a team.
//   - The DELETE succeeds and an INSERT fails. Access the directory still
//     grants is dropped. Safe, but wrong, and equally silent.
//   - Between the two, the group is empty. A membership check landing in that
//     window is answered no for a user who has the access.
//
// One transaction closes all three: the old rows and the new ones move
// together, and a failure leaves the previous membership exactly as it was for
// the caller to report.
func (e *SyncEngine) replaceDirectoryMemberships(ctx context.Context, groupID, directoryID, orgID string, memberUserIDs []string) error {
	tx, err := e.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`DELETE FROM group_memberships WHERE group_id = $1 AND org_id = $3 AND user_id IN (
			SELECT id FROM users WHERE directory_id = $2 AND org_id = $3
		)`, groupID, directoryID, orgID); err != nil {
		return fmt.Errorf("clear the directory-managed members: %w", err)
	}

	for _, userID := range memberUserIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			userID, groupID, orgID); err != nil {
			return fmt.Errorf("add the current members: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// record runs one of the sync's bookkeeping writes and says what is lost when
// it does not land.
//
// None of these statements changes anybody's access, which is why they were
// written unchecked. But each of them is the only thing that tells somebody --
// an operator reading the console, or the scheduler deciding when to run again
// -- what this run did. A sync whose bookkeeping is lost is a sync that
// happened and left no trace, and the four Execs here used to lose it in
// silence.
func (e *SyncEngine) record(ctx context.Context, what, sql string, args ...any) error {
	if _, err := e.db.Pool.Exec(ctx, sql, args...); err != nil {
		e.logger.Error("a directory sync could not write down part of what it did",
			zap.String("not_recorded", what), zap.Error(err))
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

// RunSync executes a directory sync (full or incremental)
func (e *SyncEngine) RunSync(ctx context.Context, directoryID string, dirType string, configBytes []byte, fullSync bool) (*SyncResult, error) {
	start := time.Now()
	result := &SyncResult{}

	// A directory integration belongs to one org; the whole sync run
	// writes that org's tenant data. Resolve it once from the
	// integration and thread it through so every write is org-scoped
	// (this is a background job, so there is no request/orgctx).
	var orgID string
	if err := e.db.Pool.QueryRow(ctx,
		`SELECT org_id FROM directory_integrations WHERE id = $1`, directoryID).Scan(&orgID); err != nil {
		return nil, fmt.Errorf("failed to resolve directory org: %w", err)
	}

	syncType := "incremental"
	if fullSync {
		syncType = "full"
	}

	var logID string
	err := e.db.Pool.QueryRow(ctx,
		`INSERT INTO directory_sync_logs (directory_id, sync_type, status, started_at, org_id)
		 VALUES ($1, $2, 'running', $3, $4) RETURNING id`,
		directoryID, syncType, start, orgID).Scan(&logID)
	if err != nil {
		return nil, fmt.Errorf("failed to create sync log: %w", err)
	}

	// unrecorded collects the bookkeeping this run could not write down. The
	// sync's own outcome takes precedence over it -- a failure to record a
	// success must never be reported as a failed sync -- but it is not
	// swallowed either: with every one of these lost, a run that moved a
	// thousand accounts is indistinguishable from one that never started.
	var unrecorded []string
	if err := e.record(ctx,
		"that the sync had started",
		`UPDATE directory_integrations SET sync_status = 'syncing', updated_at = NOW() WHERE id = $1 AND org_id = $2`,
		directoryID, orgID); err != nil {
		unrecorded = append(unrecorded, err.Error())
	}

	syncErr := e.doSync(ctx, directoryID, orgID, dirType, configBytes, fullSync, result)

	result.Duration = time.Since(start)
	status := "success"
	var errMsg *string
	if syncErr != nil {
		status = "failed"
		msg := syncErr.Error()
		errMsg = &msg
	} else if len(result.Errors) > 0 {
		status = "partial"
		msg := strings.Join(result.Errors, "; ")
		errMsg = &msg
	}

	now := time.Now()

	// The log row was created 'running' and this is the only statement that
	// ever takes it out of that state, so losing it leaves a finished run
	// showing as in progress for ever -- and error_message is the only place a
	// failed sync's reason is kept, so the sync history shows a run that is
	// still going and never says what went wrong with it.
	if err := e.record(ctx,
		"the outcome of the run",
		`UPDATE directory_sync_logs
		 SET status = $2, completed_at = $3, users_added = $4, users_updated = $5, users_disabled = $6,
		     groups_added = $7, groups_updated = $8, groups_deleted = $9, error_message = $10
		 WHERE id = $1 AND org_id = $11`,
		logID, status, now, result.UsersAdded, result.UsersUpdated, result.UsersDisabled,
		result.GroupsAdded, result.GroupsUpdated, result.GroupsDeleted, errMsg, orgID); err != nil {
		unrecorded = append(unrecorded, err.Error())
	}

	// last_sync_at is not a display value: Scheduler.checkAndRunSyncs reads it
	// to decide whether a sync is due, and a NULL there means "never synced"
	// -- which schedules a FULL sync. So losing this write does not merely
	// leave the console stale; it makes the scheduler run a full directory
	// sync on every 60-second tick, for ever, against the customer's LDAP or
	// Graph tenant, with nothing anywhere saying why.
	durationMs := int(result.Duration.Milliseconds())
	if err := e.record(ctx,
		"when the directory was last synced",
		`INSERT INTO directory_sync_state (directory_id, last_sync_at, users_synced, groups_synced, errors_count, sync_duration_ms, updated_at, org_id)
		 VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)
		 ON CONFLICT (directory_id) DO UPDATE SET
		     last_sync_at = $2, users_synced = $3, groups_synced = $4, errors_count = $5, sync_duration_ms = $6, updated_at = NOW()`,
		directoryID, now,
		result.UsersAdded+result.UsersUpdated,
		result.GroupsAdded+result.GroupsUpdated,
		len(result.Errors), durationMs, orgID); err != nil {
		unrecorded = append(unrecorded, err.Error())
	}

	// The integration's own status. Nothing else moves it out of 'syncing',
	// so a lost write here is the directories page showing a sync in progress
	// that finished hours ago -- and, when the sync failed, hiding that it
	// failed at all.
	dirStatus := "synced"
	if syncErr != nil {
		dirStatus = "failed"
	}
	if err := e.record(ctx,
		"the directory's sync status",
		`UPDATE directory_integrations SET sync_status = $2, last_sync_at = $3, updated_at = NOW() WHERE id = $1 AND org_id = $4`,
		directoryID, dirStatus, now, orgID); err != nil {
		unrecorded = append(unrecorded, err.Error())
	}

	// The sync's own failure comes first: it is the more serious of the two,
	// and reporting a bookkeeping failure in its place would hide it.
	if syncErr != nil {
		return result, syncErr
	}

	if len(unrecorded) > 0 {
		return result, fmt.Errorf(
			"the directory sync itself completed, but its outcome was not recorded (%s); "+
				"the console and the sync schedule are now wrong about this directory",
			strings.Join(unrecorded, "; "))
	}

	e.logger.Info("Directory sync completed",
		zap.String("directory_id", directoryID),
		zap.String("type", syncType),
		zap.String("dir_type", dirType),
		zap.Int("users_added", result.UsersAdded),
		zap.Int("users_updated", result.UsersUpdated),
		zap.Int("users_disabled", result.UsersDisabled),
		zap.Int("groups_added", result.GroupsAdded),
		zap.Duration("duration", result.Duration),
	)

	return result, nil
}

func (e *SyncEngine) doSync(ctx context.Context, directoryID, orgID, dirType string, configBytes []byte, fullSync bool, result *SyncResult) error {
	switch dirType {
	case "ldap", "active_directory":
		var cfg LDAPConfig
		if err := json.Unmarshal(configBytes, &cfg); err != nil {
			return fmt.Errorf("invalid LDAP config: %w", err)
		}
		return e.doSyncLDAP(ctx, directoryID, orgID, cfg, fullSync, result)
	case "azure_ad":
		var cfg AzureADConfig
		if err := json.Unmarshal(configBytes, &cfg); err != nil {
			return fmt.Errorf("invalid Azure AD config: %w", err)
		}
		return e.doSyncAzureAD(ctx, directoryID, orgID, cfg, fullSync, result)
	case "hris", "bamboohr":
		var cfg HRISConfig
		if err := json.Unmarshal(configBytes, &cfg); err != nil {
			return fmt.Errorf("invalid HRIS config: %w", err)
		}
		return e.doSyncHRIS(ctx, directoryID, orgID, cfg, fullSync, result)
	default:
		return fmt.Errorf("unsupported directory type: %s", dirType)
	}
}

func (e *SyncEngine) doSyncLDAP(ctx context.Context, directoryID, orgID string, cfg LDAPConfig, fullSync bool, result *SyncResult) error {
	connector := NewLDAPConnector(cfg, e.logger)

	// Sync users
	if err := e.syncUsers(ctx, connector, directoryID, orgID, cfg, fullSync, result); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("user sync error: %v", err))
	}

	// Sync groups
	if err := e.syncGroups(ctx, connector, directoryID, orgID, cfg, result); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("group sync error: %v", err))
	}

	// Sync group memberships
	if err := e.syncMemberships(ctx, connector, directoryID, orgID, cfg); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("membership sync error: %v", err))
	}

	return nil
}

func (e *SyncEngine) doSyncAzureAD(ctx context.Context, directoryID, orgID string, cfg AzureADConfig, fullSync bool, result *SyncResult) error {
	connector := NewAzureADConnector(cfg, e.logger)
	if err := connector.ensureToken(ctx); err != nil {
		return fmt.Errorf("failed to acquire Azure AD token: %w", err)
	}

	// Sync users
	if err := e.syncAzureADUsers(ctx, connector, directoryID, orgID, cfg, fullSync, result); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("user sync error: %v", err))
	}

	// Sync groups
	if err := e.syncAzureADGroups(ctx, connector, directoryID, orgID, result); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("group sync error: %v", err))
	}

	// Sync memberships
	if err := e.syncAzureADMemberships(ctx, connector, directoryID, orgID); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("membership sync error: %v", err))
	}

	return nil
}

type dbUser struct {
	ID        string
	Username  string
	Email     string
	FirstName string
	LastName  string
	LdapDN    string
	Enabled   bool
}

func (e *SyncEngine) syncUsers(ctx context.Context, connector *LDAPConnector, directoryID, orgID string, cfg LDAPConfig, fullSync bool, result *SyncResult) error {
	conn, err := connector.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	var records []UserRecord

	if fullSync {
		entries, err := connector.SearchUsers(conn)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			records = append(records, MapUserEntry(entry, cfg.AttributeMapping))
		}
	} else {
		var lastUSN int64
		var lastTimestamp *string
		e.db.Pool.QueryRow(ctx,
			`SELECT last_usn_changed, last_modify_timestamp FROM directory_sync_state WHERE directory_id = $1 AND org_id = $2`,
			directoryID, orgID).Scan(&lastUSN, &lastTimestamp)

		ts := ""
		if lastTimestamp != nil {
			ts = *lastTimestamp
		}
		entries, err := connector.SearchUsersIncremental(conn, lastUSN, ts)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			records = append(records, MapUserEntry(entry, cfg.AttributeMapping))
		}
	}

	// Build map of existing DB users for this directory
	dbUsers := make(map[string]dbUser)
	rows, err := e.db.Pool.Query(ctx,
		`SELECT id, username, email, first_name, last_name, ldap_dn, enabled
		 FROM users WHERE directory_id = $1 AND org_id = $2`, directoryID, orgID)
	if err != nil {
		return fmt.Errorf("failed to query existing users: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var u dbUser
		var dn *string
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.FirstName, &u.LastName, &dn, &u.Enabled); err != nil {
			continue
		}
		if dn != nil {
			u.LdapDN = *dn
			dbUsers[*dn] = u
		}
	}

	// Process records
	ldapDNs := make(map[string]bool)
	for _, record := range records {
		if record.Username == "" || record.Email == "" {
			continue
		}
		ldapDNs[record.DN] = true

		existing, found := dbUsers[record.DN]
		if found {
			if existing.Username != record.Username || existing.Email != record.Email ||
				existing.FirstName != record.FirstName || existing.LastName != record.LastName {
				_, err := e.db.Pool.Exec(ctx,
					`UPDATE users SET username = $2, email = $3, first_name = $4, last_name = $5, updated_at = NOW()
					 WHERE id = $1 AND org_id = $6`,
					existing.ID, record.Username, record.Email, record.FirstName, record.LastName, orgID)
				if err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("failed to update user %s: %v", record.Username, err))
				} else {
					result.UsersUpdated++
				}
			}
		} else {
			// Create new LDAP user with an unusable password
			randomPwd := fmt.Sprintf("ldap-nologin-%d", time.Now().UnixNano())
			hash, _ := bcrypt.GenerateFromPassword([]byte(randomPwd), bcrypt.DefaultCost)

			_, err := e.db.Pool.Exec(ctx,
				`INSERT INTO users (username, email, first_name, last_name, password_hash, enabled, email_verified, source, directory_id, ldap_dn, org_id)
				 VALUES ($1, $2, $3, $4, $5, true, true, 'ldap', $6, $7, $8)
				 ON CONFLICT (username) DO NOTHING`,
				record.Username, record.Email, record.FirstName, record.LastName, string(hash), directoryID, record.DN, orgID)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("failed to create user %s: %v", record.Username, err))
			} else {
				result.UsersAdded++
			}
		}
	}

	// Deprovision: users in DB but not in LDAP (only for full sync)
	if fullSync {
		deprovisionCount := 0
		for dn, user := range dbUsers {
			if !ldapDNs[dn] && user.Enabled {
				deprovisionCount++
			}
		}

		totalLdap := len(records)
		if totalLdap > 0 && deprovisionCount > 0 {
			pct := float64(deprovisionCount) / float64(totalLdap+deprovisionCount) * 100
			if pct > 25 {
				e.logger.Warn("High deprovision rate detected",
					zap.Float64("percent", pct),
					zap.Int("count", deprovisionCount),
				)
				result.Errors = append(result.Errors, fmt.Sprintf("high deprovision rate: %.0f%% (%d users)", pct, deprovisionCount))
			}
		}

		for dn, user := range dbUsers {
			if !ldapDNs[dn] && user.Enabled {
				action := cfg.DeprovisionAction
				if action == "" {
					action = "disable"
				}

				if action == "delete" {
					if _, err := e.db.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1 AND org_id = $2`, user.ID, orgID); err != nil {
						result.Errors = append(result.Errors, fmt.Sprintf("failed to delete user %s: %v", user.Username, err))
					} else {
						result.UsersDisabled++
					}
				} else {
					if _, err := e.db.Pool.Exec(ctx, `UPDATE users SET enabled = false, updated_at = NOW() WHERE id = $1 AND org_id = $2`, user.ID, orgID); err != nil {
						result.Errors = append(result.Errors, fmt.Sprintf("failed to disable user %s: %v", user.Username, err))
					} else {
						result.UsersDisabled++
					}
				}
			}
		}
	}

	return nil
}

func (e *SyncEngine) syncGroups(ctx context.Context, connector *LDAPConnector, directoryID, orgID string, cfg LDAPConfig, result *SyncResult) error {
	conn, err := connector.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	entries, err := connector.SearchGroups(conn)
	if err != nil {
		return err
	}

	memberAttr := cfg.MemberAttribute
	if memberAttr == "" {
		memberAttr = "member"
	}

	// Existing groups
	dbGroups := make(map[string]string) // ldap_dn -> id
	rows, err := e.db.Pool.Query(ctx,
		`SELECT id, ldap_dn FROM groups WHERE directory_id = $1 AND org_id = $2`, directoryID, orgID)
	if err != nil {
		return fmt.Errorf("failed to query existing groups: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id string
		var dn *string
		if err := rows.Scan(&id, &dn); err != nil {
			continue
		}
		if dn != nil {
			dbGroups[*dn] = id
		}
	}

	ldapDNs := make(map[string]bool)
	for _, entry := range entries {
		record := MapGroupEntry(entry, cfg.AttributeMapping, memberAttr)
		if record.Name == "" {
			continue
		}
		ldapDNs[record.DN] = true

		if _, found := dbGroups[record.DN]; found {
			_, err := e.db.Pool.Exec(ctx,
				`UPDATE groups SET name = $2, description = $3, updated_at = NOW() WHERE ldap_dn = $1 AND directory_id = $4 AND org_id = $5`,
				record.DN, record.Name, record.Description, directoryID, orgID)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("failed to update group %s: %v", record.Name, err))
			} else {
				result.GroupsUpdated++
			}
		} else {
			_, err := e.db.Pool.Exec(ctx,
				`INSERT INTO groups (name, description, source, directory_id, ldap_dn, external_id, org_id)
				 VALUES ($1, $2, 'ldap', $3, $4, $5, $6)
				 ON CONFLICT (org_id, name) DO NOTHING`,
				record.Name, record.Description, directoryID, record.DN, record.DN, orgID)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("failed to create group %s: %v", record.Name, err))
			} else {
				result.GroupsAdded++
			}
		}
	}

	for dn, id := range dbGroups {
		if !ldapDNs[dn] {
			if _, err := e.db.Pool.Exec(ctx, `DELETE FROM groups WHERE id = $1 AND org_id = $2`, id, orgID); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("failed to delete group: %v", err))
			} else {
				result.GroupsDeleted++
			}
		}
	}

	return nil
}

func (e *SyncEngine) syncMemberships(ctx context.Context, connector *LDAPConnector, directoryID, orgID string, cfg LDAPConfig) error {
	// Re-fetch groups from LDAP to get member DNs
	conn, err := connector.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	entries, err := connector.SearchGroups(conn)
	if err != nil {
		return err
	}

	memberAttr := cfg.MemberAttribute
	if memberAttr == "" {
		memberAttr = "member"
	}

	// Build user DN -> ID map
	userDNMap := make(map[string]string)
	uRows, err := e.db.Pool.Query(ctx,
		`SELECT id, ldap_dn FROM users WHERE directory_id = $1 AND org_id = $2 AND ldap_dn IS NOT NULL`, directoryID, orgID)
	if err != nil {
		return err
	}
	defer uRows.Close()
	for uRows.Next() {
		var id string
		var dn *string
		if err := uRows.Scan(&id, &dn); err == nil && dn != nil {
			userDNMap[*dn] = id
		}
	}

	// Build group DN -> ID map
	groupDNMap := make(map[string]string)
	gRows, err := e.db.Pool.Query(ctx,
		`SELECT id, ldap_dn FROM groups WHERE directory_id = $1 AND org_id = $2 AND ldap_dn IS NOT NULL`, directoryID, orgID)
	if err != nil {
		return err
	}
	defer gRows.Close()
	for gRows.Next() {
		var id string
		var dn *string
		if err := gRows.Scan(&id, &dn); err == nil && dn != nil {
			groupDNMap[*dn] = id
		}
	}

	var failed []string
	for _, entry := range entries {
		record := MapGroupEntry(entry, cfg.AttributeMapping, memberAttr)
		groupID, ok := groupDNMap[record.DN]
		if !ok {
			continue
		}

		members := make([]string, 0, len(record.MemberDNs))
		for _, memberDN := range record.MemberDNs {
			if userID, found := userDNMap[memberDN]; found {
				members = append(members, userID)
			}
		}
		if err := e.replaceDirectoryMemberships(ctx, groupID, directoryID, orgID, members); err != nil {
			e.logger.Error("could not apply the directory's membership for a group; its previous membership stands",
				zap.String("group_id", groupID), zap.Error(err))
			failed = append(failed, groupID)
		}
	}

	if len(failed) > 0 {
		return fmt.Errorf("%d group(s) kept the membership they had because the directory's could not be applied: %v",
			len(failed), failed)
	}
	return nil
}

// Azure AD sync helpers

type dbAzureUser struct {
	ID         string
	Username   string
	Email      string
	FirstName  string
	LastName   string
	ExternalID string
	Enabled    bool
}

func (e *SyncEngine) syncAzureADUsers(ctx context.Context, connector *AzureADConnector, directoryID, orgID string, cfg AzureADConfig, fullSync bool, result *SyncResult) error {
	var records []UserRecord
	var newDeltaLink string

	if fullSync {
		users, err := connector.SearchUsers(ctx)
		if err != nil {
			return err
		}
		records = users
	} else {
		// Incremental sync using delta query
		var deltaLink *string
		e.db.Pool.QueryRow(ctx,
			`SELECT last_delta_link FROM directory_sync_state WHERE directory_id = $1 AND org_id = $2`,
			directoryID, orgID).Scan(&deltaLink)

		dl := ""
		if deltaLink != nil {
			dl = *deltaLink
		}
		users, dlNext, err := connector.SearchUsersIncremental(ctx, dl)
		if err != nil {
			return err
		}
		records = users
		newDeltaLink = dlNext
	}

	// Everything below appends to result.Errors rather than returning, so this
	// is where the delta link's fate is decided: see the end of the function.
	errorsBefore := len(result.Errors)

	// Build map of existing DB users for this directory (keyed by external_id)
	dbUsers := make(map[string]dbAzureUser)
	rows, err := e.db.Pool.Query(ctx,
		`SELECT id, username, email, first_name, last_name, COALESCE(external_id, ''), enabled
		 FROM users WHERE directory_id = $1 AND org_id = $2`, directoryID, orgID)
	if err != nil {
		return fmt.Errorf("failed to query existing users: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var u dbAzureUser
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.FirstName, &u.LastName, &u.ExternalID, &u.Enabled); err != nil {
			continue
		}
		if u.ExternalID != "" {
			dbUsers[u.ExternalID] = u
		}
	}

	// Process records
	seenIDs := make(map[string]bool)
	for _, record := range records {
		if record.Username == "" || record.Email == "" {
			continue
		}
		seenIDs[record.ExternalID] = true

		existing, found := dbUsers[record.ExternalID]
		if found {
			if existing.Username != record.Username || existing.Email != record.Email ||
				existing.FirstName != record.FirstName || existing.LastName != record.LastName {
				_, err := e.db.Pool.Exec(ctx,
					`UPDATE users SET username = $2, email = $3, first_name = $4, last_name = $5, updated_at = NOW()
					 WHERE id = $1 AND org_id = $6`,
					existing.ID, record.Username, record.Email, record.FirstName, record.LastName, orgID)
				if err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("failed to update user %s: %v", record.Username, err))
				} else {
					result.UsersUpdated++
				}
			}
		} else {
			// Create new Azure AD user with an unusable password
			randomPwd := fmt.Sprintf("azuread-nologin-%d", time.Now().UnixNano())
			hash, _ := bcrypt.GenerateFromPassword([]byte(randomPwd), bcrypt.DefaultCost)

			_, err := e.db.Pool.Exec(ctx,
				`INSERT INTO users (username, email, first_name, last_name, password_hash, enabled, email_verified, source, directory_id, external_id, org_id)
				 VALUES ($1, $2, $3, $4, $5, true, true, 'azure_ad', $6, $7, $8)
				 ON CONFLICT (username) DO NOTHING`,
				record.Username, record.Email, record.FirstName, record.LastName, string(hash), directoryID, record.ExternalID, orgID)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("failed to create user %s: %v", record.Username, err))
			} else {
				result.UsersAdded++
			}
		}
	}

	// Deprovision: users in DB but not in Azure AD (only for full sync)
	if fullSync {
		for extID, user := range dbUsers {
			if !seenIDs[extID] && user.Enabled {
				action := cfg.DeprovisionAction
				if action == "" {
					action = "disable"
				}
				if action == "delete" {
					if _, err := e.db.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1 AND org_id = $2`, user.ID, orgID); err != nil {
						result.Errors = append(result.Errors, fmt.Sprintf("failed to delete user %s: %v", user.Username, err))
					} else {
						result.UsersDisabled++
					}
				} else {
					if _, err := e.db.Pool.Exec(ctx, `UPDATE users SET enabled = false, updated_at = NOW() WHERE id = $1 AND org_id = $2`, user.ID, orgID); err != nil {
						result.Errors = append(result.Errors, fmt.Sprintf("failed to disable user %s: %v", user.Username, err))
					} else {
						result.UsersDisabled++
					}
				}
			}
		}
	}

	// The delta link is a cursor, and it used to be stored the moment Graph
	// handed it over -- before a single one of the records it covers had been
	// applied. A delta query returns only what has changed since the token was
	// issued, so storing it means never being offered those records again: a
	// user whose UPDATE the database refused was stepped over permanently, and
	// the sync went on to report itself partial without ever saying that the
	// change had been lost rather than deferred.
	//
	// It is now stored last, and only when every record landed. Holding it
	// costs one repeated page on the next run -- the writes are upserts keyed
	// on external_id, so re-applying them is free -- and that is the cheaper
	// side of the trade by a wide margin.
	e.storeDeltaLink(ctx, directoryID, orgID, newDeltaLink, len(result.Errors)-errorsBefore, result)

	return nil
}

// storeDeltaLink advances the Azure AD delta cursor, or deliberately does not.
//
// unapplied is how many of the records this page carried could not be written.
// While it is non-zero the cursor is held where it is: Graph will offer those
// records again on the next run, which is the only way they are ever seen
// again. Advancing past them is permanent.
func (e *SyncEngine) storeDeltaLink(ctx context.Context, directoryID, orgID, deltaLink string, unapplied int, result *SyncResult) {
	if deltaLink == "" {
		return
	}
	if unapplied > 0 {
		e.logger.Warn("holding the Azure AD delta cursor: records in this page were not applied, "+
			"so advancing it would skip them for good; the next sync re-fetches from the previous cursor",
			zap.String("directory_id", directoryID),
			zap.Int("records_not_applied", unapplied))
		return
	}
	// An upsert, not an UPDATE. On a directory's first incremental sync there
	// is no state row yet -- RunSync creates it after doSync returns -- so the
	// old UPDATE matched nothing and stored no cursor at all, without saying
	// so, and that run's delta token was thrown away.
	if err := e.record(ctx,
		"the Azure AD delta cursor",
		`INSERT INTO directory_sync_state (directory_id, last_delta_link, updated_at, org_id)
		 VALUES ($1, $2, NOW(), $3)
		 ON CONFLICT (directory_id) DO UPDATE SET last_delta_link = $2, updated_at = NOW()`,
		directoryID, deltaLink, orgID); err != nil {
		result.Errors = append(result.Errors, err.Error())
	}
}

func (e *SyncEngine) syncAzureADGroups(ctx context.Context, connector *AzureADConnector, directoryID, orgID string, result *SyncResult) error {
	groups, err := connector.SearchGroups(ctx)
	if err != nil {
		return err
	}

	// Existing groups keyed by external_id
	dbGroups := make(map[string]string) // external_id -> id
	rows, err := e.db.Pool.Query(ctx,
		`SELECT id, COALESCE(external_id, '') FROM groups WHERE directory_id = $1 AND org_id = $2`, directoryID, orgID)
	if err != nil {
		return fmt.Errorf("failed to query existing groups: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id, extID string
		if err := rows.Scan(&id, &extID); err != nil {
			continue
		}
		if extID != "" {
			dbGroups[extID] = id
		}
	}

	seenIDs := make(map[string]bool)
	for _, group := range groups {
		if group.Name == "" {
			continue
		}
		seenIDs[group.DN] = true // DN is the Azure objectId

		if _, found := dbGroups[group.DN]; found {
			_, err := e.db.Pool.Exec(ctx,
				`UPDATE groups SET name = $2, description = $3, updated_at = NOW() WHERE external_id = $1 AND directory_id = $4 AND org_id = $5`,
				group.DN, group.Name, group.Description, directoryID, orgID)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("failed to update group %s: %v", group.Name, err))
			} else {
				result.GroupsUpdated++
			}
		} else {
			_, err := e.db.Pool.Exec(ctx,
				`INSERT INTO groups (name, description, source, directory_id, external_id, org_id)
				 VALUES ($1, $2, 'azure_ad', $3, $4, $5)
				 ON CONFLICT (org_id, name) DO NOTHING`,
				group.Name, group.Description, directoryID, group.DN, orgID)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("failed to create group %s: %v", group.Name, err))
			} else {
				result.GroupsAdded++
			}
		}
	}

	// Delete groups that no longer exist in Azure AD
	for extID, id := range dbGroups {
		if !seenIDs[extID] {
			if _, err := e.db.Pool.Exec(ctx, `DELETE FROM groups WHERE id = $1 AND org_id = $2`, id, orgID); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("failed to delete group: %v", err))
			} else {
				result.GroupsDeleted++
			}
		}
	}

	return nil
}

func (e *SyncEngine) syncAzureADMemberships(ctx context.Context, connector *AzureADConnector, directoryID, orgID string) error {
	// Build user external_id -> ID map
	userExtMap := make(map[string]string)
	uRows, err := e.db.Pool.Query(ctx,
		`SELECT id, external_id FROM users WHERE directory_id = $1 AND org_id = $2 AND external_id IS NOT NULL`, directoryID, orgID)
	if err != nil {
		return err
	}
	defer uRows.Close()
	for uRows.Next() {
		var id string
		var extID *string
		if err := uRows.Scan(&id, &extID); err == nil && extID != nil {
			userExtMap[*extID] = id
		}
	}

	// Build group external_id -> ID map
	groupExtMap := make(map[string]string)
	gRows, err := e.db.Pool.Query(ctx,
		`SELECT id, external_id FROM groups WHERE directory_id = $1 AND org_id = $2 AND external_id IS NOT NULL`, directoryID, orgID)
	if err != nil {
		return err
	}
	defer gRows.Close()
	for gRows.Next() {
		var id string
		var extID *string
		if err := gRows.Scan(&id, &extID); err == nil && extID != nil {
			groupExtMap[*extID] = id
		}
	}

	var failed []string
	// For each group, fetch members from Azure AD and sync
	for azureGroupID, groupID := range groupExtMap {
		memberIDs, err := connector.SearchGroupMembers(ctx, azureGroupID)
		if err != nil {
			e.logger.Warn("Failed to fetch Azure AD group members",
				zap.String("group_id", azureGroupID), zap.Error(err))
			continue
		}

		members := make([]string, 0, len(memberIDs))
		for _, memberAzureID := range memberIDs {
			if userID, found := userExtMap[memberAzureID]; found {
				members = append(members, userID)
			}
		}
		if err := e.replaceDirectoryMemberships(ctx, groupID, directoryID, orgID, members); err != nil {
			e.logger.Error("could not apply the directory's membership for a group; its previous membership stands",
				zap.String("group_id", groupID), zap.Error(err))
			failed = append(failed, groupID)
		}
	}

	if len(failed) > 0 {
		return fmt.Errorf("%d group(s) kept the membership they had because the directory's could not be applied: %v",
			len(failed), failed)
	}
	return nil
}
