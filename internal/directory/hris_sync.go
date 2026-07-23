package directory

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// This file implements HR-driven JML (Joiner/Mover/Leaver). An HRIS (BambooHR
// today) is the system of record for the employee lifecycle; a full sync
// reconciles the users table to the HR directory:
//
//   Joiner  — an employee in HR with no matching local user  -> create
//   Mover   — an employee whose HR attributes changed         -> update (title,
//             department, manager, name, status, dates)
//   Leaver  — a local HR-sourced user no longer active in HR  -> deprovision
//             (present-but-terminated, or absent from the directory)
//
// Managers are resolved in a second pass (once every user exists) by mapping
// each record's manager external id to the created/updated local user id.

// hrDBUser is the existing-user projection the JML reconcile compares against.
type hrDBUser struct {
	ID               string
	Username         string
	Email            string
	FirstName        string
	LastName         string
	JobTitle         string
	Department       string
	EmploymentStatus string
	Enabled          bool
}

func (e *SyncEngine) doSyncHRIS(ctx context.Context, directoryID, orgID string, cfg HRISConfig, fullSync bool, result *SyncResult) error {
	connector, err := newHRISConnector(cfg, e.logger)
	if err != nil {
		return err
	}

	records, err := connector.SearchUsers(ctx)
	if err != nil {
		return fmt.Errorf("HRIS directory fetch: %w", err)
	}

	// Existing HR-sourced users for this directory, keyed by external_hr_id.
	dbUsers := make(map[string]hrDBUser)
	rows, err := e.db.Pool.Query(ctx, `
		SELECT id, username, email, first_name, last_name,
		       COALESCE(external_hr_id,''), COALESCE(job_title,''), COALESCE(department,''),
		       COALESCE(employment_status,''), enabled
		  FROM users WHERE directory_id = $1 AND org_id = $2`, directoryID, orgID)
	if err != nil {
		return fmt.Errorf("failed to query existing users: %w", err)
	}
	for rows.Next() {
		var u hrDBUser
		var extHR string
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.FirstName, &u.LastName,
			&extHR, &u.JobTitle, &u.Department, &u.EmploymentStatus, &u.Enabled); err != nil {
			continue
		}
		if extHR != "" {
			dbUsers[extHR] = u
		}
	}
	rows.Close()

	// localIDByExternal lets the manager pass map an HR supervisor id to a local
	// user id after all joiners exist.
	localIDByExternal := make(map[string]string)
	seen := make(map[string]bool)

	for _, rec := range records {
		if rec.ExternalID == "" || rec.Username == "" {
			continue
		}
		seen[rec.ExternalID] = true

		existing, found := dbUsers[rec.ExternalID]
		if found {
			localIDByExternal[rec.ExternalID] = existing.ID
			e.applyMover(ctx, orgID, existing, rec, result)
			// A present-but-terminated employee is a leaver even though HR still
			// lists them; deprovision on this pass.
			if rec.EmploymentStatus == "terminated" && existing.Enabled {
				e.deprovisionHR(ctx, orgID, existing.ID, existing.Username, cfg.DeprovisionAction, result)
			}
			continue
		}

		// Joiner: skip creating an already-terminated employee (nothing to
		// provision), but still count them as processed.
		if rec.EmploymentStatus == "terminated" {
			continue
		}
		newID, err := e.createHRUser(ctx, directoryID, orgID, rec)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("failed to create user %s: %v", rec.Username, err))
			continue
		}
		if newID != "" {
			localIDByExternal[rec.ExternalID] = newID
			result.UsersAdded++
		}
	}

	// Manager pass: resolve each record's supervisor external id to a local id.
	for _, rec := range records {
		if rec.ManagerExternal == "" {
			continue
		}
		childID, ok := localIDByExternal[rec.ExternalID]
		if !ok {
			continue
		}
		managerID, ok := localIDByExternal[rec.ManagerExternal]
		if !ok {
			continue // manager not in this directory / not yet provisioned
		}
		e.db.Pool.Exec(ctx,
			`UPDATE users SET manager_id = $2, updated_at = NOW() WHERE id = $1 AND org_id = $3`,
			childID, managerID, orgID)
	}

	// Leaver: HR-sourced users absent from the directory (only on full sync, so a
	// partial fetch can't mass-deprovision).
	if fullSync {
		absent := 0
		for extID := range dbUsers {
			if !seen[extID] && dbUsers[extID].Enabled {
				absent++
			}
		}
		// Safety valve: refuse a mass deprovision that looks like a bad fetch.
		if len(records) > 0 && absent > 0 {
			pct := float64(absent) / float64(len(records)+absent) * 100
			if pct > 40 {
				result.Errors = append(result.Errors,
					fmt.Sprintf("HRIS leaver rate %.0f%% (%d users) exceeds safety threshold; skipping deprovision", pct, absent))
				return nil
			}
		}
		for extID, user := range dbUsers {
			if !seen[extID] && user.Enabled {
				e.deprovisionHR(ctx, orgID, user.ID, user.Username, cfg.DeprovisionAction, result)
			}
		}
	}

	return nil
}

// applyMover updates HR attributes when any changed. It always keeps the org
// chart / title / department current and refreshes name/email.
func (e *SyncEngine) applyMover(ctx context.Context, orgID string, existing hrDBUser, rec UserRecord, result *SyncResult) {
	changed := existing.Username != rec.Username ||
		existing.Email != rec.Email ||
		existing.FirstName != rec.FirstName ||
		existing.LastName != rec.LastName ||
		existing.JobTitle != rec.JobTitle ||
		existing.Department != rec.Department ||
		(rec.EmploymentStatus != "" && existing.EmploymentStatus != rec.EmploymentStatus)
	if !changed {
		return
	}
	_, err := e.db.Pool.Exec(ctx, `
		UPDATE users SET username=$2, email=$3, first_name=$4, last_name=$5,
		       job_title=$6, department=$7, employment_status=$8,
		       hire_date = COALESCE(NULLIF($9,'')::date, hire_date),
		       termination_date = NULLIF($10,'')::date,
		       employee_number = COALESCE(NULLIF($11,''), employee_number),
		       updated_at = NOW()
		 WHERE id=$1 AND org_id=$12`,
		existing.ID, rec.Username, rec.Email, rec.FirstName, rec.LastName,
		rec.JobTitle, rec.Department, nonEmptyOr(rec.EmploymentStatus, "active"),
		rec.HireDate, rec.TerminationDate, rec.EmployeeNumber, orgID)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to update user %s: %v", rec.Username, err))
		return
	}
	result.UsersUpdated++
}

// createHRUser inserts a new HR-sourced user (joiner) with an unusable password.
func (e *SyncEngine) createHRUser(ctx context.Context, directoryID, orgID string, rec UserRecord) (string, error) {
	randomPwd := fmt.Sprintf("hris-nologin-%d", time.Now().UnixNano())
	hash, _ := bcrypt.GenerateFromPassword([]byte(randomPwd), bcrypt.DefaultCost)

	var id string
	err := e.db.Pool.QueryRow(ctx, `
		INSERT INTO users (username, email, first_name, last_name, password_hash,
		                   enabled, email_verified, source, directory_id,
		                   external_hr_id, employee_number, job_title, department,
		                   employment_status,
		                   hire_date, termination_date, org_id)
		VALUES ($1,$2,$3,$4,$5, true, true, 'hris', $6, $7, $8, $9, $10, $11,
		        NULLIF($12,'')::date, NULLIF($13,'')::date, $14)
		ON CONFLICT (username) DO NOTHING
		RETURNING id`,
		rec.Username, nonEmptyOr(rec.Email, rec.Username+"@no-email.local"),
		rec.FirstName, rec.LastName, string(hash), directoryID,
		rec.ExternalID, rec.EmployeeNumber, rec.JobTitle, rec.Department,
		nonEmptyOr(rec.EmploymentStatus, "active"),
		rec.HireDate, rec.TerminationDate, orgID).Scan(&id)
	if err != nil {
		// ON CONFLICT DO NOTHING returns no rows -> not a fatal error; the user
		// exists under this username already (e.g. from another source).
		if err.Error() == "no rows in result set" {
			return "", nil
		}
		return "", err
	}
	return id, nil
}

// deprovisionHR disables (or deletes) a leaver and stamps the termination.
func (e *SyncEngine) deprovisionHR(ctx context.Context, orgID, userID, username, action string, result *SyncResult) {
	if action == "delete" {
		if _, err := e.db.Pool.Exec(ctx, `DELETE FROM users WHERE id=$1 AND org_id=$2`, userID, orgID); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("failed to delete user %s: %v", username, err))
			return
		}
		result.UsersDisabled++
		return
	}
	if _, err := e.db.Pool.Exec(ctx, `
		UPDATE users SET enabled=false, employment_status='terminated',
		       termination_date = COALESCE(termination_date, CURRENT_DATE), updated_at=NOW()
		 WHERE id=$1 AND org_id=$2`, userID, orgID); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to disable user %s: %v", username, err))
		return
	}
	result.UsersDisabled++
}

// newHRISConnector selects the connector for the configured HRIS provider.
func newHRISConnector(cfg HRISConfig, logger *zap.Logger) (DirectoryConnector, error) {
	switch cfg.Provider {
	case "", "bamboohr":
		return NewBambooHRConnector(cfg, logger), nil
	default:
		return nil, fmt.Errorf("unsupported HRIS provider: %s", cfg.Provider)
	}
}

func nonEmptyOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
