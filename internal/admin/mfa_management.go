package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	apperrors "github.com/openidx/openidx/internal/common/errors"
)

// MFAPolicy represents an MFA enforcement policy
type MFAPolicy struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	Enabled          bool            `json:"enabled"`
	Priority         int             `json:"priority"`
	Conditions       json.RawMessage `json:"conditions"`
	RequiredMethods  json.RawMessage `json:"required_methods"`
	GracePeriodHours int             `json:"grace_period_hours"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// MFAEnrollmentStats represents aggregate MFA enrollment statistics
type MFAEnrollmentStats struct {
	TotalUsers    int `json:"total_users"`
	AnyMFA        int `json:"any_mfa"`
	TOTPCount     int `json:"totp_count"`
	SMSCount      int `json:"sms_count"`
	EmailOTPCount int `json:"email_otp_count"`
	PushCount     int `json:"push_count"`
	WebAuthnCount int `json:"webauthn_count"`
}

// UserMFAStatus represents MFA enrollment status for a single user
type UserMFAStatus struct {
	UserID               string `json:"user_id"`
	Username             string `json:"username"`
	Email                string `json:"email"`
	TOTPEnabled          bool   `json:"totp_enabled"`
	SMSEnabled           bool   `json:"sms_enabled"`
	EmailOTPEnabled      bool   `json:"email_otp_enabled"`
	PushEnabled          bool   `json:"push_enabled"`
	WebAuthnEnabled      bool   `json:"webauthn_enabled"`
	BackupCodesRemaining int    `json:"backup_codes_remaining"`
}

// --- MFA Enrollment Stats Handler ---

func (s *Service) handleMFAEnrollmentStats(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var stats MFAEnrollmentStats
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT
			COUNT(*) AS total_users,
			SUM(CASE WHEN totp_enabled OR sms_enabled OR email_otp_enabled OR push_enabled OR webauthn_enabled THEN 1 ELSE 0 END) AS any_mfa,
			SUM(CASE WHEN totp_enabled THEN 1 ELSE 0 END) AS totp_count,
			SUM(CASE WHEN sms_enabled THEN 1 ELSE 0 END) AS sms_count,
			SUM(CASE WHEN email_otp_enabled THEN 1 ELSE 0 END) AS email_otp_count,
			SUM(CASE WHEN push_enabled THEN 1 ELSE 0 END) AS push_count,
			SUM(CASE WHEN webauthn_enabled THEN 1 ELSE 0 END) AS webauthn_count
		 FROM user_mfa_methods`,
	).Scan(&stats.TotalUsers, &stats.AnyMFA, &stats.TOTPCount, &stats.SMSCount,
		&stats.EmailOTPCount, &stats.PushCount, &stats.WebAuthnCount)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to get MFA enrollment stats", err))
		return
	}

	c.JSON(http.StatusOK, stats)
}

// --- MFA Policies Handlers ---

func (s *Service) handleListMFAPolicies(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, name, description, enabled, priority, conditions, required_methods, grace_period_hours, created_at, updated_at
		 FROM mfa_policies ORDER BY priority, name`)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to list MFA policies", err))
		return
	}
	defer rows.Close()

	var policies []MFAPolicy
	for rows.Next() {
		var p MFAPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &p.Priority,
			&p.Conditions, &p.RequiredMethods, &p.GracePeriodHours, &p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		policies = append(policies, p)
	}
	if policies == nil {
		policies = []MFAPolicy{}
	}
	c.JSON(http.StatusOK, gin.H{"data": policies})
}

func (s *Service) handleCreateMFAPolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		Name             string          `json:"name"`
		Description      string          `json:"description"`
		Enabled          bool            `json:"enabled"`
		Priority         int             `json:"priority"`
		Conditions       json.RawMessage `json:"conditions"`
		RequiredMethods  json.RawMessage `json:"required_methods"`
		GracePeriodHours int             `json:"grace_period_hours"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	if req.Name == "" {
		respondError(c, nil, apperrors.BadRequest("name is required"))
		return
	}

	conditions := req.Conditions
	if conditions == nil {
		conditions = json.RawMessage("{}")
	}
	requiredMethods := req.RequiredMethods
	if requiredMethods == nil {
		requiredMethods = json.RawMessage("[]")
	}

	var policy MFAPolicy
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO mfa_policies (name, description, enabled, priority, conditions, required_methods, grace_period_hours)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id, name, description, enabled, priority, conditions, required_methods, grace_period_hours, created_at, updated_at`,
		req.Name, req.Description, req.Enabled, req.Priority, conditions, requiredMethods, req.GracePeriodHours,
	).Scan(&policy.ID, &policy.Name, &policy.Description, &policy.Enabled, &policy.Priority,
		&policy.Conditions, &policy.RequiredMethods, &policy.GracePeriodHours, &policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to create MFA policy", err))
		return
	}

	c.JSON(http.StatusCreated, policy)
}

func (s *Service) handleGetMFAPolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var p MFAPolicy
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, name, description, enabled, priority, conditions, required_methods, grace_period_hours, created_at, updated_at
		 FROM mfa_policies WHERE id = $1`, id,
	).Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &p.Priority,
		&p.Conditions, &p.RequiredMethods, &p.GracePeriodHours, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		respondError(c, nil, apperrors.NotFound("MFA policy"))
		return
	}
	c.JSON(http.StatusOK, p)
}

func (s *Service) handleUpdateMFAPolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var req struct {
		Name             *string          `json:"name"`
		Description      *string          `json:"description"`
		Enabled          *bool            `json:"enabled"`
		Priority         *int             `json:"priority"`
		Conditions       *json.RawMessage `json:"conditions"`
		RequiredMethods  *json.RawMessage `json:"required_methods"`
		GracePeriodHours *int             `json:"grace_period_hours"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, nil, apperrors.BadRequest("Invalid request body"))
		return
	}

	sets := []string{"updated_at = NOW()"}
	args := []interface{}{}
	argIdx := 1

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *req.Name)
		argIdx++
	}
	if req.Description != nil {
		sets = append(sets, fmt.Sprintf("description = $%d", argIdx))
		args = append(args, *req.Description)
		argIdx++
	}
	if req.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled = $%d", argIdx))
		args = append(args, *req.Enabled)
		argIdx++
	}
	if req.Priority != nil {
		sets = append(sets, fmt.Sprintf("priority = $%d", argIdx))
		args = append(args, *req.Priority)
		argIdx++
	}
	if req.Conditions != nil {
		sets = append(sets, fmt.Sprintf("conditions = $%d", argIdx))
		args = append(args, *req.Conditions)
		argIdx++
	}
	if req.RequiredMethods != nil {
		sets = append(sets, fmt.Sprintf("required_methods = $%d", argIdx))
		args = append(args, *req.RequiredMethods)
		argIdx++
	}
	if req.GracePeriodHours != nil {
		sets = append(sets, fmt.Sprintf("grace_period_hours = $%d", argIdx))
		args = append(args, *req.GracePeriodHours)
		argIdx++
	}

	args = append(args, id)
	query := fmt.Sprintf("UPDATE mfa_policies SET %s WHERE id = $%d",
		joinSetClauses(sets), argIdx)

	tag, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to update MFA policy", err))
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("MFA policy"))
		return
	}

	// Return the updated policy
	var p MFAPolicy
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, name, description, enabled, priority, conditions, required_methods, grace_period_hours, created_at, updated_at
		 FROM mfa_policies WHERE id = $1`, id,
	).Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &p.Priority,
		&p.Conditions, &p.RequiredMethods, &p.GracePeriodHours, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to fetch updated MFA policy", err))
		return
	}
	c.JSON(http.StatusOK, p)
}

func (s *Service) handleDeleteMFAPolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	tag, err := s.db.Pool.Exec(c.Request.Context(),
		"DELETE FROM mfa_policies WHERE id = $1", id)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to delete MFA policy", err))
		return
	}
	if tag.RowsAffected() == 0 {
		respondError(c, nil, apperrors.NotFound("MFA policy"))
		return
	}
	c.Status(http.StatusNoContent)
}

// --- User MFA Status Handlers ---

func (s *Service) handleListUserMFAStatus(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	limit := 50
	offset := 0
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	if o := c.Query("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}

	ctx := c.Request.Context()

	var total int
	err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM user_mfa_methods").Scan(&total)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to count user MFA records", err))
		return
	}

	rows, err := s.db.Pool.Query(ctx,
		`SELECT m.user_id, m.username, u.email,
		        m.totp_enabled, m.sms_enabled, m.email_otp_enabled,
		        m.push_enabled, m.webauthn_enabled, m.backup_codes_remaining
		 FROM user_mfa_methods m
		 JOIN users u ON u.id = m.user_id
		 ORDER BY m.username
		 LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		respondError(c, s.logger, apperrors.Internal("Failed to list user MFA status", err))
		return
	}
	defer rows.Close()

	var statuses []UserMFAStatus
	for rows.Next() {
		var u UserMFAStatus
		if err := rows.Scan(&u.UserID, &u.Username, &u.Email,
			&u.TOTPEnabled, &u.SMSEnabled, &u.EmailOTPEnabled,
			&u.PushEnabled, &u.WebAuthnEnabled, &u.BackupCodesRemaining); err != nil {
			continue
		}
		statuses = append(statuses, u)
	}
	if statuses == nil {
		statuses = []UserMFAStatus{}
	}
	c.JSON(http.StatusOK, gin.H{"data": statuses, "total": total})
}

func (s *Service) handleGetUserMFAStatus(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var u UserMFAStatus
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT m.user_id, m.username, u.email,
		        m.totp_enabled, m.sms_enabled, m.email_otp_enabled,
		        m.push_enabled, m.webauthn_enabled, m.backup_codes_remaining
		 FROM user_mfa_methods m
		 JOIN users u ON u.id = m.user_id
		 WHERE m.user_id = $1`, id,
	).Scan(&u.UserID, &u.Username, &u.Email,
		&u.TOTPEnabled, &u.SMSEnabled, &u.EmailOTPEnabled,
		&u.PushEnabled, &u.WebAuthnEnabled, &u.BackupCodesRemaining)
	if err != nil {
		respondError(c, nil, apperrors.NotFound("user MFA status"))
		return
	}
	c.JSON(http.StatusOK, u)
}
