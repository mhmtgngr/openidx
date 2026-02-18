package admin

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// UserConsent represents a user's consent record for privacy compliance
type UserConsent struct {
	ID          string          `json:"id"`
	UserID      string          `json:"user_id"`
	ConsentType string          `json:"consent_type"`
	Version     string          `json:"version"`
	Granted     bool            `json:"granted"`
	IPAddress   *string         `json:"ip_address"`
	UserAgent   *string         `json:"user_agent"`
	Metadata    json.RawMessage `json:"metadata"`
	GrantedAt   *time.Time      `json:"granted_at"`
	RevokedAt   *time.Time      `json:"revoked_at"`
	ExpiresAt   *time.Time      `json:"expires_at"`
	CreatedAt   time.Time       `json:"created_at"`
}

// DataSubjectRequest represents a GDPR/CCPA data subject access request
type DataSubjectRequest struct {
	ID                      string          `json:"id"`
	UserID                  string          `json:"user_id"`
	RequestType             string          `json:"request_type"` // export, delete, restrict
	Status                  string          `json:"status"`       // pending, in_progress, completed, rejected
	Reason                  string          `json:"reason"`
	RequestedDataCategories json.RawMessage `json:"requested_data_categories"`
	ResultFilePath          *string         `json:"result_file_path"`
	ResultFileSize          *int64          `json:"result_file_size"`
	ProcessedBy             *string         `json:"processed_by"`
	Notes                   string          `json:"notes"`
	DueDate                 *time.Time      `json:"due_date"`
	CreatedAt               time.Time       `json:"created_at"`
	UpdatedAt               time.Time       `json:"updated_at"`
	CompletedAt             *time.Time      `json:"completed_at"`
}

// PrivacyRetentionPolicy defines data retention rules for privacy compliance
type PrivacyRetentionPolicy struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	DataCategory    string          `json:"data_category"`
	RetentionDays   int             `json:"retention_days"`
	Action          string          `json:"action"` // delete, anonymize
	AnonymizeFields json.RawMessage `json:"anonymize_fields"`
	Enabled         bool            `json:"enabled"`
	LastExecutedAt  *time.Time      `json:"last_executed_at"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// PrivacyAssessment represents a privacy impact assessment (PIA/DPIA)
type PrivacyAssessment struct {
	ID                 string          `json:"id"`
	Title              string          `json:"title"`
	Description        string          `json:"description"`
	DataCategories     json.RawMessage `json:"data_categories"`
	ProcessingPurposes json.RawMessage `json:"processing_purposes"`
	RiskLevel          string          `json:"risk_level"` // low, medium, high, critical
	Status             string          `json:"status"`     // draft, in_review, approved, rejected
	Findings           json.RawMessage `json:"findings"`
	Mitigations        json.RawMessage `json:"mitigations"`
	AssessorID         *string         `json:"assessor_id"`
	ReviewerID         *string         `json:"reviewer_id"`
	ReviewNotes        string          `json:"review_notes"`
	ApprovedAt         *time.Time      `json:"approved_at"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

// handlePrivacyDashboard returns aggregated privacy compliance statistics
func (s *Service) handlePrivacyDashboard(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	ctx := c.Request.Context()

	var totalConsents, activeDSARs, overdueDSARs, totalAssessments int

	err := s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_consents WHERE granted = true`).Scan(&totalConsents)
	if err != nil {
		s.logger.Error("Failed to count consents", zap.Error(err))
		totalConsents = 0
	}

	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM data_subject_requests WHERE status IN ('pending', 'in_progress')`).Scan(&activeDSARs)
	if err != nil {
		s.logger.Error("Failed to count active DSARs", zap.Error(err))
		activeDSARs = 0
	}

	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM data_subject_requests WHERE status = 'pending' AND due_date < NOW()`).Scan(&overdueDSARs)
	if err != nil {
		s.logger.Error("Failed to count overdue DSARs", zap.Error(err))
		overdueDSARs = 0
	}

	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM privacy_assessments`).Scan(&totalAssessments)
	if err != nil {
		s.logger.Error("Failed to count assessments", zap.Error(err))
		totalAssessments = 0
	}

	// Consent breakdown by type
	type consentBreakdown struct {
		ConsentType string `json:"consent_type"`
		Granted     int    `json:"granted"`
		Revoked     int    `json:"revoked"`
	}
	var breakdown []consentBreakdown
	rows, err := s.db.Pool.Query(ctx,
		`SELECT consent_type,
			SUM(CASE WHEN granted = true THEN 1 ELSE 0 END) AS granted,
			SUM(CASE WHEN granted = false THEN 1 ELSE 0 END) AS revoked
		 FROM user_consents GROUP BY consent_type`)
	if err != nil {
		s.logger.Error("Failed to query consent breakdown", zap.Error(err))
	} else {
		defer rows.Close()
		for rows.Next() {
			var cb consentBreakdown
			if err := rows.Scan(&cb.ConsentType, &cb.Granted, &cb.Revoked); err != nil {
				continue
			}
			breakdown = append(breakdown, cb)
		}
	}
	if breakdown == nil {
		breakdown = []consentBreakdown{}
	}

	// Recent DSARs with user info
	type recentDSAR struct {
		ID          string    `json:"id"`
		UserID      string    `json:"user_id"`
		Username    string    `json:"username"`
		RequestType string    `json:"request_type"`
		Status      string    `json:"status"`
		CreatedAt   time.Time `json:"created_at"`
	}
	var recentDSARs []recentDSAR
	dsarRows, err := s.db.Pool.Query(ctx,
		`SELECT d.id, d.user_id, COALESCE(u.username, ''), d.request_type, d.status, d.created_at
		 FROM data_subject_requests d
		 LEFT JOIN users u ON d.user_id = u.id
		 ORDER BY d.created_at DESC LIMIT 5`)
	if err != nil {
		s.logger.Error("Failed to query recent DSARs", zap.Error(err))
	} else {
		defer dsarRows.Close()
		for dsarRows.Next() {
			var rd recentDSAR
			if err := dsarRows.Scan(&rd.ID, &rd.UserID, &rd.Username, &rd.RequestType, &rd.Status, &rd.CreatedAt); err != nil {
				continue
			}
			recentDSARs = append(recentDSARs, rd)
		}
	}
	if recentDSARs == nil {
		recentDSARs = []recentDSAR{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_consents":    totalConsents,
		"active_dsars":      activeDSARs,
		"overdue_dsars":     overdueDSARs,
		"total_assessments": totalAssessments,
		"consent_breakdown": breakdown,
		"recent_dsars":      recentDSARs,
	})
}

// handleListConsents lists user consent records with optional filtering
func (s *Service) handleListConsents(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	consentType := c.Query("consent_type")
	userID := c.Query("user_id")

	limit := 20
	offset := 0
	if l := c.Query("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	if o := c.Query("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}
	if offset < 0 {
		offset = 0
	}

	ctx := c.Request.Context()

	baseQuery := `SELECT uc.id, uc.user_id, COALESCE(u.username, ''), uc.consent_type, uc.version,
		uc.granted, uc.ip_address, uc.user_agent, uc.metadata,
		uc.granted_at, uc.revoked_at, uc.expires_at, uc.created_at
		FROM user_consents uc LEFT JOIN users u ON uc.user_id = u.id`
	countQuery := `SELECT COUNT(*) FROM user_consents uc`

	conditions := []string{}
	args := []interface{}{}
	argIdx := 1

	if consentType != "" {
		conditions = append(conditions, fmt.Sprintf("uc.consent_type = $%d", argIdx))
		args = append(args, consentType)
		argIdx++
	}
	if userID != "" {
		conditions = append(conditions, fmt.Sprintf("uc.user_id = $%d", argIdx))
		args = append(args, userID)
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE "
		for i, cond := range conditions {
			if i > 0 {
				whereClause += " AND "
			}
			whereClause += cond
		}
	}

	var total int
	err := s.db.Pool.QueryRow(ctx, countQuery+whereClause, args...).Scan(&total)
	if err != nil {
		s.logger.Error("Failed to count consents", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count consents"})
		return
	}

	paginatedArgs := append([]interface{}{}, args...)
	finalQuery := baseQuery + whereClause + " ORDER BY uc.created_at DESC"
	finalQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	paginatedArgs = append(paginatedArgs, limit, offset)

	rows, err := s.db.Pool.Query(ctx, finalQuery, paginatedArgs...)
	if err != nil {
		s.logger.Error("Failed to query consents", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query consents"})
		return
	}
	defer rows.Close()

	type consentWithUser struct {
		UserConsent
		Username string `json:"username"`
	}
	var consents []consentWithUser
	for rows.Next() {
		var cu consentWithUser
		if err := rows.Scan(&cu.ID, &cu.UserID, &cu.Username, &cu.ConsentType, &cu.Version,
			&cu.Granted, &cu.IPAddress, &cu.UserAgent, &cu.Metadata,
			&cu.GrantedAt, &cu.RevokedAt, &cu.ExpiresAt, &cu.CreatedAt); err != nil {
			s.logger.Error("Failed to scan consent row", zap.Error(err))
			continue
		}
		consents = append(consents, cu)
	}
	if consents == nil {
		consents = []consentWithUser{}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  consents,
		"total": total,
	})
}

// handleConsentStats returns consent statistics grouped by type
func (s *Service) handleConsentStats(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT consent_type,
			SUM(CASE WHEN granted = true THEN 1 ELSE 0 END) AS granted,
			SUM(CASE WHEN granted = false THEN 1 ELSE 0 END) AS revoked
		 FROM user_consents GROUP BY consent_type ORDER BY consent_type`)
	if err != nil {
		s.logger.Error("Failed to query consent stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query consent stats"})
		return
	}
	defer rows.Close()

	type stat struct {
		ConsentType string `json:"consent_type"`
		Granted     int    `json:"granted"`
		Revoked     int    `json:"revoked"`
	}
	var stats []stat
	for rows.Next() {
		var s stat
		if err := rows.Scan(&s.ConsentType, &s.Granted, &s.Revoked); err != nil {
			continue
		}
		stats = append(stats, s)
	}
	if stats == nil {
		stats = []stat{}
	}

	c.JSON(http.StatusOK, gin.H{"data": stats})
}

// handleListDSARs lists data subject access requests with optional status filtering
func (s *Service) handleListDSARs(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	status := c.Query("status")

	limit := 20
	offset := 0
	if l := c.Query("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	if o := c.Query("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}
	if offset < 0 {
		offset = 0
	}

	ctx := c.Request.Context()

	baseQuery := `SELECT d.id, d.user_id, COALESCE(u.username, ''), d.request_type, d.status,
		d.reason, d.requested_data_categories, d.result_file_path, d.result_file_size,
		d.processed_by, d.notes, d.due_date, d.created_at, d.updated_at, d.completed_at
		FROM data_subject_requests d LEFT JOIN users u ON d.user_id = u.id`
	countQuery := `SELECT COUNT(*) FROM data_subject_requests d`

	conditions := []string{}
	args := []interface{}{}
	argIdx := 1

	if status != "" {
		conditions = append(conditions, fmt.Sprintf("d.status = $%d", argIdx))
		args = append(args, status)
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + conditions[0]
	}

	var total int
	err := s.db.Pool.QueryRow(ctx, countQuery+whereClause, args...).Scan(&total)
	if err != nil {
		s.logger.Error("Failed to count DSARs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count DSARs"})
		return
	}

	paginatedArgs := append([]interface{}{}, args...)
	finalQuery := baseQuery + whereClause + " ORDER BY d.created_at DESC"
	finalQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	paginatedArgs = append(paginatedArgs, limit, offset)

	rows, err := s.db.Pool.Query(ctx, finalQuery, paginatedArgs...)
	if err != nil {
		s.logger.Error("Failed to query DSARs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query DSARs"})
		return
	}
	defer rows.Close()

	type dsarWithUser struct {
		DataSubjectRequest
		Username string `json:"username"`
	}
	var dsars []dsarWithUser
	for rows.Next() {
		var d dsarWithUser
		if err := rows.Scan(&d.ID, &d.UserID, &d.Username, &d.RequestType, &d.Status,
			&d.Reason, &d.RequestedDataCategories, &d.ResultFilePath, &d.ResultFileSize,
			&d.ProcessedBy, &d.Notes, &d.DueDate, &d.CreatedAt, &d.UpdatedAt, &d.CompletedAt); err != nil {
			s.logger.Error("Failed to scan DSAR row", zap.Error(err))
			continue
		}
		dsars = append(dsars, d)
	}
	if dsars == nil {
		dsars = []dsarWithUser{}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  dsars,
		"total": total,
	})
}

// handleCreateDSAR creates a new data subject access request
func (s *Service) handleCreateDSAR(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		UserID                  string          `json:"user_id"`
		RequestType             string          `json:"request_type"`
		Reason                  string          `json:"reason"`
		RequestedDataCategories json.RawMessage `json:"requested_data_categories"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.UserID == "" || req.RequestType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id and request_type are required"})
		return
	}

	validTypes := map[string]bool{"export": true, "delete": true, "restrict": true}
	if !validTypes[req.RequestType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "request_type must be export, delete, or restrict"})
		return
	}

	categories := req.RequestedDataCategories
	if categories == nil {
		categories = json.RawMessage("[]")
	}

	dueDate := time.Now().Add(30 * 24 * time.Hour)

	var id string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO data_subject_requests (user_id, request_type, reason, requested_data_categories, due_date)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		req.UserID, req.RequestType, req.Reason, categories, dueDate,
	).Scan(&id)
	if err != nil {
		s.logger.Error("Failed to create DSAR", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create DSAR"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "pending", "due_date": dueDate})
}

// handleGetDSAR retrieves a single data subject access request by ID
func (s *Service) handleGetDSAR(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()

	type dsarDetail struct {
		DataSubjectRequest
		Username      string `json:"username"`
		ProcessedName string `json:"processed_by_name"`
	}
	var d dsarDetail
	err := s.db.Pool.QueryRow(ctx,
		`SELECT d.id, d.user_id, COALESCE(u.username, ''), d.request_type, d.status,
			d.reason, d.requested_data_categories, d.result_file_path, d.result_file_size,
			d.processed_by, COALESCE(p.username, ''), d.notes, d.due_date,
			d.created_at, d.updated_at, d.completed_at
		 FROM data_subject_requests d
		 LEFT JOIN users u ON d.user_id = u.id
		 LEFT JOIN users p ON d.processed_by = p.id
		 WHERE d.id = $1`, id,
	).Scan(&d.ID, &d.UserID, &d.Username, &d.RequestType, &d.Status,
		&d.Reason, &d.RequestedDataCategories, &d.ResultFilePath, &d.ResultFileSize,
		&d.ProcessedBy, &d.ProcessedName, &d.Notes, &d.DueDate,
		&d.CreatedAt, &d.UpdatedAt, &d.CompletedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "DSAR not found"})
		return
	}

	c.JSON(http.StatusOK, d)
}

// handleUpdateDSAR updates a data subject access request status and notes
func (s *Service) handleUpdateDSAR(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")

	var req struct {
		Status *string `json:"status"`
		Notes  *string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	sets := []string{}
	args := []interface{}{}
	argIdx := 1

	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, *req.Status)
		argIdx++

		if *req.Status == "completed" {
			sets = append(sets, fmt.Sprintf("completed_at = $%d", argIdx))
			args = append(args, time.Now())
			argIdx++
		}
	}
	if req.Notes != nil {
		sets = append(sets, fmt.Sprintf("notes = $%d", argIdx))
		args = append(args, *req.Notes)
		argIdx++
	}

	if userIDStr != "" {
		sets = append(sets, fmt.Sprintf("processed_by = $%d", argIdx))
		args = append(args, userIDStr)
		argIdx++
	}

	sets = append(sets, "updated_at = NOW()")

	if len(sets) <= 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
		return
	}

	args = append(args, id)
	query := fmt.Sprintf("UPDATE data_subject_requests SET %s WHERE id = $%d", joinSetClauses(sets), argIdx)

	result, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		s.logger.Error("Failed to update DSAR", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update DSAR"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "DSAR not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "DSAR updated"})
}

// handleExecuteDSAR executes a data subject access request (export or delete)
func (s *Service) handleExecuteDSAR(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	ctx := c.Request.Context()

	var dsar DataSubjectRequest
	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, user_id, request_type, status FROM data_subject_requests WHERE id = $1`, id,
	).Scan(&dsar.ID, &dsar.UserID, &dsar.RequestType, &dsar.Status)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "DSAR not found"})
		return
	}

	if dsar.Status == "completed" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DSAR is already completed"})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	switch dsar.RequestType {
	case "export":
		// Gather user data from multiple tables
		userData := map[string]interface{}{}

		// User profile
		var profileJSON json.RawMessage
		err := s.db.Pool.QueryRow(ctx,
			`SELECT row_to_json(u) FROM (SELECT id, username, email, first_name, last_name, created_at, updated_at FROM users WHERE id = $1) u`,
			dsar.UserID).Scan(&profileJSON)
		if err == nil {
			userData["profile"] = profileJSON
		}

		// Consents
		var consentsJSON json.RawMessage
		err = s.db.Pool.QueryRow(ctx,
			`SELECT COALESCE(json_agg(row_to_json(c)), '[]'::json) FROM (SELECT id, consent_type, version, granted, granted_at, revoked_at FROM user_consents WHERE user_id = $1) c`,
			dsar.UserID).Scan(&consentsJSON)
		if err == nil {
			userData["consents"] = consentsJSON
		}

		// Sessions
		var sessionsJSON json.RawMessage
		err = s.db.Pool.QueryRow(ctx,
			`SELECT COALESCE(json_agg(row_to_json(s)), '[]'::json) FROM (SELECT id, client_id, ip_address, started_at, expires_at FROM sessions WHERE user_id = $1) s`,
			dsar.UserID).Scan(&sessionsJSON)
		if err == nil {
			userData["sessions"] = sessionsJSON
		}

		// Audit events
		var auditJSON json.RawMessage
		err = s.db.Pool.QueryRow(ctx,
			`SELECT COALESCE(json_agg(row_to_json(a)), '[]'::json) FROM (SELECT id, event_type, action, resource_type, created_at FROM audit_events WHERE actor_id = $1 ORDER BY created_at DESC LIMIT 1000) a`,
			dsar.UserID).Scan(&auditJSON)
		if err == nil {
			userData["audit_events"] = auditJSON
		}

		// Write gzip file
		exportDir := "/tmp/openidx-privacy"
		if err := os.MkdirAll(exportDir, 0750); err != nil {
			s.logger.Error("Failed to create export directory", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create export directory"})
			return
		}

		filename := fmt.Sprintf("dsar-export-%s-%s.json.gz", dsar.UserID, time.Now().Format("20060102-150405"))
		filePath := filepath.Join(exportDir, filename)

		f, err := os.Create(filePath)
		if err != nil {
			s.logger.Error("Failed to create export file", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create export file"})
			return
		}

		gzWriter := gzip.NewWriter(f)
		encoder := json.NewEncoder(gzWriter)
		encoder.SetIndent("", "  ")
		encErr := encoder.Encode(userData)
		gzWriter.Close()
		f.Close()

		if encErr != nil {
			s.logger.Error("Failed to write export data", zap.Error(encErr))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write export data"})
			return
		}

		// Get file size
		fi, err := os.Stat(filePath)
		if err != nil {
			s.logger.Error("Failed to stat export file", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to stat export file"})
			return
		}
		fileSize := fi.Size()

		_, err = s.db.Pool.Exec(ctx,
			`UPDATE data_subject_requests SET status = 'completed', result_file_path = $1, result_file_size = $2,
				processed_by = $3, completed_at = NOW(), updated_at = NOW() WHERE id = $4`,
			filePath, fileSize, nilIfEmpty(userIDStr), id)
		if err != nil {
			s.logger.Error("Failed to update DSAR after export", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update DSAR"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message":   "Data export completed",
			"file_path": filePath,
			"file_size": fileSize,
		})

	case "delete":
		// Anonymize user data
		deletedEmail := fmt.Sprintf("deleted-%s@deleted", dsar.UserID)
		_, err := s.db.Pool.Exec(ctx,
			`UPDATE users SET email = $1, first_name = 'Deleted', last_name = 'Deleted', updated_at = NOW() WHERE id = $2`,
			deletedEmail, dsar.UserID)
		if err != nil {
			s.logger.Error("Failed to anonymize user data", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to anonymize user data"})
			return
		}

		_, err = s.db.Pool.Exec(ctx,
			`UPDATE data_subject_requests SET status = 'completed', processed_by = $1, completed_at = NOW(), updated_at = NOW() WHERE id = $2`,
			nilIfEmpty(userIDStr), id)
		if err != nil {
			s.logger.Error("Failed to update DSAR after delete", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update DSAR"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "User data anonymized and DSAR completed"})

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Execution not supported for request type: %s", dsar.RequestType)})
	}
}

// handleListPrivacyRetention lists all privacy retention policies
func (s *Service) handleListPrivacyRetention(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, name, data_category, retention_days, action, anonymize_fields,
			enabled, last_executed_at, created_at, updated_at
		 FROM privacy_retention_policies ORDER BY data_category`)
	if err != nil {
		s.logger.Error("Failed to list retention policies", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list retention policies"})
		return
	}
	defer rows.Close()

	var policies []PrivacyRetentionPolicy
	for rows.Next() {
		var p PrivacyRetentionPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.DataCategory, &p.RetentionDays, &p.Action,
			&p.AnonymizeFields, &p.Enabled, &p.LastExecutedAt, &p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		policies = append(policies, p)
	}
	if policies == nil {
		policies = []PrivacyRetentionPolicy{}
	}

	c.JSON(http.StatusOK, gin.H{"data": policies})
}

// handleCreatePrivacyRetention creates a new privacy retention policy
func (s *Service) handleCreatePrivacyRetention(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		Name            string          `json:"name"`
		DataCategory    string          `json:"data_category"`
		RetentionDays   int             `json:"retention_days"`
		Action          string          `json:"action"`
		AnonymizeFields json.RawMessage `json:"anonymize_fields"`
		Enabled         bool            `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.Name == "" || req.DataCategory == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and data_category are required"})
		return
	}

	validActions := map[string]bool{"delete": true, "anonymize": true}
	if !validActions[req.Action] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action must be delete or anonymize"})
		return
	}

	anonymizeFields := req.AnonymizeFields
	if anonymizeFields == nil {
		anonymizeFields = json.RawMessage("[]")
	}

	var id string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO privacy_retention_policies (name, data_category, retention_days, action, anonymize_fields, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		req.Name, req.DataCategory, req.RetentionDays, req.Action, anonymizeFields, req.Enabled,
	).Scan(&id)
	if err != nil {
		s.logger.Error("Failed to create retention policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create retention policy"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// handleUpdatePrivacyRetention updates an existing privacy retention policy
func (s *Service) handleUpdatePrivacyRetention(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")

	var req struct {
		Name            *string          `json:"name"`
		DataCategory    *string          `json:"data_category"`
		RetentionDays   *int             `json:"retention_days"`
		Action          *string          `json:"action"`
		AnonymizeFields *json.RawMessage `json:"anonymize_fields"`
		Enabled         *bool            `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	sets := []string{}
	args := []interface{}{}
	argIdx := 1

	if req.Name != nil {
		sets = append(sets, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *req.Name)
		argIdx++
	}
	if req.DataCategory != nil {
		sets = append(sets, fmt.Sprintf("data_category = $%d", argIdx))
		args = append(args, *req.DataCategory)
		argIdx++
	}
	if req.RetentionDays != nil {
		sets = append(sets, fmt.Sprintf("retention_days = $%d", argIdx))
		args = append(args, *req.RetentionDays)
		argIdx++
	}
	if req.Action != nil {
		sets = append(sets, fmt.Sprintf("action = $%d", argIdx))
		args = append(args, *req.Action)
		argIdx++
	}
	if req.AnonymizeFields != nil {
		sets = append(sets, fmt.Sprintf("anonymize_fields = $%d", argIdx))
		args = append(args, *req.AnonymizeFields)
		argIdx++
	}
	if req.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled = $%d", argIdx))
		args = append(args, *req.Enabled)
		argIdx++
	}

	if len(sets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
		return
	}

	sets = append(sets, "updated_at = NOW()")
	args = append(args, id)
	query := fmt.Sprintf("UPDATE privacy_retention_policies SET %s WHERE id = $%d", joinSetClauses(sets), argIdx)

	result, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		s.logger.Error("Failed to update retention policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update retention policy"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Retention policy not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Retention policy updated"})
}

// handleDeletePrivacyRetention deletes a privacy retention policy
func (s *Service) handleDeletePrivacyRetention(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")

	result, err := s.db.Pool.Exec(c.Request.Context(),
		`DELETE FROM privacy_retention_policies WHERE id = $1`, id)
	if err != nil {
		s.logger.Error("Failed to delete retention policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete retention policy"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Retention policy not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Retention policy deleted"})
}

// handleListPrivacyAssessments lists privacy impact assessments with optional filtering
func (s *Service) handleListPrivacyAssessments(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	status := c.Query("status")
	riskLevel := c.Query("risk_level")

	ctx := c.Request.Context()

	baseQuery := `SELECT id, title, description, data_categories, processing_purposes,
		risk_level, status, findings, mitigations, assessor_id, reviewer_id,
		review_notes, approved_at, created_at, updated_at
		FROM privacy_assessments`

	conditions := []string{}
	args := []interface{}{}
	argIdx := 1

	if status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, status)
		argIdx++
	}
	if riskLevel != "" {
		conditions = append(conditions, fmt.Sprintf("risk_level = $%d", argIdx))
		args = append(args, riskLevel)
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE "
		for i, cond := range conditions {
			if i > 0 {
				whereClause += " AND "
			}
			whereClause += cond
		}
	}

	rows, err := s.db.Pool.Query(ctx, baseQuery+whereClause+" ORDER BY created_at DESC", args...)
	if err != nil {
		s.logger.Error("Failed to list privacy assessments", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list privacy assessments"})
		return
	}
	defer rows.Close()

	var assessments []PrivacyAssessment
	for rows.Next() {
		var a PrivacyAssessment
		if err := rows.Scan(&a.ID, &a.Title, &a.Description, &a.DataCategories, &a.ProcessingPurposes,
			&a.RiskLevel, &a.Status, &a.Findings, &a.Mitigations, &a.AssessorID, &a.ReviewerID,
			&a.ReviewNotes, &a.ApprovedAt, &a.CreatedAt, &a.UpdatedAt); err != nil {
			continue
		}
		assessments = append(assessments, a)
	}
	if assessments == nil {
		assessments = []PrivacyAssessment{}
	}

	c.JSON(http.StatusOK, gin.H{"data": assessments})
}

// handleCreatePrivacyAssessment creates a new privacy impact assessment
func (s *Service) handleCreatePrivacyAssessment(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		Title              string          `json:"title"`
		Description        string          `json:"description"`
		DataCategories     json.RawMessage `json:"data_categories"`
		ProcessingPurposes json.RawMessage `json:"processing_purposes"`
		RiskLevel          string          `json:"risk_level"`
		Findings           json.RawMessage `json:"findings"`
		Mitigations        json.RawMessage `json:"mitigations"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title is required"})
		return
	}

	validRisk := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if req.RiskLevel != "" && !validRisk[req.RiskLevel] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "risk_level must be low, medium, high, or critical"})
		return
	}
	if req.RiskLevel == "" {
		req.RiskLevel = "medium"
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	dataCategories := req.DataCategories
	if dataCategories == nil {
		dataCategories = json.RawMessage("[]")
	}
	processingPurposes := req.ProcessingPurposes
	if processingPurposes == nil {
		processingPurposes = json.RawMessage("[]")
	}
	findings := req.Findings
	if findings == nil {
		findings = json.RawMessage("[]")
	}
	mitigations := req.Mitigations
	if mitigations == nil {
		mitigations = json.RawMessage("[]")
	}

	var id string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO privacy_assessments (title, description, data_categories, processing_purposes,
			risk_level, findings, mitigations, assessor_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		req.Title, req.Description, dataCategories, processingPurposes,
		req.RiskLevel, findings, mitigations, nilIfEmpty(userIDStr),
	).Scan(&id)
	if err != nil {
		s.logger.Error("Failed to create privacy assessment", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create privacy assessment"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "draft"})
}

// handleGetPrivacyAssessment retrieves a single privacy assessment by ID
func (s *Service) handleGetPrivacyAssessment(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")

	var a PrivacyAssessment
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, title, description, data_categories, processing_purposes,
			risk_level, status, findings, mitigations, assessor_id, reviewer_id,
			review_notes, approved_at, created_at, updated_at
		 FROM privacy_assessments WHERE id = $1`, id,
	).Scan(&a.ID, &a.Title, &a.Description, &a.DataCategories, &a.ProcessingPurposes,
		&a.RiskLevel, &a.Status, &a.Findings, &a.Mitigations, &a.AssessorID, &a.ReviewerID,
		&a.ReviewNotes, &a.ApprovedAt, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Privacy assessment not found"})
		return
	}

	c.JSON(http.StatusOK, a)
}

// handleUpdatePrivacyAssessment updates an existing privacy assessment
func (s *Service) handleUpdatePrivacyAssessment(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")

	var req struct {
		Title              *string          `json:"title"`
		Description        *string          `json:"description"`
		DataCategories     *json.RawMessage `json:"data_categories"`
		ProcessingPurposes *json.RawMessage `json:"processing_purposes"`
		RiskLevel          *string          `json:"risk_level"`
		Status             *string          `json:"status"`
		Findings           *json.RawMessage `json:"findings"`
		Mitigations        *json.RawMessage `json:"mitigations"`
		ReviewerID         *string          `json:"reviewer_id"`
		ReviewNotes        *string          `json:"review_notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	sets := []string{}
	args := []interface{}{}
	argIdx := 1

	if req.Title != nil {
		sets = append(sets, fmt.Sprintf("title = $%d", argIdx))
		args = append(args, *req.Title)
		argIdx++
	}
	if req.Description != nil {
		sets = append(sets, fmt.Sprintf("description = $%d", argIdx))
		args = append(args, *req.Description)
		argIdx++
	}
	if req.DataCategories != nil {
		sets = append(sets, fmt.Sprintf("data_categories = $%d", argIdx))
		args = append(args, *req.DataCategories)
		argIdx++
	}
	if req.ProcessingPurposes != nil {
		sets = append(sets, fmt.Sprintf("processing_purposes = $%d", argIdx))
		args = append(args, *req.ProcessingPurposes)
		argIdx++
	}
	if req.RiskLevel != nil {
		sets = append(sets, fmt.Sprintf("risk_level = $%d", argIdx))
		args = append(args, *req.RiskLevel)
		argIdx++
	}
	if req.Status != nil {
		sets = append(sets, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, *req.Status)
		argIdx++

		if *req.Status == "approved" {
			sets = append(sets, fmt.Sprintf("approved_at = $%d", argIdx))
			args = append(args, time.Now())
			argIdx++
		}
	}
	if req.Findings != nil {
		sets = append(sets, fmt.Sprintf("findings = $%d", argIdx))
		args = append(args, *req.Findings)
		argIdx++
	}
	if req.Mitigations != nil {
		sets = append(sets, fmt.Sprintf("mitigations = $%d", argIdx))
		args = append(args, *req.Mitigations)
		argIdx++
	}
	if req.ReviewerID != nil {
		sets = append(sets, fmt.Sprintf("reviewer_id = $%d", argIdx))
		args = append(args, *req.ReviewerID)
		argIdx++
	}
	if req.ReviewNotes != nil {
		sets = append(sets, fmt.Sprintf("review_notes = $%d", argIdx))
		args = append(args, *req.ReviewNotes)
		argIdx++
	}

	if len(sets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
		return
	}

	sets = append(sets, "updated_at = NOW()")
	args = append(args, id)
	query := fmt.Sprintf("UPDATE privacy_assessments SET %s WHERE id = $%d", joinSetClauses(sets), argIdx)

	result, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		s.logger.Error("Failed to update privacy assessment", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update privacy assessment"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Privacy assessment not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Privacy assessment updated"})
}

// handleDeletePrivacyAssessment deletes a privacy assessment
func (s *Service) handleDeletePrivacyAssessment(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")

	result, err := s.db.Pool.Exec(c.Request.Context(),
		`DELETE FROM privacy_assessments WHERE id = $1`, id)
	if err != nil {
		s.logger.Error("Failed to delete privacy assessment", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete privacy assessment"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Privacy assessment not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Privacy assessment deleted"})
}
