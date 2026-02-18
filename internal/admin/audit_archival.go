package admin

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// RetentionPolicy defines how long to keep audit events
type RetentionPolicy struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	EventCategory  string    `json:"event_category"`
	RetentionDays  int       `json:"retention_days"`
	ArchiveEnabled bool      `json:"archive_enabled"`
	ArchiveFormat  string    `json:"archive_format"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// AuditArchive represents a compressed archive of audit events
type AuditArchive struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	DateRangeStart *time.Time `json:"date_range_start"`
	DateRangeEnd   *time.Time `json:"date_range_end"`
	EventCount     int        `json:"event_count"`
	FileSize       int64      `json:"file_size"`
	FilePath       string     `json:"file_path"`
	Format         string     `json:"format"`
	Status         string     `json:"status"`
	CreatedBy      *string    `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
}

// --- Handlers ---

func (s *Service) handleListRetentionPolicies(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, name, event_category, retention_days, archive_enabled, archive_format, enabled, created_at, updated_at
		 FROM audit_retention_policies ORDER BY name`)
	if err != nil {
		s.logger.Error("Failed to list retention policies", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list policies"})
		return
	}
	defer rows.Close()

	var policies []RetentionPolicy
	for rows.Next() {
		var p RetentionPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.EventCategory, &p.RetentionDays,
			&p.ArchiveEnabled, &p.ArchiveFormat, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		policies = append(policies, p)
	}
	if policies == nil {
		policies = []RetentionPolicy{}
	}
	c.JSON(http.StatusOK, gin.H{"data": policies})
}

func (s *Service) handleCreateRetentionPolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		Name           string `json:"name"`
		EventCategory  string `json:"event_category"`
		RetentionDays  int    `json:"retention_days"`
		ArchiveEnabled bool   `json:"archive_enabled"`
		ArchiveFormat  string `json:"archive_format"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.Name == "" || req.RetentionDays <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and retention_days (>0) are required"})
		return
	}
	if req.EventCategory == "" {
		req.EventCategory = "all"
	}
	if req.ArchiveFormat == "" {
		req.ArchiveFormat = "json_gz"
	}

	var id string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO audit_retention_policies (name, event_category, retention_days, archive_enabled, archive_format)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		req.Name, req.EventCategory, req.RetentionDays, req.ArchiveEnabled, req.ArchiveFormat,
	).Scan(&id)
	if err != nil {
		s.logger.Error("Failed to create retention policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create policy"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Policy created"})
}

func (s *Service) handleUpdateRetentionPolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var req struct {
		Name           *string `json:"name"`
		EventCategory  *string `json:"event_category"`
		RetentionDays  *int    `json:"retention_days"`
		ArchiveEnabled *bool   `json:"archive_enabled"`
		ArchiveFormat  *string `json:"archive_format"`
		Enabled        *bool   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
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
	if req.EventCategory != nil {
		sets = append(sets, fmt.Sprintf("event_category = $%d", argIdx))
		args = append(args, *req.EventCategory)
		argIdx++
	}
	if req.RetentionDays != nil {
		sets = append(sets, fmt.Sprintf("retention_days = $%d", argIdx))
		args = append(args, *req.RetentionDays)
		argIdx++
	}
	if req.ArchiveEnabled != nil {
		sets = append(sets, fmt.Sprintf("archive_enabled = $%d", argIdx))
		args = append(args, *req.ArchiveEnabled)
		argIdx++
	}
	if req.ArchiveFormat != nil {
		sets = append(sets, fmt.Sprintf("archive_format = $%d", argIdx))
		args = append(args, *req.ArchiveFormat)
		argIdx++
	}
	if req.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled = $%d", argIdx))
		args = append(args, *req.Enabled)
		argIdx++
	}

	args = append(args, id)
	query := fmt.Sprintf("UPDATE audit_retention_policies SET %s WHERE id = $%d", joinSetClauses(sets), argIdx)

	tag, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		s.logger.Error("Failed to update retention policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update policy"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Policy updated"})
}

func (s *Service) handleDeleteRetentionPolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	tag, err := s.db.Pool.Exec(c.Request.Context(), "DELETE FROM audit_retention_policies WHERE id = $1", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete policy"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted"})
}

func (s *Service) handleCreateAuditArchive(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		Name           string `json:"name"`
		DateRangeStart string `json:"date_range_start"`
		DateRangeEnd   string `json:"date_range_end"`
		Category       string `json:"category"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.Name == "" || req.DateRangeStart == "" || req.DateRangeEnd == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name, date_range_start, and date_range_end are required"})
		return
	}

	start, err1 := time.Parse(time.RFC3339, req.DateRangeStart)
	end, err2 := time.Parse(time.RFC3339, req.DateRangeEnd)
	if err1 != nil || err2 != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date format (use RFC3339)"})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var archiveID string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO audit_archives (name, date_range_start, date_range_end, status, created_by)
		 VALUES ($1, $2, $3, 'creating', $4) RETURNING id`,
		req.Name, start, end, nilIfEmpty(userIDStr),
	).Scan(&archiveID)
	if err != nil {
		s.logger.Error("Failed to create audit archive", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create archive"})
		return
	}

	// Run archive creation in background
	go s.createAuditArchive(archiveID, start, end, req.Category)

	c.JSON(http.StatusCreated, gin.H{"id": archiveID, "status": "creating"})
}

func (s *Service) createAuditArchive(archiveID string, start, end time.Time, category string) {
	ctx := context.Background()

	// Query events in date range
	query := `SELECT id, timestamp, event_type, category, action, outcome, actor_id, actor_type,
	          actor_ip, target_id, target_type, resource_id, details, session_id, request_id
	          FROM audit_events WHERE timestamp >= $1 AND timestamp < $2`
	args := []interface{}{start, end}

	if category != "" && category != "all" {
		query += " AND category = $3"
		args = append(args, category)
	}
	query += " ORDER BY timestamp"

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		s.logger.Error("Failed to query audit events for archive", zap.Error(err))
		_, _ = s.db.Pool.Exec(ctx,
			"UPDATE audit_archives SET status = 'failed' WHERE id = $1", archiveID)
		return
	}
	defer rows.Close()

	// Create archive directory
	archiveDir := "/tmp/openidx-archives"
	_ = os.MkdirAll(archiveDir, 0750)
	filePath := filepath.Join(archiveDir, fmt.Sprintf("audit_%s.json.gz", archiveID))

	file, err := os.Create(filePath)
	if err != nil {
		s.logger.Error("Failed to create archive file", zap.Error(err))
		_, _ = s.db.Pool.Exec(ctx,
			"UPDATE audit_archives SET status = 'failed' WHERE id = $1", archiveID)
		return
	}
	defer file.Close()

	gzWriter := gzip.NewWriter(file)
	defer gzWriter.Close()

	eventCount := 0
	_, _ = gzWriter.Write([]byte("[\n"))

	for rows.Next() {
		var id, eventType, cat, action, outcome string
		var ts time.Time
		var actorID, actorType, actorIP, targetID, targetType, resourceID, sessionID, requestID *string
		var details json.RawMessage

		if err := rows.Scan(&id, &ts, &eventType, &cat, &action, &outcome,
			&actorID, &actorType, &actorIP, &targetID, &targetType, &resourceID,
			&details, &sessionID, &requestID); err != nil {
			continue
		}

		event := map[string]interface{}{
			"id": id, "timestamp": ts, "event_type": eventType,
			"category": cat, "action": action, "outcome": outcome,
			"actor_id": actorID, "actor_type": actorType, "actor_ip": actorIP,
			"target_id": targetID, "target_type": targetType, "resource_id": resourceID,
			"details": details, "session_id": sessionID, "request_id": requestID,
		}

		if eventCount > 0 {
			_, _ = gzWriter.Write([]byte(",\n"))
		}
		eventJSON, _ := json.Marshal(event)
		_, _ = gzWriter.Write(eventJSON)
		eventCount++
	}

	_, _ = gzWriter.Write([]byte("\n]"))
	_ = gzWriter.Close()

	// Get file size
	stat, _ := os.Stat(filePath)
	var fileSize int64
	if stat != nil {
		fileSize = stat.Size()
	}

	_, _ = s.db.Pool.Exec(ctx,
		`UPDATE audit_archives SET status = 'completed', event_count = $1, file_size = $2, file_path = $3
		 WHERE id = $4`,
		eventCount, fileSize, filePath, archiveID)
}

func (s *Service) handleListAuditArchives(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, name, date_range_start, date_range_end, event_count, file_size, file_path,
		        format, status, created_by, created_at
		 FROM audit_archives ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		s.logger.Error("Failed to list audit archives", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list archives"})
		return
	}
	defer rows.Close()

	var archives []AuditArchive
	for rows.Next() {
		var a AuditArchive
		if err := rows.Scan(&a.ID, &a.Name, &a.DateRangeStart, &a.DateRangeEnd,
			&a.EventCount, &a.FileSize, &a.FilePath, &a.Format, &a.Status,
			&a.CreatedBy, &a.CreatedAt); err != nil {
			continue
		}
		archives = append(archives, a)
	}
	if archives == nil {
		archives = []AuditArchive{}
	}
	c.JSON(http.StatusOK, gin.H{"data": archives})
}

func (s *Service) handleGetAuditArchive(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var a AuditArchive
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, name, date_range_start, date_range_end, event_count, file_size, file_path,
		        format, status, created_by, created_at
		 FROM audit_archives WHERE id = $1`, id,
	).Scan(&a.ID, &a.Name, &a.DateRangeStart, &a.DateRangeEnd, &a.EventCount, &a.FileSize,
		&a.FilePath, &a.Format, &a.Status, &a.CreatedBy, &a.CreatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Archive not found"})
		return
	}
	c.JSON(http.StatusOK, a)
}

func (s *Service) handleRestoreAuditArchive(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var filePath, status string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT file_path, status FROM audit_archives WHERE id = $1", id,
	).Scan(&filePath, &status)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Archive not found"})
		return
	}
	if status != "completed" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Archive is not in completed state"})
		return
	}

	// Read and decompress the archive
	file, err := os.Open(filePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Archive file not accessible"})
		return
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read archive"})
		return
	}
	defer gzReader.Close()

	var events []map[string]interface{}
	if err := json.NewDecoder(gzReader).Decode(&events); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse archive"})
		return
	}

	restored := 0
	for _, evt := range events {
		details, _ := json.Marshal(evt["details"])
		_, err := s.db.Pool.Exec(c.Request.Context(),
			`INSERT INTO audit_events (id, timestamp, event_type, category, action, outcome,
			  actor_id, actor_type, actor_ip, target_id, target_type, resource_id,
			  details, session_id, request_id)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
			 ON CONFLICT (id) DO NOTHING`,
			evt["id"], evt["timestamp"], evt["event_type"], evt["category"], evt["action"], evt["outcome"],
			evt["actor_id"], evt["actor_type"], evt["actor_ip"], evt["target_id"], evt["target_type"], evt["resource_id"],
			details, evt["session_id"], evt["request_id"])
		if err == nil {
			restored++
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Restored %d events", restored), "restored_count": restored})
}
