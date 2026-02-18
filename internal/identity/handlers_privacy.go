package identity

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// --- User Self-Service Privacy/GDPR Endpoints ---

func (s *Service) handleGetMyPrivacyConsents(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, consent_type, version, granted, ip_address, user_agent, metadata,
			granted_at, revoked_at, expires_at, created_at
		 FROM user_consents WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		s.logger.Error("Failed to list user consents", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list consents"})
		return
	}
	defer rows.Close()

	type consent struct {
		ID          string          `json:"id"`
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

	var consents []consent
	for rows.Next() {
		var co consent
		if err := rows.Scan(&co.ID, &co.ConsentType, &co.Version, &co.Granted,
			&co.IPAddress, &co.UserAgent, &co.Metadata,
			&co.GrantedAt, &co.RevokedAt, &co.ExpiresAt, &co.CreatedAt); err != nil {
			continue
		}
		consents = append(consents, co)
	}
	if consents == nil {
		consents = []consent{}
	}
	c.JSON(http.StatusOK, gin.H{"data": consents})
}

func (s *Service) handleGrantPrivacyConsent(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req struct {
		ConsentType string          `json:"consent_type" binding:"required"`
		Version     string          `json:"version"`
		Metadata    json.RawMessage `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if req.Version == "" {
		req.Version = "1.0"
	}

	now := time.Now()
	_, err := s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO user_consents (user_id, consent_type, version, granted, ip_address, user_agent, metadata, granted_at)
		 VALUES ($1, $2, $3, true, $4, $5, $6, $7)`,
		userID, req.ConsentType, req.Version,
		c.ClientIP(), c.Request.UserAgent(), req.Metadata, now)
	if err != nil {
		s.logger.Error("Failed to grant consent", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to grant consent"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "Consent granted"})
}

func (s *Service) handleRevokePrivacyConsent(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}
	consentType := c.Param("consentType")

	now := time.Now()
	_, err := s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO user_consents (user_id, consent_type, version, granted, ip_address, user_agent, revoked_at)
		 VALUES ($1, $2, '1.0', false, $3, $4, $5)`,
		userID, consentType, c.ClientIP(), c.Request.UserAgent(), now)
	if err != nil {
		s.logger.Error("Failed to revoke consent", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke consent"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Consent revoked"})
}

func (s *Service) handleSubmitDSAR(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req struct {
		RequestType             string          `json:"request_type" binding:"required"` // export, delete, restrict
		Reason                  string          `json:"reason"`
		RequestedDataCategories json.RawMessage `json:"requested_data_categories"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	var id string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO data_subject_requests (user_id, request_type, reason, requested_data_categories, due_date)
		 VALUES ($1, $2, $3, $4, NOW() + INTERVAL '30 days')
		 RETURNING id`,
		userID, req.RequestType, req.Reason, req.RequestedDataCategories).Scan(&id)
	if err != nil {
		s.logger.Error("Failed to submit DSAR", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to submit request"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Data subject request submitted"})
}

func (s *Service) handleGetMyDSARs(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, request_type, status, reason, requested_data_categories, due_date, created_at, updated_at, completed_at
		 FROM data_subject_requests WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		s.logger.Error("Failed to list user DSARs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list requests"})
		return
	}
	defer rows.Close()

	type dsar struct {
		ID                      string          `json:"id"`
		RequestType             string          `json:"request_type"`
		Status                  string          `json:"status"`
		Reason                  string          `json:"reason"`
		RequestedDataCategories json.RawMessage `json:"requested_data_categories"`
		DueDate                 *time.Time      `json:"due_date"`
		CreatedAt               time.Time       `json:"created_at"`
		UpdatedAt               time.Time       `json:"updated_at"`
		CompletedAt             *time.Time      `json:"completed_at"`
	}

	var dsars []dsar
	for rows.Next() {
		var d dsar
		if err := rows.Scan(&d.ID, &d.RequestType, &d.Status, &d.Reason,
			&d.RequestedDataCategories, &d.DueDate, &d.CreatedAt, &d.UpdatedAt, &d.CompletedAt); err != nil {
			continue
		}
		dsars = append(dsars, d)
	}
	if dsars == nil {
		dsars = []dsar{}
	}
	c.JSON(http.StatusOK, gin.H{"data": dsars})
}
