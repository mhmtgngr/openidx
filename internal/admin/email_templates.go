package admin

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// EmailTemplate represents an admin-customizable email template
type EmailTemplate struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Slug      string          `json:"slug"`
	Subject   string          `json:"subject"`
	HTMLBody  string          `json:"html_body"`
	TextBody  string          `json:"text_body"`
	Category  string          `json:"category"`
	Variables json.RawMessage `json:"variables"`
	Enabled   bool            `json:"enabled"`
	UpdatedBy *string         `json:"updated_by"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// EmailBranding represents organization-level email branding
type EmailBranding struct {
	ID           string    `json:"id"`
	OrgID        *string   `json:"org_id"`
	LogoURL      string    `json:"logo_url"`
	PrimaryColor string    `json:"primary_color"`
	AccentColor  string    `json:"accent_color"`
	HeaderText   string    `json:"header_text"`
	FooterText   string    `json:"footer_text"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// --- Handlers ---

func (s *Service) handleListEmailTemplates(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, name, slug, subject, html_body, text_body, category, variables, enabled, updated_by, created_at, updated_at
		 FROM email_templates ORDER BY category, name`)
	if err != nil {
		s.logger.Error("Failed to list email templates", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list templates"})
		return
	}
	defer rows.Close()

	var templates []EmailTemplate
	for rows.Next() {
		var t EmailTemplate
		if err := rows.Scan(&t.ID, &t.Name, &t.Slug, &t.Subject, &t.HTMLBody, &t.TextBody,
			&t.Category, &t.Variables, &t.Enabled, &t.UpdatedBy, &t.CreatedAt, &t.UpdatedAt); err != nil {
			continue
		}
		templates = append(templates, t)
	}
	if templates == nil {
		templates = []EmailTemplate{}
	}
	c.JSON(http.StatusOK, gin.H{"data": templates})
}

func (s *Service) handleGetEmailTemplate(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var t EmailTemplate
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, name, slug, subject, html_body, text_body, category, variables, enabled, updated_by, created_at, updated_at
		 FROM email_templates WHERE id = $1`, id,
	).Scan(&t.ID, &t.Name, &t.Slug, &t.Subject, &t.HTMLBody, &t.TextBody,
		&t.Category, &t.Variables, &t.Enabled, &t.UpdatedBy, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
		return
	}
	c.JSON(http.StatusOK, t)
}

func (s *Service) handleUpdateEmailTemplate(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var req struct {
		Subject  *string `json:"subject"`
		HTMLBody *string `json:"html_body"`
		TextBody *string `json:"text_body"`
		Enabled  *bool   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	// Build dynamic update
	sets := []string{"updated_at = NOW()"}
	args := []interface{}{}
	argIdx := 1

	if req.Subject != nil {
		sets = append(sets, fmt.Sprintf("subject = $%d", argIdx))
		args = append(args, *req.Subject)
		argIdx++
	}
	if req.HTMLBody != nil {
		sets = append(sets, fmt.Sprintf("html_body = $%d", argIdx))
		args = append(args, *req.HTMLBody)
		argIdx++
	}
	if req.TextBody != nil {
		sets = append(sets, fmt.Sprintf("text_body = $%d", argIdx))
		args = append(args, *req.TextBody)
		argIdx++
	}
	if req.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled = $%d", argIdx))
		args = append(args, *req.Enabled)
		argIdx++
	}

	if userIDStr != "" {
		sets = append(sets, fmt.Sprintf("updated_by = $%d", argIdx))
		args = append(args, userIDStr)
		argIdx++
	}

	args = append(args, id)
	query := fmt.Sprintf("UPDATE email_templates SET %s WHERE id = $%d", strings.Join(sets, ", "), argIdx)

	tag, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		s.logger.Error("Failed to update email template", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update template"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Template updated"})
}

func (s *Service) handlePreviewEmailTemplate(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var htmlBody string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT html_body FROM email_templates WHERE id = $1", id).Scan(&htmlBody)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
		return
	}

	// Sample data for preview
	sampleData := map[string]string{
		"FirstName":    "John",
		"LastName":     "Doe",
		"Username":     "jdoe",
		"Email":        "jdoe@example.com",
		"LoginURL":     "https://app.openidx.io/login",
		"ResetLink":    "https://app.openidx.io/reset?token=sample",
		"VerifyLink":   "https://app.openidx.io/verify?token=sample",
		"InviteLink":   "https://app.openidx.io/invite?token=sample",
		"InviterName":  "Admin User",
		"ExpiryDate":   time.Now().Add(72 * time.Hour).Format("January 2, 2006"),
		"ExpiryMinutes": "15",
		"OTPCode":      "123456",
	}

	tmpl, err := template.New("preview").Parse(htmlBody)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid template syntax", "details": err.Error()})
		return
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, sampleData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Template execution error", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"html": buf.String()})
}

func (s *Service) handleResetEmailTemplate(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var slug string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		"SELECT slug FROM email_templates WHERE id = $1", id).Scan(&slug)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
		return
	}

	defaults := map[string]struct{ Subject, HTML, Text string }{
		"welcome": {
			Subject: "Welcome to OpenIDX",
			HTML:    `<html><body><h1>Welcome, {{.FirstName}}!</h1><p>Your account has been created. You can now log in at <a href="{{.LoginURL}}">{{.LoginURL}}</a>.</p><p>Username: {{.Username}}</p></body></html>`,
			Text:    "Welcome, {{.FirstName}}! Your account has been created. Log in at {{.LoginURL}}. Username: {{.Username}}",
		},
		"password-reset": {
			Subject: "Reset Your Password",
			HTML:    `<html><body><h1>Password Reset</h1><p>Hi {{.FirstName}}, click the link below to reset your password:</p><p><a href="{{.ResetLink}}">Reset Password</a></p><p>This link expires in {{.ExpiryMinutes}} minutes.</p></body></html>`,
			Text:    "Hi {{.FirstName}}, reset your password: {{.ResetLink}} (expires in {{.ExpiryMinutes}} minutes)",
		},
		"invitation": {
			Subject: "You are Invited to OpenIDX",
			HTML:    `<html><body><h1>You are Invited!</h1><p>{{.InviterName}} has invited you to join OpenIDX.</p><p><a href="{{.InviteLink}}">Accept Invitation</a></p><p>This invitation expires on {{.ExpiryDate}}.</p></body></html>`,
			Text:    "{{.InviterName}} has invited you to join OpenIDX. Accept: {{.InviteLink}} (expires {{.ExpiryDate}})",
		},
		"verification": {
			Subject: "Verify Your Email",
			HTML:    `<html><body><h1>Verify Your Email</h1><p>Hi {{.FirstName}}, please verify your email address by clicking the link below:</p><p><a href="{{.VerifyLink}}">Verify Email</a></p></body></html>`,
			Text:    "Hi {{.FirstName}}, verify your email: {{.VerifyLink}}",
		},
		"otp": {
			Subject: "Your One-Time Password",
			HTML:    `<html><body><h1>Your OTP Code</h1><p>Your one-time password is: <strong>{{.OTPCode}}</strong></p><p>This code expires in {{.ExpiryMinutes}} minutes. Do not share this code with anyone.</p></body></html>`,
			Text:    "Your OTP code is: {{.OTPCode}}. Expires in {{.ExpiryMinutes}} minutes.",
		},
	}

	def, ok := defaults[slug]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No default available for this template"})
		return
	}

	_, err = s.db.Pool.Exec(c.Request.Context(),
		"UPDATE email_templates SET subject = $1, html_body = $2, text_body = $3, updated_at = NOW() WHERE id = $4",
		def.Subject, def.HTML, def.Text, id)
	if err != nil {
		s.logger.Error("Failed to reset email template", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset template"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Template reset to default"})
}

func (s *Service) handleGetEmailBranding(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var b EmailBranding
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, org_id, logo_url, primary_color, accent_color, header_text, footer_text, created_at, updated_at
		 FROM email_branding ORDER BY created_at LIMIT 1`,
	).Scan(&b.ID, &b.OrgID, &b.LogoURL, &b.PrimaryColor, &b.AccentColor, &b.HeaderText, &b.FooterText, &b.CreatedAt, &b.UpdatedAt)
	if err != nil {
		// Return defaults if no branding exists
		c.JSON(http.StatusOK, EmailBranding{
			PrimaryColor: "#1e40af",
			AccentColor:  "#3b82f6",
			HeaderText:   "OpenIDX",
			FooterText:   "Powered by OpenIDX - Open Source Zero Trust Access Platform",
		})
		return
	}
	c.JSON(http.StatusOK, b)
}

func (s *Service) handleUpdateEmailBranding(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		LogoURL      string `json:"logo_url"`
		PrimaryColor string `json:"primary_color"`
		AccentColor  string `json:"accent_color"`
		HeaderText   string `json:"header_text"`
		FooterText   string `json:"footer_text"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	_, err := s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO email_branding (org_id, logo_url, primary_color, accent_color, header_text, footer_text)
		 VALUES ((SELECT id FROM organizations LIMIT 1), $1, $2, $3, $4, $5)
		 ON CONFLICT (org_id) DO UPDATE SET
		   logo_url = EXCLUDED.logo_url, primary_color = EXCLUDED.primary_color,
		   accent_color = EXCLUDED.accent_color, header_text = EXCLUDED.header_text,
		   footer_text = EXCLUDED.footer_text, updated_at = NOW()`,
		req.LogoURL, req.PrimaryColor, req.AccentColor, req.HeaderText, req.FooterText)
	if err != nil {
		s.logger.Error("Failed to update email branding", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update branding"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Branding updated"})
}

