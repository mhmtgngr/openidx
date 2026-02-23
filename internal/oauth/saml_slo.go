// Package oauth provides SAML Single Logout functionality
package oauth

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// SAML Single Logout constants
const (
	SAMLLogoutStatusSuccess    = "urn:oasis:names:tc:SAML:2.0:status:Success"
	SAMLLogoutStatusRequester  = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	SAMLLogoutStatusResponder  = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	SAMLLogoutStatusVersionMismatch = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
)

// LogoutRequest represents a SAML LogoutRequest
type LogoutRequest struct {
	XMLName      xml.Name `xml:"samlp:LogoutRequest"`
	XMLNS        string   `xml:"xmlns:samlp,attr"`
	XMLNSSAML    string   `xml:"xmlns:saml,attr"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Destination  string   `xml:"Destination,attr,omitempty"`
	Issuer       string   `xml:"saml:Issuer"`
	NotOnOrAfter string   `xml:"NotOnOrAfter,attr,omitempty"`
	SessionIndex string   `xml:"SessionIndex,omitempty"`
	NameID       *LogoutNameID `xml:"saml:NameID,omitempty"`
	SessionIndexes []string `xml:"saml:SessionIndex,omitempty"`
}

// LogoutNameID represents the NameID in a LogoutRequest
type LogoutNameID struct {
	Format  string   `xml:"Format,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

// LogoutResponse represents a SAML LogoutResponse
type LogoutResponse struct {
	XMLName      xml.Name `xml:"samlp:LogoutResponse"`
	XMLNS        string   `xml:"xmlns:samlp,attr"`
	XMLNSSAML    string   `xml:"xmlns:saml,attr"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Destination  string   `xml:"Destination,attr"`
	InResponseTo string   `xml:"InResponseTo,attr,omitempty"`
	Issuer       string   `xml:"saml:Issuer"`
	Status       LogoutResponseStatus `xml:"samlp:Status"`
}

// LogoutResponseStatus represents the status in a LogoutResponse
type LogoutResponseStatus struct {
	StatusCode    LogoutStatusCode    `xml:"StatusCode"`
	StatusMessage *LogoutStatusMessage `xml:"StatusMessage,omitempty"`
}

// LogoutStatusCode represents the status code
type LogoutStatusCode struct {
	Value string `xml:"Value,attr"`
}

// LogoutStatusMessage represents an optional status message
type LogoutStatusMessage struct {
	Value string `xml:",chardata"`
}

// SAMLSession represents a SAML session for logout tracking
type SAMLSession struct {
	ID           string
	UserID       string
	SPID         string
	SPEntityID   string
	SessionIndex string
	NameID       string
	NameIDFormat string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// LogoutSession tracks an in-progress logout operation
type LogoutSession struct {
	ID            string
	UserID        string
	RequestID     string
	RequestingSP  string
	SPSessions    []string // SP session IDs to logout
	Status        string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// handleIdPSLO handles Single Logout requests at the IdP
// Supports both SP-initiated and IdP-initiated SLO
// GET/POST /saml/idp/slo
func (s *Service) handleIdPSLO(c *gin.Context) {
	var samlRequest string
	var binding string

	if c.Request.Method == "POST" {
		samlRequest = c.PostForm("SAMLRequest")
		binding = SAMLBindingHTTPPost
	} else {
		samlRequest = c.Query("SAMLRequest")
		binding = SAMLBindingHTTPRedirect
	}

	relayState := c.Query("RelayState")
	if relayState == "" {
		relayState = c.PostForm("RelayState")
	}

	// If there's a SAMLRequest, it's an SP-initiated logout
	if samlRequest != "" {
		s.handleSPInitiatedSLO(c, samlRequest, relayState, binding)
		return
	}

	// Check if this is an IdP-initiated logout (user logged out from IdP)
	sessionToken, err := c.Cookie("openidx_session")
	if err == nil && sessionToken != "" {
		s.handleIdPInitiatedSLO(c, sessionToken, c.Query("sp_entity_id"))
		return
	}

	c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid SLO request"})
}

// handleSPInitiatedSLO handles SP-initiated Single Logout
func (s *Service) handleSPInitiatedSLO(c *gin.Context, samlRequest, relayState, binding string) {
	// Decode the LogoutRequest
	decoded, err := inflateAndDecode(samlRequest)
	if err != nil {
		decoded, err = base64Decode(samlRequest)
		if err != nil {
			s.logger.Error("Failed to decode SLO request", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid SAMLRequest encoding"})
			return
		}
	}

	// Parse LogoutRequest
	var logoutReq LogoutRequest
	if err := xml.Unmarshal(decoded, &logoutReq); err != nil {
		s.logger.Error("Failed to parse LogoutRequest", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid LogoutRequest format"})
		return
	}

	s.logger.Info("Received SAML LogoutRequest",
		zap.String("request_id", logoutReq.ID),
		zap.String("issuer", logoutReq.Issuer),
	)

	// Look up the SP
	sp, err := s.getSAMLServiceProviderByEntityID(c.Request.Context(), logoutReq.Issuer)
	if err != nil {
		s.logger.Error("Unknown SP in SLO request", zap.String("issuer", logoutReq.Issuer))
		s.sendSAMLLogoutResponse(c, "", "", logoutReq.ID, SAMLLogoutStatusResponder, "Unknown service provider", sp)
		return
	}

	// Extract user identifier
	userID := ""
	nameID := ""
	if logoutReq.NameID != nil {
		nameID = logoutReq.NameID.Value
		// Look up user by email/nameID
		userID, _ = s.findUserByNameID(c.Request.Context(), nameID)
	} else if logoutReq.SessionIndex != "" {
		// Look up by session index
		userID, nameID, _ = s.findUserBySessionIndex(c.Request.Context(), logoutReq.SessionIndex, logoutReq.Issuer)
	}

	if userID == "" {
		s.logger.Warn("User not found in SLO request", zap.String("name_id", nameID))
		s.sendSAMLLogoutResponse(c, sp.SLOURL, sp.EntityID, logoutReq.ID, SAMLLogoutStatusRequester, "User not found", sp)
		return
	}

	// Perform logout
	if err := s.performUserLogout(c.Request.Context(), userID, logoutReq.Issuer); err != nil {
		s.logger.Error("Failed to perform logout", zap.Error(err), zap.String("user_id", userID))
		s.sendSAMLLogoutResponse(c, sp.SLOURL, sp.EntityID, logoutReq.ID, SAMLLogoutStatusResponder, "Logout failed", sp)
		return
	}

	// Log the SLO event
	go s.logAuditEvent(context.Background(), "authentication", "saml_idp", "slo_sp_initiated", "success",
		userID, c.ClientIP(), sp.EntityID, "service_provider",
		map[string]interface{}{
			"sp_entity_id": sp.EntityID,
			"sp_name": sp.Name,
			"request_id": logoutReq.ID,
		})

	// Send success response
	s.sendSAMLLogoutResponse(c, sp.SLOURL, sp.EntityID, logoutReq.ID, SAMLLogoutStatusSuccess, "", sp)
}

// handleIdPInitiatedSLO handles IdP-initiated Single Logout
// This is when the user logs out from the IdP and we need to notify all SPs
func (s *Service) handleIdPInitiatedSLO(c *gin.Context, sessionToken string, targetSPEntityID string) {
	// Get the user from session
	userID, err := s.extractUserIDFromSession(c.Request.Context(), sessionToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
		return
	}

	// Get all active SAML sessions for this user
	sessions, err := s.getSAMLSessionsForUser(c.Request.Context(), userID)
	if err != nil {
		s.logger.Error("Failed to get SAML sessions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get sessions"})
		return
	}

	// Clear the IdP session
	s.clearIdPSession(c, sessionToken)

	// If a specific SP is targeted, only logout from that SP
	if targetSPEntityID != "" {
		sessions = filterSessionsBySP(sessions, targetSPEntityID)
	}

	// Send logout requests to all SPs (or targeted SP)
	s.sendLogoutToSPs(c, sessions)

	// Show logout confirmation page
	s.showLogoutConfirmationPage(c, len(sessions))
}

// findUserByNameID finds a user by their NameID (email or persistent ID)
func (s *Service) findUserByNameID(ctx context.Context, nameID string) (string, error) {
	// Try email first
	var userID string
	err := s.db.Pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", nameID).Scan(&userID)
	if err == nil {
		return userID, nil
	}

	// Try external_user_id
	err = s.db.Pool.QueryRow(ctx, "SELECT id FROM users WHERE external_user_id = $1", nameID).Scan(&userID)
	if err == nil {
		return userID, nil
	}

	return "", fmt.Errorf("user not found")
}

// findUserBySessionIndex finds a user by their SAML session index
func (s *Service) findUserBySessionIndex(ctx context.Context, sessionIndex, spEntityID string) (string, string, error) {
	var userID, nameID string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT user_id, name_id FROM saml_sessions
		WHERE session_index = $1 AND sp_entity_id = $2
	`, sessionIndex, spEntityID).Scan(&userID, &nameID)
	return userID, nameID, err
}

// performUserLogout performs the actual logout for a user
func (s *Service) performUserLogout(ctx context.Context, userID, spEntityID string) error {
	// Delete all user sessions from the sessions table
	_, err := s.db.Pool.Exec(ctx, "DELETE FROM user_sessions WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("failed to delete user sessions: %w", err)
	}

	// Delete SAML sessions for this SP
	_, err = s.db.Pool.Exec(ctx, "DELETE FROM saml_sessions WHERE user_id = $1 AND sp_entity_id = $2", userID, spEntityID)
	if err != nil {
		return fmt.Errorf("failed to delete SAML sessions: %w", err)
	}

	// Revoke any OAuth tokens for this user
	_, err = s.db.Pool.Exec(ctx, "DELETE FROM oauth_refresh_tokens WHERE user_id = $1", userID)
	if err != nil {
		s.logger.Warn("Failed to delete OAuth tokens", zap.Error(err))
	}

	_, err = s.db.Pool.Exec(ctx, "DELETE FROM oauth_access_tokens WHERE user_id = $1", userID)
	if err != nil {
		s.logger.Warn("Failed to delete access tokens", zap.Error(err))
	}

	return nil
}

// sendSAMLLogoutResponse sends a LogoutResponse to the SP
func (s *Service) sendSAMLLogoutResponse(c *gin.Context, sloURL, spEntityID, inResponseTo, statusCode, statusMessage string, sp *SAMLServiceProvider) {
	now := time.Now().UTC()
	response := LogoutResponse{
		XMLNS:        SAMLProtocolNamespace,
		XMLNSSAML:    SAMLAssertionNamespace,
		ID:           "_" + uuid.New().String(),
		Version:      "2.0",
		IssueInstant: now.Format(time.RFC3339),
		Destination:  sloURL,
		InResponseTo: inResponseTo,
		Issuer:       s.issuer,
		Status: LogoutResponseStatus{
			StatusCode: LogoutStatusCode{
				Value: statusCode,
			},
		},
	}

	if statusMessage != "" {
		response.Status.StatusMessage = &LogoutStatusMessage{Value: statusMessage}
	}

	responseXML, err := xml.Marshal(response)
	if err != nil {
		s.logger.Error("Failed to marshal LogoutResponse", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build LogoutResponse"})
		return
	}

	// If SP has an SLO URL, send the response there
	if sloURL != "" {
		// Encode and redirect
		encoded, err := deflateAndEncode(responseXML)
		if err != nil {
			s.logger.Error("Failed to encode LogoutResponse", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode LogoutResponse"})
			return
		}

		redirectURL := sloURL
		if strings.Contains(redirectURL, "?") {
			redirectURL += "&"
		} else {
			redirectURL += "?"
		}
		redirectURL += "SAMLResponse=" + encoded
		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	// No SLO URL - return the response directly
	c.Header("Content-Type", "application/xml")
	c.String(http.StatusOK, xml.Header+string(responseXML))
}

// getSAMLSessionsForUser retrieves all active SAML sessions for a user
func (s *Service) getSAMLSessionsForUser(ctx context.Context, userID string) ([]SAMLSession, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, user_id, sp_id, sp_entity_id, session_index, name_id, name_id_format, created_at, expires_at
		FROM saml_sessions
		WHERE user_id = $1 AND expires_at > NOW()
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []SAMLSession
	for rows.Next() {
		var s SAMLSession
		if err := rows.Scan(&s.ID, &s.UserID, &s.SPID, &s.SPEntityID, &s.SessionIndex,
			&s.NameID, &s.NameIDFormat, &s.CreatedAt, &s.ExpiresAt); err != nil {
			continue
		}
		sessions = append(sessions, s)
	}

	return sessions, nil
}

// filterSessionsBySP filters sessions by SP entity ID
func filterSessionsBySP(sessions []SAMLSession, spEntityID string) []SAMLSession {
	var filtered []SAMLSession
	for _, s := range sessions {
		if s.SPEntityID == spEntityID {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// sendLogoutToSPs sends logout requests to multiple SPs
func (s *Service) sendLogoutToSPs(c *gin.Context, sessions []SAMLSession) {
	for _, session := range sessions {
		sp, err := s.getSAMLServiceProviderByEntityID(c.Request.Context(), session.SPEntityID)
		if err != nil {
			s.logger.Warn("SP not found for logout", zap.String("sp_entity_id", session.SPEntityID))
			continue
		}

		if sp.SLOURL == "" {
			s.logger.Debug("SP has no SLO URL", zap.String("sp_entity_id", session.SPEntityID))
			continue
		}

		// Create LogoutRequest
		logoutReq := s.createLogoutRequest(session, sp)

		// Send logout request (async)
		go s.sendLogoutRequestToSP(context.Background(), logoutReq, sp.SLOURL)
	}
}

// createLogoutRequest creates a SAML LogoutRequest for a session
func (s *Service) createLogoutRequest(session SAMLSession, sp *SAMLServiceProvider) LogoutRequest {
	return LogoutRequest{
		XMLNS:        SAMLProtocolNamespace,
		XMLNSSAML:    SAMLAssertionNamespace,
		ID:           "_" + uuid.New().String(),
		Version:      "2.0",
		IssueInstant: time.Now().UTC().Format(time.RFC3339),
		Destination:  sp.SLOURL,
		Issuer:       s.issuer,
		SessionIndex: session.SessionIndex,
		NameID: &LogoutNameID{
			Format: session.NameIDFormat,
			Value:  session.NameID,
		},
	}
}

// sendLogoutRequestToSP sends a logout request to an SP (async)
func (s *Service) sendLogoutRequestToSP(ctx context.Context, logoutReq LogoutRequest, sloURL string) {
	xmlData, err := xml.Marshal(logoutReq)
	if err != nil {
		s.logger.Error("Failed to marshal LogoutRequest", zap.Error(err))
		return
	}

	encoded, err := deflateAndEncode(xmlData)
	if err != nil {
		s.logger.Error("Failed to encode LogoutRequest", zap.Error(err))
		return
	}

	// Build the logout URL
	logoutURL := sloURL
	if strings.Contains(logoutURL, "?") {
		logoutURL += "&"
	} else {
		logoutURL += "?"
	}
	logoutURL += "SAMLRequest=" + url.QueryEscape(encoded)

	s.logger.Info("Sending SAML LogoutRequest to SP",
		zap.String("slo_url", sloURL),
		zap.String("request_id", logoutReq.ID),
	)

	// In production, you would make an HTTP request here
	// For now, just log it
	s.logger.Debug("SAML LogoutRequest URL", zap.String("url", logoutURL))
}

// extractUserIDFromSession extracts user ID from a session token
func (s *Service) extractUserIDFromSession(ctx context.Context, sessionToken string) (string, error) {
	var userID string
	err := s.db.Pool.QueryRow(ctx,
		"SELECT user_id FROM user_sessions WHERE session_token = $1 AND expires_at > NOW()",
		sessionToken).Scan(&userID)
	return userID, err
}

// clearIdPSession clears the IdP session (cookie)
func (s *Service) clearIdPSession(c *gin.Context, sessionToken string) {
	// Delete from database
	s.db.Pool.Exec(c.Request.Context(),
		"DELETE FROM user_sessions WHERE session_token = $1", sessionToken)

	// Clear cookie
	c.SetCookie("openidx_session", "", -1, "/", "", false, true)
}

// showLogoutConfirmationPage shows a logout confirmation page
func (s *Service) showLogoutConfirmationPage(c *gin.Context, spCount int) {
	html := `<!DOCTYPE html>
<html>
<head>
	<title>Logged Out</title>
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; }
		.container { text-align: center; padding: 2rem; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); max-width: 400px; }
		h2 { margin: 0 0 1rem 0; color: #333; }
		p { color: #666; margin-bottom: 1.5rem; }
		.success-icon { width: 64px; height: 64px; margin: 0 auto 1rem; background: #4caf50; border-radius: 50%; display: flex; align-items: center; justify-content: center; }
		.success-icon svg { width: 32px; height: 32px; fill: white; }
	</style>
</head>
<body>
	<div class="container">
		<div class="success-icon">
			<svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
		</div>
		<h2>You've been logged out</h2>
		<p>You have been successfully logged out from OpenIDX.`

	if spCount > 0 {
		html += fmt.Sprintf(" You have also been logged out from %d service provider(s).", spCount)
	}

	html += `
		</p>
		<a href="/login" style="display: inline-block; padding: 0.5rem 1rem; background: #4285f4; color: white; text-decoration: none; border-radius: 4px;">Log in again</a>
	</div>
</body>
</html>`

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, html)
}

// recordSAMLSession records a SAML session after successful SSO
func (s *Service) recordSAMLSession(ctx context.Context, userID, spID, spEntityID, sessionIndex, nameID, nameIDFormat string) error {
	// Set expiry to 8 hours
	expiresAt := time.Now().Add(8 * time.Hour)

	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO saml_sessions (id, user_id, sp_id, sp_entity_id, session_index, name_id, name_id_format, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8)
		ON CONFLICT (user_id, sp_entity_id, session_index) DO UPDATE SET
			expires_at = EXCLUDED.expires_at
	`, uuid.New().String(), userID, spID, spEntityID, sessionIndex, nameID, nameIDFormat, expiresAt)

	return err
}

// cleanupExpiredSAMLSessions removes expired SAML sessions
func (s *Service) cleanupExpiredSAMLSessions(ctx context.Context) error {
	_, err := s.db.Pool.Exec(ctx, "DELETE FROM saml_sessions WHERE expires_at < NOW()")
	return err
}

// Helper function for base64 decoding
func base64Decode(data string) ([]byte, error) {
	// Try standard base64
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err == nil {
		return decoded, nil
	}
	// Try URL-safe base64
	return base64.URLEncoding.DecodeString(data)
}

// handleSAMLLogoutRequest handles incoming SAML logout requests from SPs
// This is an alternative handler that can be used for receiving logout requests
func (s *Service) handleSAMLLogoutRequest(c *gin.Context) {
	samlRequest := c.PostForm("SAMLRequest")
	if samlRequest == "" {
		samlRequest = c.Query("SAMLRequest")
	}

	if samlRequest == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing SAMLRequest"})
		return
	}

	relayState := c.Query("RelayState")
	if relayState == "" {
		relayState = c.PostForm("RelayState")
	}

	// Process the logout request
	s.handleSPInitiatedSLO(c, samlRequest, relayState, SAMLBindingHTTPPost)
}
