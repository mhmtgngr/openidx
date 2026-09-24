// Package oauth provides SAML Single Logout functionality
package oauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// samlRedirectSigAlg is the SigAlg URI for RSA-SHA256 under the HTTP-Redirect
// binding (SAML Bindings 3.4.4.1).
const samlRedirectSigAlg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

// SAML Single Logout constants
const (
	SAMLLogoutStatusSuccess         = "urn:oasis:names:tc:SAML:2.0:status:Success"
	SAMLLogoutStatusRequester       = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	SAMLLogoutStatusResponder       = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	SAMLLogoutStatusVersionMismatch = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
)

// How long an inbound LogoutRequest is good for. A LogoutRequest travels
// through the browser straight from the SP to here, so it is seconds old when
// it arrives; the bound is what makes a captured one useless later, and the
// replay record below only has to last as long as a request can be accepted.
const (
	samlMessageClockSkew       = 3 * time.Minute
	samlLogoutRequestMaxAge    = 5 * time.Minute
	samlLogoutReplayRedisTTL   = samlLogoutRequestMaxAge + 2*samlMessageClockSkew
	samlLogoutReplayRedisGroup = "saml_logout_request_seen:"
)

// LogoutRequest is the SAML LogoutRequest this IdP SENDS. The prefixed tags
// are for marshalling only; inboundLogoutRequest below parses what SPs send.
// Child order follows the schema: Issuer, NameID, SessionIndex.
type LogoutRequest struct {
	XMLName      xml.Name      `xml:"samlp:LogoutRequest"`
	XMLNS        string        `xml:"xmlns:samlp,attr"`
	XMLNSSAML    string        `xml:"xmlns:saml,attr"`
	ID           string        `xml:"ID,attr"`
	Version      string        `xml:"Version,attr"`
	IssueInstant string        `xml:"IssueInstant,attr"`
	Destination  string        `xml:"Destination,attr,omitempty"`
	NotOnOrAfter string        `xml:"NotOnOrAfter,attr,omitempty"`
	Issuer       string        `xml:"saml:Issuer"`
	NameID       *LogoutNameID `xml:"saml:NameID,omitempty"`
	SessionIndex string        `xml:"samlp:SessionIndex,omitempty"`
}

// LogoutNameID represents the NameID in a LogoutRequest
type LogoutNameID struct {
	Format string `xml:"Format,attr,omitempty"`
	Value  string `xml:",chardata"`
}

// inboundLogoutRequest parses a LogoutRequest a service provider SENDS.
//
// Its tags name namespace URIs. encoding/xml matches a tag such as
// "samlp:LogoutRequest" against an element's local name, which is never
// "samlp:LogoutRequest", so parsing with the marshalling struct above refused
// every LogoutRequest any SP has ever sent, and SP-initiated Single Logout
// always answered "Invalid LogoutRequest format".
type inboundLogoutRequest struct {
	XMLName        xml.Name      `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
	ID             string        `xml:"ID,attr"`
	Version        string        `xml:"Version,attr"`
	IssueInstant   string        `xml:"IssueInstant,attr"`
	Destination    string        `xml:"Destination,attr"`
	NotOnOrAfter   string        `xml:"NotOnOrAfter,attr"`
	Issuer         string        `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameID         *LogoutNameID `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SessionIndexes []string      `xml:"urn:oasis:names:tc:SAML:2.0:protocol SessionIndex"`
}

// LogoutResponse represents a SAML LogoutResponse
type LogoutResponse struct {
	XMLName      xml.Name             `xml:"samlp:LogoutResponse"`
	XMLNS        string               `xml:"xmlns:samlp,attr"`
	XMLNSSAML    string               `xml:"xmlns:saml,attr"`
	ID           string               `xml:"ID,attr"`
	Version      string               `xml:"Version,attr"`
	IssueInstant string               `xml:"IssueInstant,attr"`
	Destination  string               `xml:"Destination,attr,omitempty"`
	InResponseTo string               `xml:"InResponseTo,attr,omitempty"`
	Issuer       string               `xml:"saml:Issuer"`
	Status       LogoutResponseStatus `xml:"samlp:Status"`
}

// LogoutResponseStatus represents the status in a LogoutResponse. The child
// elements are in the protocol namespace; unprefixed, they were in no
// namespace at all, and an SP looking for samlp:StatusCode found none.
type LogoutResponseStatus struct {
	StatusCode    LogoutStatusCode     `xml:"samlp:StatusCode"`
	StatusMessage *LogoutStatusMessage `xml:"samlp:StatusMessage,omitempty"`
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
	ID           string
	UserID       string
	RequestID    string
	RequestingSP string
	SPSessions   []string // SP session IDs to logout
	Status       string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// handleIdPSLO handles Single Logout requests at the IdP
// Supports both SP-initiated and IdP-initiated SLO
// GET/POST /saml/idp/slo
func (s *Service) handleIdPSLO(c *gin.Context) {
	// If there's a SAMLRequest, it's an SP-initiated logout
	msg, err := readSAMLInbound(c, "SAMLRequest")
	if err == nil {
		s.handleSPInitiatedSLO(c, msg)
		return
	}
	if !errors.Is(err, errSAMLMessageMissing) {
		s.logger.Warn("Failed to decode SLO request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid SAMLRequest encoding"})
		return
	}

	// A LogoutResponse is an SP answering a logout this IdP started. The
	// dispatch goes over the back channel and reads the answer there, so one
	// arriving through the browser has nothing left to complete: say so.
	if c.Query("SAMLResponse") != "" || c.PostForm("SAMLResponse") != "" {
		s.showLogoutConfirmationPage(c, 0)
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

// handleSPInitiatedSLO handles SP-initiated Single Logout.
//
// A LogoutRequest ends sessions, so before it is acted on it has to be shown
// to come from the service provider it names, to be addressed here, to be
// recent and to be seen for the first time. SAML Profiles 4.4.4.1 requires the
// requester to authenticate its LogoutRequest; over the browser bindings that
// means a signature, so one without a signature that verifies against the
// SP's registered certificate is refused, whichever binding carried it.
func (s *Service) handleSPInitiatedSLO(c *gin.Context, msg *samlInbound) {
	ctx := c.Request.Context()

	var logoutReq inboundLogoutRequest
	if err := xml.Unmarshal(msg.xml, &logoutReq); err != nil {
		s.logger.Warn("Failed to parse LogoutRequest", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid LogoutRequest format"})
		return
	}
	if logoutReq.ID == "" || logoutReq.Issuer == "" || logoutReq.Version != "2.0" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid LogoutRequest format"})
		return
	}

	s.logger.Info("Received SAML LogoutRequest",
		zap.String("request_id", logoutReq.ID),
		zap.String("issuer", logoutReq.Issuer),
	)

	refuse := func(sp *SAMLServiceProvider, status int, reason, message string) {
		entityID := logoutReq.Issuer
		if sp != nil {
			entityID = sp.EntityID
		}
		s.logAuditEvent(ctx, "authentication", "saml_idp", "slo_sp_initiated", "failure",
			"", c.ClientIP(), entityID, "service_provider",
			map[string]interface{}{"reason": reason, "sp_entity_id": entityID, "request_id": logoutReq.ID})
		c.JSON(status, gin.H{"error": message})
	}

	sp, err := s.getSAMLServiceProviderByEntityID(ctx, logoutReq.Issuer)
	if err != nil {
		refuse(nil, http.StatusBadRequest, "unknown_service_provider", "Unknown service provider")
		return
	}
	if !sp.Enabled {
		refuse(sp, http.StatusForbidden, "sp_disabled", "Service provider is disabled")
		return
	}

	state, verr := verifyInboundSignature(msg, sp)
	if verr != nil {
		s.logger.Warn("LogoutRequest signature verification failed",
			zap.String("sp_entity_id", sp.EntityID), zap.Error(verr))
		refuse(sp, http.StatusBadRequest, "logout_request_signature_invalid", "LogoutRequest signature verification failed")
		return
	}
	if state != messageSigned {
		refuse(sp, http.StatusBadRequest, "logout_request_unsigned", "LogoutRequest must be signed")
		return
	}

	if logoutReq.Destination != "" && !s.isOwnSLOEndpoint(c, logoutReq.Destination) {
		refuse(sp, http.StatusBadRequest, "logout_request_wrong_destination", "LogoutRequest is addressed to another endpoint")
		return
	}

	if ferr := checkLogoutRequestFreshness(logoutReq.IssueInstant, logoutReq.NotOnOrAfter, time.Now()); ferr != nil {
		s.logger.Warn("Stale LogoutRequest", zap.String("sp_entity_id", sp.EntityID), zap.Error(ferr))
		refuse(sp, http.StatusBadRequest, "logout_request_expired", "LogoutRequest has expired")
		return
	}

	// Last, so a request refused for any reason above does not use up its ID.
	if rerr := s.claimLogoutRequestID(ctx, sp.EntityID, logoutReq.ID); rerr != nil {
		if errors.Is(rerr, errSAMLMessageReplayed) {
			refuse(sp, http.StatusBadRequest, "logout_request_replayed", "LogoutRequest has already been processed")
			return
		}
		s.logger.Error("Could not record the LogoutRequest ID; refusing rather than accept a possible replay", zap.Error(rerr))
		refuse(sp, http.StatusServiceUnavailable, "replay_store_unavailable", "Logout is temporarily unavailable")
		return
	}

	nameID := ""
	if logoutReq.NameID != nil {
		nameID = strings.TrimSpace(logoutReq.NameID.Value)
	}
	if nameID == "" && len(logoutReq.SessionIndexes) == 0 {
		s.sendSAMLLogoutResponse(c, sp, logoutReq.ID, SAMLLogoutStatusRequester, "The LogoutRequest names no subject", msg.relayState)
		return
	}

	subjects, err := s.findLogoutSubjects(ctx, sp.EntityID, nameID, logoutReq.SessionIndexes)
	if err != nil {
		s.logger.Error("Failed to resolve the sessions a LogoutRequest names", zap.Error(err))
		s.sendSAMLLogoutResponse(c, sp, logoutReq.ID, SAMLLogoutStatusResponder, "Logout failed", msg.relayState)
		return
	}

	// No matching session is not an error: the principal has no session with
	// this SP here, which is the state a logout asks for.
	for _, subject := range subjects {
		subjectCtx := orgctx.With(ctx, orgctx.Org{ID: subject.orgID})
		if err := s.performUserLogout(subjectCtx, subject.userID, sp.EntityID); err != nil {
			s.logger.Error("Failed to perform logout", zap.Error(err), zap.String("user_id", subject.userID))
			s.sendSAMLLogoutResponse(c, sp, logoutReq.ID, SAMLLogoutStatusResponder, "Logout failed", msg.relayState)
			return
		}
		userID := subject.userID
		go func() {
			bg, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.logAuditEvent(orgctx.With(bg, orgctx.Org{ID: subject.orgID}), "authentication", "saml_idp", "slo_sp_initiated", "success",
				userID, c.ClientIP(), sp.EntityID, "service_provider",
				map[string]interface{}{
					"sp_entity_id": sp.EntityID,
					"sp_name":      sp.Name,
					"request_id":   logoutReq.ID,
				})
		}()
	}

	s.sendSAMLLogoutResponse(c, sp, logoutReq.ID, SAMLLogoutStatusSuccess, "", msg.relayState)
}

// isOwnSLOEndpoint reports whether destination is this IdP's Single Logout
// endpoint, as published in its metadata for this host or under its issuer.
func (s *Service) isOwnSLOEndpoint(c *gin.Context, destination string) bool {
	for _, base := range []string{s.getBaseURL(c), s.issuer} {
		if base != "" && destination == strings.TrimRight(base, "/")+"/saml/idp/slo" {
			return true
		}
	}
	return false
}

// checkLogoutRequestFreshness refuses a LogoutRequest that was issued too long
// ago, claims to be issued in the future, or is past its own NotOnOrAfter.
// The errors say which test failed and do not quote the timestamps: both are
// the sender's text, and the error reaches the log through zap.Error.
func checkLogoutRequestFreshness(issueInstant, notOnOrAfter string, now time.Time) error {
	issued, err := time.Parse(time.RFC3339, strings.TrimSpace(issueInstant))
	if err != nil {
		return fmt.Errorf("IssueInstant is not a dateTime")
	}
	if issued.After(now.Add(samlMessageClockSkew)) {
		return fmt.Errorf("IssueInstant is in the future")
	}
	if now.Sub(issued) > samlLogoutRequestMaxAge+samlMessageClockSkew {
		return fmt.Errorf("IssueInstant is older than %s", samlLogoutRequestMaxAge)
	}
	if strings.TrimSpace(notOnOrAfter) != "" {
		limit, err := time.Parse(time.RFC3339, strings.TrimSpace(notOnOrAfter))
		if err != nil {
			return fmt.Errorf("NotOnOrAfter is not a dateTime")
		}
		if !now.Before(limit.Add(samlMessageClockSkew)) {
			return fmt.Errorf("past its NotOnOrAfter")
		}
	}
	return nil
}

// errSAMLMessageReplayed reports a LogoutRequest ID already processed.
var errSAMLMessageReplayed = errors.New("SAML message already processed")

// claimLogoutRequestID records that the LogoutRequest ID from this SP has been
// acted on, and fails if it already was. The record outlives the freshness
// window, so a request cannot be replayed while it would still be accepted.
func (s *Service) claimLogoutRequestID(ctx context.Context, spEntityID, requestID string) error {
	if s.redis == nil || s.redis.Client == nil {
		return fmt.Errorf("no replay store configured")
	}
	sum := sha256.Sum256([]byte(spEntityID + "\x00" + requestID))
	fresh, err := s.redis.Client.SetNX(ctx, samlLogoutReplayRedisGroup+hex.EncodeToString(sum[:]), "1", samlLogoutReplayRedisTTL).Result()
	if err != nil {
		return err
	}
	if !fresh {
		return errSAMLMessageReplayed
	}
	return nil
}

// logoutSubject is a user a LogoutRequest names, with the tenant the session
// was recorded under.
type logoutSubject struct {
	userID string
	orgID  string
}

// findLogoutSubjects resolves the users whose sessions with spEntityID a
// verified LogoutRequest names. The request may name SessionIndexes, a NameID,
// or both; what it names must be a session this IdP recorded for this SP when
// it issued the assertion, so an SP can only end sessions it was part of.
//
// PRE-TENANT-RESOLUTION, like the entity-id lookup in saml_sp.go: an inbound
// LogoutRequest names a session and an SP, and the session this finds is what
// identifies the user and, through the user, the tenant.
func (s *Service) findLogoutSubjects(ctx context.Context, spEntityID, nameID string, sessionIndexes []string) ([]logoutSubject, error) {
	if sessionIndexes == nil {
		sessionIndexes = []string{}
	}
	//orgscope:ignore pre-tenant-resolution lookup: an inbound SAML LogoutRequest names only a session index or NameID and an SP entity id, and this is the query that resolves which user (and so which org) it belongs to
	rows, err := s.db.Pool.Query(orgctx.WithBypassRLS(ctx), `
		SELECT DISTINCT user_id::text, org_id::text FROM saml_sessions
		 WHERE sp_entity_id = $1
		   AND (cardinality($2::text[]) = 0 OR session_index = ANY($2::text[]))
		   AND ($3 = '' OR name_id = $3)
	`, spEntityID, sessionIndexes, nameID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []logoutSubject
	for rows.Next() {
		var subject logoutSubject
		if err := rows.Scan(&subject.userID, &subject.orgID); err != nil {
			return nil, err
		}
		out = append(out, subject)
	}
	return out, rows.Err()
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

	// Clear the IdP session. Everything after this point tells the user and the
	// SPs that the session is over, so none of it may run when it is not.
	if err := s.clearIdPSession(c, sessionToken); err != nil {
		s.logger.Error("IdP-initiated logout could not end the session", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to end session"})
		return
	}

	// If a specific SP is targeted, only logout from that SP
	if targetSPEntityID != "" {
		sessions = filterSessionsBySP(sessions, targetSPEntityID)
	}

	// Send logout requests to all SPs (or targeted SP)
	s.sendLogoutToSPs(c, sessions)

	// The SAML sessions just dispatched are over; their records would only
	// make a later logout notify an SP about a session it no longer has.
	s.forgetSAMLSessions(c.Request.Context(), sessions)

	// Show logout confirmation page
	s.showLogoutConfirmationPage(c, len(sessions))
}

// forgetSAMLSessions deletes the records of SAML sessions that have ended.
// Best-effort: a record left behind costs one LogoutRequest to an SP that no
// longer knows the session, never a live session.
func (s *Service) forgetSAMLSessions(ctx context.Context, sessions []SAMLSession) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return
	}
	for _, session := range sessions {
		if _, err := s.db.Pool.Exec(ctx,
			"DELETE FROM saml_sessions WHERE id = $1 AND org_id = $2", session.ID, org.ID); err != nil {
			s.logger.Warn("Failed to delete an ended SAML session record",
				zap.String("sp_entity_id", session.SPEntityID), zap.Error(err))
		}
	}
}

// performUserLogout performs the actual logout for a user
func (s *Service) performUserLogout(ctx context.Context, userID, spEntityID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Delete all user sessions from the sessions table
	_, err = s.db.Pool.Exec(ctx, "DELETE FROM user_sessions WHERE user_id = $1 AND org_id = $2", userID, org.ID)
	if err != nil {
		return fmt.Errorf("failed to delete user sessions: %w", err)
	}

	// Delete SAML sessions for this SP
	_, err = s.db.Pool.Exec(ctx,
		"DELETE FROM saml_sessions WHERE user_id = $1 AND sp_entity_id = $2 AND org_id = $3",
		userID, spEntityID, org.ID)
	if err != nil {
		return fmt.Errorf("failed to delete SAML sessions: %w", err)
	}

	// Revoke any OAuth tokens for this user
	_, err = s.db.Pool.Exec(ctx, "DELETE FROM oauth_refresh_tokens WHERE user_id = $1 AND org_id = $2", userID, org.ID)
	if err != nil {
		s.logger.Warn("Failed to delete OAuth tokens", zap.Error(err))
	}

	_, err = s.db.Pool.Exec(ctx, "DELETE FROM oauth_access_tokens WHERE user_id = $1 AND org_id = $2", userID, org.ID)
	if err != nil {
		s.logger.Warn("Failed to delete access tokens", zap.Error(err))
	}

	return nil
}

// sendSAMLLogoutResponse answers a LogoutRequest from sp. It goes back to the
// SP's Single Logout URL over the HTTP-Redirect binding, signed (SAML
// Bindings 3.4.4.1) because an SP that validates logout messages refuses an
// unsigned one, with the RelayState the request carried.
func (s *Service) sendSAMLLogoutResponse(c *gin.Context, sp *SAMLServiceProvider, inResponseTo, statusCode, statusMessage, relayState string) {
	now := time.Now().UTC()
	response := LogoutResponse{
		XMLNS:        SAMLProtocolNamespace,
		XMLNSSAML:    SAMLAssertionNamespace,
		ID:           "_" + uuid.New().String(),
		Version:      "2.0",
		IssueInstant: now.Format(time.RFC3339),
		Destination:  sp.SLOURL,
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

	// No SLO URL - return the response directly
	if sp.SLOURL == "" {
		c.Header("Content-Type", "application/xml")
		c.String(http.StatusOK, xml.Header+string(responseXML))
		return
	}

	encoded, err := deflateAndEncode(responseXML)
	if err != nil {
		s.logger.Error("Failed to encode LogoutResponse", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode LogoutResponse"})
		return
	}

	// The signature covers exactly the encoded query as sent, in this
	// parameter order -- re-encoding or reordering breaks verification.
	query := "SAMLResponse=" + url.QueryEscape(encoded)
	if relayState != "" {
		query += "&RelayState=" + url.QueryEscape(relayState)
	}
	query += "&SigAlg=" + url.QueryEscape(samlRedirectSigAlg)
	sig, err := s.signRedirectBinding(query)
	if err != nil {
		s.logger.Error("Failed to sign LogoutResponse", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign LogoutResponse"})
		return
	}
	query += "&Signature=" + url.QueryEscape(sig)

	sep := "?"
	if strings.Contains(sp.SLOURL, "?") {
		sep = "&"
	}
	c.Redirect(http.StatusFound, sp.SLOURL+sep+query)
}

// getSAMLSessionsForUser retrieves all active SAML sessions for a user
func (s *Service) getSAMLSessionsForUser(ctx context.Context, userID string) ([]SAMLSession, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id, user_id, sp_id, sp_entity_id, session_index, name_id, name_id_format, created_at, expires_at
		FROM saml_sessions
		WHERE user_id = $1 AND org_id = (SELECT org_id FROM users WHERE id = $1)
		  AND expires_at > NOW()
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

		// Send logout request (async) with timeout
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			s.sendLogoutRequestToSP(ctx, logoutReq, sp.SLOURL)
		}()
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

// signRedirectBinding signs the exact query-string a redirect-binding message
// carries ("SAMLRequest=...&SigAlg=...", values already URL-encoded) per SAML
// Bindings 3.4.4.1, returning the base64 signature for the Signature
// parameter.
func (s *Service) signRedirectBinding(signedQuery string) (string, error) {
	priv := s.activePrivateKey()
	if priv == nil {
		return "", fmt.Errorf("no signing key available")
	}
	digest := sha256.Sum256([]byte(signedQuery))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// sendLogoutRequestToSP delivers a LogoutRequest to the SP's SLO endpoint
// over the HTTP-Redirect binding, signed with SigAlg+Signature query
// parameters. This is a back-channel dispatch: SLO identifies the session by
// NameID/SessionIndex inside the message, so the SP terminates it without
// needing the user's browser cookies. This function used to build the URL and
// only log it — the IdP told the user their SP sessions were ended while no
// SP had ever been contacted.
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

	// The signature covers exactly the encoded query as sent, in this
	// parameter order — re-encoding or reordering breaks verification.
	signedQuery := "SAMLRequest=" + url.QueryEscape(encoded) + "&SigAlg=" + url.QueryEscape(samlRedirectSigAlg)
	fullQuery := signedQuery
	if sig, serr := s.signRedirectBinding(signedQuery); serr != nil {
		// An unsigned LogoutRequest is still processable by SPs that don't
		// require SLO signatures; deliver it and say so, rather than
		// silently dropping the logout.
		s.logger.Warn("sending unsigned SAML LogoutRequest", zap.Error(serr))
	} else {
		fullQuery += "&Signature=" + url.QueryEscape(sig)
	}

	sep := "?"
	if strings.Contains(sloURL, "?") {
		sep = "&"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sloURL+sep+fullQuery, nil)
	if err != nil {
		s.logger.Error("Failed to build LogoutRequest dispatch", zap.String("sp_slo_url", sloURL), zap.Error(err))
		return
	}

	// Not following redirects: the SP's answer to a redirect-binding
	// LogoutRequest is a redirect carrying its LogoutResponse, meant for a
	// browser, and it is the answer -- a 3xx here is a delivered logout.
	client := s.outboundHTTPClientNoRedirect("saml-slo", 10*time.Second)
	resp, err := client.Do(req)
	if err != nil {
		s.logger.Warn("SAML LogoutRequest delivery failed — the SP session may outlive the IdP session",
			zap.String("sp_slo_url", sloURL), zap.String("request_id", logoutReq.ID), zap.Error(err))
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	if resp.StatusCode >= http.StatusBadRequest {
		s.logger.Warn("SP rejected SAML LogoutRequest",
			zap.String("sp_slo_url", sloURL), zap.Int("status", resp.StatusCode), zap.String("request_id", logoutReq.ID))
		return
	}
	s.logger.Info("SAML LogoutRequest delivered",
		zap.String("sp_slo_url", sloURL), zap.Int("status", resp.StatusCode), zap.String("request_id", logoutReq.ID))
}

// extractUserIDFromSession extracts user ID from a session token
func (s *Service) extractUserIDFromSession(ctx context.Context, sessionToken string) (string, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return "", err
	}
	var userID string
	err = s.db.Pool.QueryRow(ctx,
		"SELECT user_id FROM user_sessions WHERE session_token = $1 AND org_id = $2 AND expires_at > NOW()",
		sessionToken, org.ID).Scan(&userID)
	return userID, err
}

// clearIdPSession ends the IdP session: the row goes first, the cookie second.
//
// The DELETE is the logout. Clearing the cookie only stops the browser from
// presenting the token; anyone else holding it -- the shoulder-surfer, the
// proxy log, the shared machine the user just walked away from -- still has a
// live session. So a delete that did not run must not be followed by a cleared
// cookie and a "You have been logged out" page: that combination is the worst
// of both, a user who believes they are out and a session that is in. The
// cookie is left alone on failure so the browser's state still matches the
// server's, and the caller answers an error the user can act on by retrying.
func (s *Service) clearIdPSession(c *gin.Context, sessionToken string) error {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		return fmt.Errorf("organization context required to end the session: %w", err)
	}
	if _, err := s.db.Pool.Exec(ctx,
		"DELETE FROM user_sessions WHERE session_token = $1 AND org_id = $2", sessionToken, org.ID); err != nil {
		return fmt.Errorf("delete the IdP session: %w", err)
	}

	// Clear cookie. Secure is tied to production (matching the proxy session
	// cookie convention) so the deletion is still honored over plain HTTP in
	// dev while carrying the Secure attribute in production.
	c.SetCookie("openidx_session", "", -1, "/", "", s.config.IsProduction(), true)
	return nil
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

	// org_id comes from the session's own user, so the two cannot disagree and
	// the v144 WITH CHECK cannot refuse a legitimate write -- which would lose
	// the record SLO needs to log this user out of this SP later.
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO saml_sessions (id, org_id, user_id, sp_id, sp_entity_id, session_index, name_id, name_id_format, created_at, expires_at)
		VALUES ($1, (SELECT org_id FROM users WHERE id = $2), $2, $3, $4, $5, $6, $7, NOW(), $8)
		ON CONFLICT (user_id, sp_entity_id, session_index) DO UPDATE SET
			expires_at = EXCLUDED.expires_at
	`, uuid.New().String(), userID, spID, spEntityID, sessionIndex, nameID, nameIDFormat, expiresAt)

	return err
}

// cleanupExpiredSAMLSessions removes expired SAML sessions
func (s *Service) cleanupExpiredSAMLSessions(ctx context.Context) error {
	// Install-wide sweeper: expiry is not a tenant's property and a per-org
	// sweep would need a loop over orgs to do the same work.
	//orgscope:ignore install-wide expiry sweep; deletes only rows whose expires_at has passed, in every org
	_, err := s.db.Pool.Exec(orgctx.WithBypassRLS(ctx), "DELETE FROM saml_sessions WHERE expires_at < NOW()")
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
