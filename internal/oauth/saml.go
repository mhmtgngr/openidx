// Package oauth provides SAML 2.0 Identity Provider functionality
package oauth

import (
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// SAML-related errors
var (
	ErrInvalidAuthnRequest = errors.New("invalid saml authn request")
	ErrInvalidSAMLResponse = errors.New("invalid saml response")
	ErrSAMLSignatureFailed = errors.New("saml signature verification failed")
	ErrSPNotFound          = errors.New("service provider not found")
	ErrSPDisabled          = errors.New("service provider is disabled")
	ErrNameIDNotSupported   = errors.New("requested name id format not supported")
)

// NameIDFormat constants
const (
	NameIDFormatEmail      = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDFormatPersistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDFormatTransient  = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	NameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
)

// SAML binding constants
const (
	SAMLBindingHTTPRedirect  = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	SAMLBindingHTTPPost      = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	SAMLBindingSOAP         = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
)

// SAML protocol constants
const (
	SAMLProtocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol"
	SAMLAssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
	SAMLMetadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata"
	XMLDSigNamespace = "http://www.w3.org/2000/09/xmldsig#"
)

// AuthnRequest represents an incoming SAML Authentication Request from an SP
type AuthnRequest struct {
	XMLName                     xml.Name `xml:"AuthnRequest"`
	ID                          string   `xml:"ID,attr"`
	Version                     string   `xml:"Version,attr"`
	IssueInstant                string   `xml:"IssueInstant,attr"`
	Destination                 string   `xml:"Destination,attr,omitempty"`
	ProtocolBinding             string   `xml:"ProtocolBinding,attr,omitempty"`
	AssertionConsumerServiceURL string   `xml:"AssertionConsumerServiceURL,attr,omitempty"`
	Issuer                      string   `xml:"Issuer"`
	NameIDPolicy                *NameIDPolicy `xml:"NameIDPolicy,omitempty"`
	RequestedAuthnContext       *RequestedAuthnContext `xml:"RequestedAuthnContext,omitempty"`
	ForceAuthn                  bool     `xml:"ForceAuthn,attr,omitempty"`
	IsPassive                   bool     `xml:"IsPassive,attr,omitempty"`
}

// NameIDPolicy specifies the NameID format requested by the SP
type NameIDPolicy struct {
	Format      string `xml:"Format,attr,omitempty"`
	AllowCreate bool   `xml:"AllowCreate,attr,omitempty"`
	SPNameQualifier string `xml:"SPNameQualifier,attr,omitempty"`
}

// RequestedAuthnContext specifies authentication context requirements
type RequestedAuthnContext struct {
	Comparison string `xml:"Comparison,attr,omitempty"`
	AuthnContextClassRefs []string `xml:"AuthnContextClassRef"`
}

// SAMLUser represents user information for SAML assertion
type SAMLUser struct {
	ID              string
	Email           string
	FirstName       string
	LastName        string
	DisplayName     string
	Groups          []string
	Roles           []string
	SessionIndex    string
	AuthnInstant    time.Time
}

// SAMLResponseBuilder constructs SAML Response assertions
type SAMLResponseBuilder struct {
	idp           *Service
	responseID    string
	assertionID   string
	requestID     string
	destination   string
	issuer        string
	audience      string
	issueInstant  time.Time
	notBefore     time.Time
	notOnOrAfter  time.Time
	authnInstant  time.Time
	sessionIndex  string
	nameID        string
	nameIDFormat  string
	attributes    []SAMLAttribute
	signAssertion bool
}

// SAMLAttribute represents an attribute in the assertion
type SAMLAttribute struct {
	Name       string
	NameFormat string
	Values     []string
}

// NewSAMLResponseBuilder creates a new SAML Response builder
func (s *Service) NewSAMLResponseBuilder() *SAMLResponseBuilder {
	now := time.Now().UTC()
	return &SAMLResponseBuilder{
		idp:          s,
		responseID:   "_" + uuid.New().String(),
		assertionID:  "_" + uuid.New().String(),
		issueInstant: now,
		notBefore:    now.Add(-5 * time.Minute), // Allow for clock skew
		notOnOrAfter: now.Add(5 * time.Minute),  // Short validity window
		authnInstant: now,
		sessionIndex: "_" + uuid.New().String(),
		nameIDFormat: NameIDFormatEmail,
		signAssertion: true,
	}
}

// SetRequest sets the request details from an incoming AuthnRequest
func (b *SAMLResponseBuilder) SetRequest(requestID, destination string) *SAMLResponseBuilder {
	b.requestID = requestID
	b.destination = destination
	return b
}

// SetIssuer sets the IdP entity ID
func (b *SAMLResponseBuilder) SetIssuer(issuer string) *SAMLResponseBuilder {
	b.issuer = issuer
	return b
}

// SetAudience sets the SP entity ID (audience)
func (b *SAMLResponseBuilder) SetAudience(audience string) *SAMLResponseBuilder {
	b.audience = audience
	return b
}

// SetSubject sets the subject information
func (b *SAMLResponseBuilder) SetSubject(nameID string, format string) *SAMLResponseBuilder {
	b.nameID = nameID
	b.nameIDFormat = format
	return b
}

// SetAttributes sets the user attributes
func (b *SAMLResponseBuilder) SetAttributes(attributes []SAMLAttribute) *SAMLResponseBuilder {
	b.attributes = attributes
	return b
}

// SetSessionIndex sets the session index
func (b *SAMLResponseBuilder) SetSessionIndex(sessionIndex string) *SAMLResponseBuilder {
	b.sessionIndex = sessionIndex
	return b
}

// Build creates the signed SAML Response
func (b *SAMLResponseBuilder) Build() (string, error) {
	if b.issuer == "" {
		b.issuer = b.idp.issuer
	}

	// Build attribute statement
	attrStatement := b.buildAttributeStatement()

	// Build the response XML
	response := IdPSAMLResponse{
		XMLNS:        SAMLProtocolNamespace,
		XMLNSSAML:    SAMLAssertionNamespace,
		ID:           b.responseID,
		Version:      "2.0",
		IssueInstant: b.issueInstant.Format(time.RFC3339),
		Destination:  b.destination,
		InResponseTo: b.requestID,
		Issuer: IdPIssuer{
			Value: b.issuer,
		},
		Status: IdPStatus{
			StatusCode: IdPStatusCode{
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
		Assertion: IdPAssertion{
			XMLNS:        SAMLAssertionNamespace,
			ID:           b.assertionID,
			Version:      "2.0",
			IssueInstant: b.issueInstant.Format(time.RFC3339),
			Issuer: IdPIssuer{
				Value: b.issuer,
			},
			Subject: IdPSubject{
				NameID: IdPNameID{
					Format: b.nameIDFormat,
					Value:  b.nameID,
				},
				SubjectConfirmation: IdPSubjectConfirmation{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: IdPSubjectConfirmationData{
						NotOnOrAfter: b.notOnOrAfter.Format(time.RFC3339),
						Recipient:    b.destination,
						InResponseTo: b.requestID,
					},
				},
			},
			Conditions: IdPConditions{
				NotBefore:    b.notBefore.Format(time.RFC3339),
				NotOnOrAfter: b.notOnOrAfter.Format(time.RFC3339),
				AudienceRestriction: IdPAudienceRestriction{
					Audience: b.audience,
				},
			},
			AuthnStatement: IdPAuthnStatement{
				AuthnInstant: b.authnInstant.Format(time.RFC3339),
				SessionIndex: b.sessionIndex,
				AuthnContext: IdPAuthnContext{
					AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				},
			},
			AttributeStatement: attrStatement,
		},
	}

	xmlData, err := xml.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SAML response: %w", err)
	}

	responseXML := xml.Header + string(xmlData)

	// Sign the assertion if required
	if b.signAssertion {
		signedXML, err := b.idp.signSAMLAssertion([]byte(responseXML), b.assertionID)
		if err != nil {
			return "", fmt.Errorf("failed to sign SAML assertion: %w", err)
		}
		responseXML = signedXML
	}

	return responseXML, nil
}

// buildAttributeStatement creates the attribute statement from the configured attributes
func (b *SAMLResponseBuilder) buildAttributeStatement() IdPAttributeStatement {
	attrs := make([]IdPAttribute, 0, len(b.attributes))

	for _, attr := range b.attributes {
		values := make([]IdPAttributeValue, len(attr.Values))
		for i, v := range attr.Values {
			values[i] = IdPAttributeValue{
				Type:  "xs:string",
				Value: v,
			}
		}

		nameFormat := attr.NameFormat
		if nameFormat == "" {
			nameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
		}

		attrs = append(attrs, IdPAttribute{
			Name:       attr.Name,
			NameFormat: nameFormat,
			Values:     values,
		})
	}

	return IdPAttributeStatement{
		Attributes: attrs,
	}
}

// handleIdPSSO processes SP-initiated SSO requests
// This is the main SAML IdP SSO endpoint
func (s *Service) handleIdPSSO(c *gin.Context) {
	// Extract SAMLRequest from query or form
	samlRequest := c.Query("SAMLRequest")
	if samlRequest == "" {
		samlRequest = c.PostForm("SAMLRequest")
	}

	relayState := c.Query("RelayState")
	if relayState == "" {
		relayState = c.PostForm("RelayState")
	}

	if samlRequest == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing SAMLRequest parameter"})
		return
	}

	// Decode and parse AuthnRequest
	authnReq, err := s.decodeAndParseAuthnRequest(samlRequest)
	if err != nil {
		s.logger.Error("Failed to decode AuthnRequest", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid SAMLRequest", "details": err.Error()})
		return
	}

	s.logger.Info("Received SAML AuthnRequest",
		zap.String("request_id", authnReq.ID),
		zap.String("issuer", authnReq.Issuer),
		zap.String("acs_url", authnReq.AssertionConsumerServiceURL),
	)

	// Look up the Service Provider
	sp, err := s.getSAMLServiceProviderByEntityID(c.Request.Context(), authnReq.Issuer)
	if err != nil {
		s.logger.Error("Unknown service provider",
			zap.String("entity_id", authnReq.Issuer),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown service provider"})
		return
	}

	if !sp.Enabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "Service provider is disabled"})
		return
	}

	// Verify ACS URL matches what's registered
	if authnReq.AssertionConsumerServiceURL != "" && authnReq.AssertionConsumerServiceURL != sp.ACSURL {
		s.logger.Warn("ACS URL mismatch",
			zap.String("request_acs", authnReq.AssertionConsumerServiceURL),
			zap.String("registered_acs", sp.ACSURL),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ACS URL"})
		return
	}

	// Check user authentication
	user, err := s.authenticateIdPUser(c)
	if err != nil {
		// User not authenticated - store request context and redirect to login
		ssoSession := generateRandomToken(32)
		ssoData := map[string]interface{}{
			"sp_id":        sp.ID,
			"entity_id":    authnReq.Issuer,
			"request_id":   authnReq.ID,
			"acs_url":      sp.ACSURL,
			"relay_state":  relayState,
			"name_id_format": getNameIDFormat(authnReq.NameIDPolicy),
		}
		ssoDataJSON, _ := json.Marshal(ssoData)

		s.redis.Client.Set(c.Request.Context(),
			"saml_idp_sso:"+ssoSession,
			string(ssoDataJSON),
			10*time.Minute,
		)

		baseURL := s.getBaseURL(c)
		loginURL := fmt.Sprintf("%s/login?saml_sso_session=%s", baseURL, ssoSession)
		c.Redirect(http.StatusFound, loginURL)
		return
	}

	// Generate SAML Response
	samlResponse, err := s.buildSAMLResponseForUser(user, sp, authnReq)
	if err != nil {
		s.logger.Error("Failed to build SAML Response", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build SAML Response"})
		return
	}

	// Log the successful SSO
	go s.logAuditEvent(context.Background(), "authentication", "saml_idp", "sso", "success",
		user.ID, c.ClientIP(), sp.EntityID, "service_provider",
		map[string]interface{}{
			"sp_entity_id": sp.EntityID,
			"sp_name": sp.Name,
			"request_id": authnReq.ID,
		})

	// Send response to SP via auto-submit form
	s.sendSAMLResponseToSP(c, sp.ACSURL, samlResponse, relayState)
}

// decodeAndParseAuthnRequest decodes and validates a SAML AuthnRequest
func (s *Service) decodeAndParseAuthnRequest(encodedRequest string) (*AuthnRequest, error) {
	// Try deflate + base64
	decoded, err := inflateAndDecode(encodedRequest)
	if err != nil {
		// Fall back to plain base64
		decoded, err = base64.StdEncoding.DecodeString(encodedRequest)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to decode request", ErrInvalidAuthnRequest)
		}
	}

	var req AuthnRequest
	if err := xml.Unmarshal(decoded, &req); err != nil {
		return nil, fmt.Errorf("%w: failed to parse request XML", ErrInvalidAuthnRequest)
	}

	// Validate version
	if req.Version != "2.0" {
		return nil, fmt.Errorf("%w: unsupported SAML version: %s", ErrInvalidAuthnRequest, req.Version)
	}

	// Validate required fields
	if req.ID == "" {
		return nil, fmt.Errorf("%w: missing ID", ErrInvalidAuthnRequest)
	}
	if req.Issuer == "" {
		return nil, fmt.Errorf("%w: missing Issuer", ErrInvalidAuthnRequest)
	}

	return &req, nil
}

// authenticateIdPUser checks if the user is authenticated and returns user info
func (s *Service) authenticateIdPUser(c *gin.Context) (*SAMLUser, error) {
	// Check Authorization header for Bearer token
	authHeader := c.GetHeader("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		return s.extractSAMLUserFromToken(tokenStr)
	}

	// Check for session cookie
	sessionCookie, err := c.Cookie("openidx_session")
	if err == nil && sessionCookie != "" {
		return s.extractSAMLUserFromSession(c.Request.Context(), sessionCookie)
	}

	return nil, fmt.Errorf("user not authenticated")
}

// extractSAMLUserFromToken extracts SAML user info from a JWT token
func (s *Service) extractSAMLUserFromToken(tokenStr string) (*SAMLUser, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	userID, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)

	if userID == "" {
		return nil, fmt.Errorf("missing sub claim")
	}

	// Fetch additional user details
	var firstName, lastName string
	_ = s.db.Pool.QueryRow(context.Background(),
		"SELECT COALESCE(first_name, ''), COALESCE(last_name, '') FROM users WHERE id = $1",
		userID).Scan(&firstName, &lastName)

	if firstName == "" && lastName == "" && name != "" {
		// Try to parse name into first/last
		parts := strings.SplitN(name, " ", 2)
		if len(parts) > 0 {
			firstName = parts[0]
		}
		if len(parts) > 1 {
			lastName = parts[1]
		}
	}

	groups := s.getUserGroups(context.Background(), userID)
	roles := s.getUserRoles(context.Background(), userID)

	return &SAMLUser{
		ID:          userID,
		Email:       email,
		FirstName:   firstName,
		LastName:    lastName,
		DisplayName: name,
		Groups:      groups,
		Roles:       roles,
		AuthnInstant: time.Now(),
	}, nil
}

// extractSAMLUserFromSession extracts SAML user info from a session cookie
func (s *Service) extractSAMLUserFromSession(ctx context.Context, sessionID string) (*SAMLUser, error) {
	var userID string
	err := s.db.Pool.QueryRow(ctx,
		"SELECT user_id FROM user_sessions WHERE session_token = $1 AND expires_at > NOW()",
		sessionID).Scan(&userID)
	if err != nil {
		return nil, fmt.Errorf("invalid session: %w", err)
	}

	var email, firstName, lastName string
	err = s.db.Pool.QueryRow(ctx,
		"SELECT COALESCE(email, ''), COALESCE(first_name, ''), COALESCE(last_name, '') FROM users WHERE id = $1",
		userID).Scan(&email, &firstName, &lastName)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	displayName := firstName
	if lastName != "" {
		displayName += " " + lastName
	}

	groups := s.getUserGroups(ctx, userID)
	roles := s.getUserRoles(ctx, userID)

	return &SAMLUser{
		ID:          userID,
		Email:       email,
		FirstName:   firstName,
		LastName:    lastName,
		DisplayName: displayName,
		Groups:      groups,
		Roles:       roles,
		AuthnInstant: time.Now(),
	}, nil
}

// getUserRoles fetches role names for a user
func (s *Service) getUserRoles(ctx context.Context, userID string) []string {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT DISTINCT r.name
		FROM roles r
		INNER JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = $1
	`, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			roles = append(roles, name)
		}
	}
	return roles
}

// buildSAMLResponseForUser creates a SAML Response for a user
func (s *Service) buildSAMLResponseForUser(user *SAMLUser, sp *SAMLServiceProvider, authnReq *AuthnRequest) (string, error) {
	// Determine NameID format and value
	nameIDFormat := getNameIDFormat(authnReq.NameIDPolicy)
	if sp.NameIDFormat != "" {
		nameIDFormat = sp.NameIDFormat
	}

	nameID := user.Email
	switch nameIDFormat {
	case NameIDFormatPersistent:
		nameID = user.ID
	case NameIDFormatTransient:
		// Generate a transient ID - should be stored and consistent for the SP-user pair
		nameID = generateTransientID(user.ID, sp.EntityID)
	}

	// Build attributes with mappings
	attributes := s.buildUserAttributes(user, sp)

	// Build the response
	builder := s.NewSAMLResponseBuilder()
	builder.SetRequest(authnReq.ID, sp.ACSURL)
	builder.SetIssuer(s.issuer)
	builder.SetAudience(sp.EntityID)
	builder.SetSubject(nameID, nameIDFormat)
	builder.SetAttributes(attributes)
	if user.SessionIndex != "" {
		builder.SetSessionIndex(user.SessionIndex)
	}

	return builder.Build()
}

// buildUserAttributes creates SAML attributes from user data with SP mappings
func (s *Service) buildUserAttributes(user *SAMLUser, sp *SAMLServiceProvider) []SAMLAttribute {
	baseAttributes := []struct {
		name   string
		values []string
	}{
		{"email", []string{user.Email}},
		{"firstName", []string{user.FirstName}},
		{"lastName", []string{user.LastName}},
		{"displayName", []string{user.DisplayName}},
	}

	// Add groups
	if len(user.Groups) > 0 {
		baseAttributes = append(baseAttributes, struct {
			name   string
			values []string
		}{"groups", user.Groups})
	}

	// Add roles
	if len(user.Roles) > 0 {
		baseAttributes = append(baseAttributes, struct {
			name   string
			values []string
		}{"roles", user.Roles})
	}

	// Apply attribute mappings
	attrs := make([]SAMLAttribute, 0, len(baseAttributes))
	for _, attr := range baseAttributes {
		name := attr.name
		// Check if SP has a custom mapping
		if sp.AttributeMappings != nil {
			if mappedName, ok := sp.AttributeMappings[attr.name]; ok {
				name = mappedName
			}
		}

		attrs = append(attrs, SAMLAttribute{
			Name:       name,
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:     attr.values,
		})
	}

	return attrs
}

// getNameIDFormat extracts the NameID format from a NameIDPolicy
func getNameIDFormat(policy *NameIDPolicy) string {
	if policy == nil || policy.Format == "" {
		return NameIDFormatEmail
	}
	return policy.Format
}

// generateTransientID creates a transient NameID for a user-SP pair
func generateTransientID(userID, spEntityID string) string {
	// In production, this should be stored in the database and consistently returned
	// For now, generate a deterministic value
	data := userID + "|" + spEntityID
	hash := sha256.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hash[:])[:32]
}

// sendSAMLResponseToSP sends the SAML Response to the SP's ACS endpoint
func (s *Service) sendSAMLResponseToSP(c *gin.Context, acsURL, samlResponse, relayState string) {
	encodedResponse := base64.StdEncoding.EncodeToString([]byte(samlResponse))

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>SAML SSO</title>
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; }
		.container { text-align: center; padding: 2rem; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
		h2 { margin: 0 0 1rem 0; color: #333; }
		p { color: #666; margin-bottom: 1.5rem; }
		.progress { width: 200px; height: 4px; background: #e0e0e0; border-radius: 2px; margin: 0 auto; overflow: hidden; }
		.progress-bar { height: 100%; background: #4285f4; animation: progress 1.5s ease-in-out; }
		@keyframes progress { from { width: 0; } to { width: 100%; } }
	</style>
</head>
<body onload="document.forms[0].submit()">
	<div class="container">
		<h2>Signing you in...</h2>
		<p>You are being redirected to the service provider.</p>
		<div class="progress"><div class="progress-bar"></div></div>
		<noscript>
			<p>JavaScript is required. Please click the button below to continue.</p>
		</noscript>
	</div>
	<form method="POST" action="%s" style="display:none">
		<input type="hidden" name="SAMLResponse" value="%s" />
		<input type="hidden" name="RelayState" value="%s" />
		<noscript><input type="submit" value="Continue" /></noscript>
	</form>
</body>
</html>`, acsURL, html.EscapeString(encodedResponse), html.EscapeString(relayState))

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, html)
}

// signSAMLAssertion signs the SAML assertion with RSA-SHA256
func (s *Service) signSAMLAssertion(xmlData []byte, assertionID string) (string, error) {
	// Find the Assertion element and extract it for signing
	xmlStr := string(xmlData)

	// Find assertion start and end
	assertionStartTag := `<saml:Assertion`
	assertionEndTag := `</saml:Assertion>`
	startIdx := strings.Index(xmlStr, assertionStartTag)
	endIdx := strings.Index(xmlStr, assertionEndTag)

	if startIdx == -1 || endIdx == -1 {
		return "", fmt.Errorf("could not find assertion element")
	}

	// Extract the assertion XML (for signing)
	assertionEndIdx := endIdx + len(assertionEndTag)
	assertionXML := xmlStr[startIdx:assertionEndIdx]

	// Compute SHA-256 digest of the assertion
	digest := sha256.Sum256([]byte(assertionXML))
	digestBase64 := base64.StdEncoding.EncodeToString(digest[:])

	// Sign the digest with RSA-SHA256
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign assertion: %w", err)
	}
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	// Build the Signature element
	sigXML := fmt.Sprintf(`    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#%s">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>%s</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>%s</ds:SignatureValue>
    </ds:Signature>`, assertionID, digestBase64, signatureBase64)

	// Insert the signature after the Issuer element within the Assertion
	issuerCloseTag := `</saml:Issuer>`
	issuerIdx := strings.Index(assertionXML, issuerCloseTag)
	if issuerIdx == -1 {
		// Fallback: insert after Issuer
		issuerIdx = strings.Index(assertionXML, `<saml:Issuer>`)
		if issuerIdx != -1 {
			issuerIdx = strings.Index(assertionXML[issuerIdx:], `</saml:Issuer>`) + issuerIdx + len(`</saml:Issuer>`)
		}
	}

	if issuerIdx != -1 {
		insertPos := issuerIdx + len(issuerCloseTag)
		assertionXML = assertionXML[:insertPos] + "\n" + sigXML + assertionXML[insertPos:]
	} else {
		// Last resort: prepend signature
		assertionXML = sigXML + "\n" + assertionXML
	}

	// Replace the assertion in the original XML
	signedXML := xmlStr[:startIdx] + assertionXML + xmlStr[assertionEndIdx:]

	return signedXML, nil
}

// generateRandomToken generates a cryptographically random token
func generateRandomToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		// Fallback
		return uuid.New().String() + uuid.New().String()
	}
	return base64.RawURLEncoding.EncodeToString(b)[:length]
}

// deflateAndEncode compresses data with deflate and base64 encodes it
func deflateAndEncode(data []byte) (string, error) {
	var buf strings.Builder
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return "", err
	}

	if _, err := w.Write(data); err != nil {
		w.Close()
		return "", err
	}

	if err := w.Close(); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString([]byte(buf.String())), nil
}

// inflateAndDecode decodes base64 and decompresses deflate data
func inflateAndDecode(data string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	reader := flate.NewReader(strings.NewReader(string(decoded)))
	defer reader.Close()

	return io.ReadAll(reader)
}

// getBaseURL returns the base URL from the request
func (s *Service) getBaseURL(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := c.GetHeader("X-Forwarded-Host")
	if host == "" {
		host = c.Request.Host
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

// IdPSAMLResponse represents a SAML Response issued by the IdP
type IdPSAMLResponse struct {
	XMLName      xml.Name         `xml:"samlp:Response"`
	XMLNS        string           `xml:"xmlns:samlp,attr"`
	XMLNSSAML    string           `xml:"xmlns:saml,attr"`
	ID           string           `xml:"ID,attr"`
	Version      string           `xml:"Version,attr"`
	IssueInstant string           `xml:"IssueInstant,attr"`
	Destination  string           `xml:"Destination,attr"`
	InResponseTo string           `xml:"InResponseTo,attr,omitempty"`
	Issuer       IdPIssuer        `xml:"saml:Issuer"`
	Status       IdPStatus        `xml:"samlp:Status"`
	Assertion    IdPAssertion     `xml:"saml:Assertion"`
}

// IdPIssuer is the Issuer element
type IdPIssuer struct {
	XMLName xml.Name `xml:"saml:Issuer"`
	Value   string   `xml:",chardata"`
}

// IdPStatus is the SAML response status
type IdPStatus struct {
	XMLName    xml.Name     `xml:"samlp:Status"`
	StatusCode IdPStatusCode `xml:"samlp:StatusCode"`
}

// IdPStatusCode is the status code element
type IdPStatusCode struct {
	XMLName xml.Name `xml:"samlp:StatusCode"`
	Value   string   `xml:"Value,attr"`
}

// IdPAssertion represents a SAML Assertion
type IdPAssertion struct {
	XMLName            xml.Name              `xml:"saml:Assertion"`
	XMLNS              string                `xml:"xmlns:saml,attr"`
	ID                 string                `xml:"ID,attr"`
	Version            string                `xml:"Version,attr"`
	IssueInstant       string                `xml:"IssueInstant,attr"`
	Issuer             IdPIssuer             `xml:"saml:Issuer"`
	Subject            IdPSubject            `xml:"saml:Subject"`
	Conditions         IdPConditions         `xml:"saml:Conditions"`
	AuthnStatement     IdPAuthnStatement     `xml:"saml:AuthnStatement"`
	AttributeStatement IdPAttributeStatement `xml:"saml:AttributeStatement"`
}

// IdPSubject contains subject details
type IdPSubject struct {
	XMLName             xml.Name                   `xml:"saml:Subject"`
	NameID              IdPNameID                  `xml:"saml:NameID"`
	SubjectConfirmation IdPSubjectConfirmation      `xml:"saml:SubjectConfirmation"`
}

// IdPNameID is the NameID element
type IdPNameID struct {
	XMLName xml.Name `xml:"saml:NameID"`
	Format  string   `xml:"Format,attr"`
	Value   string   `xml:",chardata"`
}

// IdPSubjectConfirmation specifies confirmation method
type IdPSubjectConfirmation struct {
	XMLName                 xml.Name                     `xml:"saml:SubjectConfirmation"`
	Method                  string                       `xml:"Method,attr"`
	SubjectConfirmationData IdPSubjectConfirmationData   `xml:"saml:SubjectConfirmationData"`
}

// IdPSubjectConfirmationData has confirmation data
type IdPSubjectConfirmationData struct {
	XMLName      xml.Name `xml:"saml:SubjectConfirmationData"`
	NotOnOrAfter string   `xml:"NotOnOrAfter,attr"`
	Recipient    string   `xml:"Recipient,attr"`
	InResponseTo string   `xml:"InResponseTo,attr,omitempty"`
}

// IdPConditions contains assertion conditions
type IdPConditions struct {
	XMLName             xml.Name                 `xml:"saml:Conditions"`
	NotBefore           string                   `xml:"NotBefore,attr"`
	NotOnOrAfter        string                   `xml:"NotOnOrAfter,attr"`
	AudienceRestriction IdPAudienceRestriction   `xml:"saml:AudienceRestriction"`
}

// IdPAudienceRestriction restricts audience
type IdPAudienceRestriction struct {
	XMLName  xml.Name `xml:"saml:AudienceRestriction"`
	Audience string   `xml:"saml:Audience"`
}

// IdPAuthnStatement describes authentication event
type IdPAuthnStatement struct {
	XMLName      xml.Name        `xml:"saml:AuthnStatement"`
	AuthnInstant string          `xml:"AuthnInstant,attr"`
	SessionIndex string          `xml:"SessionIndex,attr"`
	AuthnContext IdPAuthnContext  `xml:"saml:AuthnContext"`
}

// IdPAuthnContext describes authn context class
type IdPAuthnContext struct {
	XMLName              xml.Name `xml:"saml:AuthnContext"`
	AuthnContextClassRef string   `xml:"saml:AuthnContextClassRef"`
}

// IdPAttributeStatement holds user attributes
type IdPAttributeStatement struct {
	XMLName    xml.Name       `xml:"saml:AttributeStatement"`
	Attributes []IdPAttribute `xml:"saml:Attribute"`
}

// IdPAttribute is a single SAML attribute
type IdPAttribute struct {
	XMLName    xml.Name             `xml:"saml:Attribute"`
	Name       string               `xml:"Name,attr"`
	NameFormat string               `xml:"NameFormat,attr"`
	Values     []IdPAttributeValue  `xml:"saml:AttributeValue"`
}

// IdPAttributeValue is an attribute value
type IdPAttributeValue struct {
	XMLName xml.Name `xml:"saml:AttributeValue"`
	Type    string   `xml:"xsi:type,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

// logAuditEvent logs an audit event (placeholder - should integrate with audit service)
func (s *Service) logAuditEvent(ctx context.Context, eventType, category, action, status string,
	userID, ipAddress, resourceID, resourceType string, metadata map[string]interface{}) {

	s.logger.Info("SAML audit event",
		zap.String("event_type", eventType),
		zap.String("category", category),
		zap.String("action", action),
		zap.String("status", status),
		zap.String("user_id", userID),
		zap.String("ip_address", ipAddress),
		zap.String("resource_id", resourceID),
		zap.String("resource_type", resourceType),
		any("metadata", metadata),
	)
}

// any is a helper for logging arbitrary data
func any(key string, value interface{}) zap.Field {
	return zap.Any(key, value)
}

// RegisterSAMLIdPRoutes registers all SAML IdP routes
func (s *Service) RegisterSAMLIdPRoutes(router *gin.Engine) {
	// IdP endpoints
	idp := router.Group("/saml/idp")
	{
		// IdP Metadata - returns the IdP's metadata XML
		idp.GET("/metadata", s.handleIdPMetadata)

		// Single Sign-On endpoint - receives AuthnRequest from SPs
		idp.GET("/sso", s.handleIdPSSO)
		idp.POST("/sso", s.handleIdPSSO)

		// Single Logout endpoint - receives LogoutRequest from SPs
		idp.GET("/slo", s.handleIdPSLO)
		idp.POST("/slo", s.handleIdPSLO)
	}

	// SP management API endpoints
	spAPI := router.Group("/api/v1/saml/service-providers")
	{
		// List all SPs with pagination
		spAPI.GET("", s.handleListSAMLServiceProviders)

		// Get a single SP by ID
		spAPI.GET("/:id", s.handleGetSAMLServiceProvider)

		// Create a new SP
		spAPI.POST("", s.handleCreateSAMLServiceProvider)

		// Update an existing SP
		spAPI.PUT("/:id", s.handleUpdateSAMLServiceProvider)

		// Delete an SP
		spAPI.DELETE("/:id", s.handleDeleteSAMLServiceProvider)

		// Rotate SP certificate
		spAPI.POST("/:id/rotate-certificate", s.handleRotateSPCertificate)

		// Import SP from metadata
		spAPI.POST("/import-metadata", s.handleImportSAMLMetadata)
	}
}
