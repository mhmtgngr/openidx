// Package oauth provides SAML Service Provider functionality
package oauth

import (
	"compress/flate"
	"context"
	"crypto/x509"
	"encoding/base64"
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

// SAMLConfig holds SAML Service Provider configuration
type SAMLConfig struct {
	EntityID         string
	ACSURL           string
	MetadataURL      string
	Certificate      *x509.Certificate
	PrivateKey       interface{}
	SignAuthnRequest bool
}

// SAMLIdentityProvider represents an external SAML IdP configuration
type SAMLIdentityProvider struct {
	ID                string
	Name              string
	EntityID          string
	SSOURL            string
	SLOUrl            string
	Certificate       *x509.Certificate
	NameIDFormat      string
	SignAuthnRequests bool
}

// SAMLAssertion represents a parsed SAML assertion
type SAMLAssertion struct {
	ID              string
	IssueInstant    time.Time
	Issuer          string
	Subject         SAMLSubject
	Conditions      SAMLConditions
	AttributeStmt   SAMLAttributeStatement
	AuthnStatement  SAMLAuthnStatement
}

// SAMLSubject contains subject information
type SAMLSubject struct {
	NameID       string
	NameIDFormat string
}

// SAMLConditions contains assertion conditions
type SAMLConditions struct {
	NotBefore    time.Time
	NotOnOrAfter time.Time
	Audience     string
}

// SAMLAttributeStatement contains SAML attributes
type SAMLAttributeStatement struct {
	Attributes map[string][]string
}

// SAMLAuthnStatement contains authentication info
type SAMLAuthnStatement struct {
	AuthnInstant time.Time
	SessionIndex string
}

// SAMLResponse represents a SAML Response XML structure
type SAMLResponse struct {
	XMLName      xml.Name `xml:"Response"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Destination  string   `xml:"Destination,attr"`
	InResponseTo string   `xml:"InResponseTo,attr"`
	Issuer       string   `xml:"Issuer"`
	Status       SAMLStatus
	Assertion    SAMLAssertionXML `xml:"Assertion"`
}

// SAMLStatus represents SAML response status
type SAMLStatus struct {
	XMLName    xml.Name `xml:"Status"`
	StatusCode struct {
		Value string `xml:"Value,attr"`
	} `xml:"StatusCode"`
}

// SAMLAssertionXML represents SAML Assertion in XML
type SAMLAssertionXML struct {
	XMLName      xml.Name `xml:"Assertion"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Issuer       string   `xml:"Issuer"`
	Subject      struct {
		NameID struct {
			Value  string `xml:",chardata"`
			Format string `xml:"Format,attr"`
		} `xml:"NameID"`
		SubjectConfirmation struct {
			Method                  string `xml:"Method,attr"`
			SubjectConfirmationData struct {
				NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
				Recipient    string `xml:"Recipient,attr"`
				InResponseTo string `xml:"InResponseTo,attr"`
			} `xml:"SubjectConfirmationData"`
		} `xml:"SubjectConfirmation"`
	} `xml:"Subject"`
	Conditions struct {
		NotBefore            string `xml:"NotBefore,attr"`
		NotOnOrAfter         string `xml:"NotOnOrAfter,attr"`
		AudienceRestriction  struct {
			Audience string `xml:"Audience"`
		} `xml:"AudienceRestriction"`
	} `xml:"Conditions"`
	AuthnStatement struct {
		AuthnInstant string `xml:"AuthnInstant,attr"`
		SessionIndex string `xml:"SessionIndex,attr"`
		AuthnContext struct {
			AuthnContextClassRef string `xml:"AuthnContextClassRef"`
		} `xml:"AuthnContext"`
	} `xml:"AuthnStatement"`
	AttributeStatement struct {
		Attributes []struct {
			Name       string `xml:"Name,attr"`
			NameFormat string `xml:"NameFormat,attr"`
			Values     []struct {
				Value string `xml:",chardata"`
			} `xml:"AttributeValue"`
		} `xml:"Attribute"`
	} `xml:"AttributeStatement"`
}

// AuthnRequest represents a SAML AuthnRequest
type AuthnRequest struct {
	XMLName                     xml.Name `xml:"samlp:AuthnRequest"`
	XMLNS                       string   `xml:"xmlns:samlp,attr"`
	XMLNSSAML                   string   `xml:"xmlns:saml,attr"`
	ID                          string   `xml:"ID,attr"`
	Version                     string   `xml:"Version,attr"`
	IssueInstant                string   `xml:"IssueInstant,attr"`
	Destination                 string   `xml:"Destination,attr"`
	ProtocolBinding             string   `xml:"ProtocolBinding,attr"`
	AssertionConsumerServiceURL string   `xml:"AssertionConsumerServiceURL,attr"`
	Issuer                      AuthnRequestIssuer
	NameIDPolicy                *NameIDPolicy `xml:"samlp:NameIDPolicy,omitempty"`
}

// AuthnRequestIssuer is the Issuer element
type AuthnRequestIssuer struct {
	XMLName xml.Name `xml:"saml:Issuer"`
	Value   string   `xml:",chardata"`
}

// NameIDPolicy specifies NameID format
type NameIDPolicy struct {
	XMLName     xml.Name `xml:"samlp:NameIDPolicy"`
	Format      string   `xml:"Format,attr,omitempty"`
	AllowCreate bool     `xml:"AllowCreate,attr,omitempty"`
}

// SPMetadata represents SAML SP Metadata
type SPMetadata struct {
	XMLName          xml.Name `xml:"md:EntityDescriptor"`
	XMLNS            string   `xml:"xmlns:md,attr"`
	EntityID         string   `xml:"entityID,attr"`
	SPSSODescriptor  SPSSODescriptor
}

// SPSSODescriptor describes SP capabilities
type SPSSODescriptor struct {
	XMLName                    xml.Name `xml:"md:SPSSODescriptor"`
	AuthnRequestsSigned        bool     `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned       bool     `xml:"WantAssertionsSigned,attr"`
	ProtocolSupportEnumeration string   `xml:"protocolSupportEnumeration,attr"`
	NameIDFormats              []NameIDFormat
	AssertionConsumerServices  []AssertionConsumerService
}

// NameIDFormat specifies supported NameID formats
type NameIDFormat struct {
	XMLName xml.Name `xml:"md:NameIDFormat"`
	Value   string   `xml:",chardata"`
}

// AssertionConsumerService describes ACS endpoint
type AssertionConsumerService struct {
	XMLName  xml.Name `xml:"md:AssertionConsumerService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
	Index    int      `xml:"index,attr"`
}

// RegisterSAMLRoutes registers SAML endpoints
func (s *Service) RegisterSAMLRoutes(router *gin.Engine) {
	saml := router.Group("/saml")
	{
		// SP Metadata endpoint
		saml.GET("/metadata", s.handleSAMLMetadata)

		// Assertion Consumer Service (ACS) - receives SAML responses
		saml.POST("/acs", s.handleSAMLACS)
		saml.GET("/acs", s.handleSAMLACS)

		// SP-initiated SSO - start login flow
		saml.GET("/login/:idp_id", s.handleSAMLLogin)

		// Single Logout (SLO)
		saml.GET("/logout", s.handleSAMLLogout)
		saml.POST("/logout", s.handleSAMLLogout)
	}
}

// handleSAMLMetadata returns SP metadata for IdP configuration
func (s *Service) handleSAMLMetadata(c *gin.Context) {
	baseURL := s.getBaseURL(c)

	metadata := SPMetadata{
		XMLNS:    "urn:oasis:names:tc:SAML:2.0:metadata",
		EntityID: baseURL,
		SPSSODescriptor: SPSSODescriptor{
			AuthnRequestsSigned:        false,
			WantAssertionsSigned:       true,
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			NameIDFormats: []NameIDFormat{
				{Value: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"},
				{Value: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"},
				{Value: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"},
			},
			AssertionConsumerServices: []AssertionConsumerService{
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: baseURL + "/saml/acs",
					Index:    0,
				},
			},
		},
	}

	output, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		s.logger.Error("Failed to generate SAML metadata", zap.Error(err))
		c.String(http.StatusInternalServerError, "Failed to generate metadata")
		return
	}

	c.Header("Content-Type", "application/xml")
	c.String(http.StatusOK, xml.Header+string(output))
}

// handleSAMLLogin initiates SP-initiated SSO
func (s *Service) handleSAMLLogin(c *gin.Context) {
	idpID := c.Param("idp_id")
	relayState := c.Query("RelayState")

	if relayState == "" {
		relayState = c.Query("redirect_uri")
	}

	// Get IdP configuration from database
	idp, err := s.getSAMLIdPConfig(c.Request.Context(), idpID)
	if err != nil {
		s.logger.Error("Failed to get SAML IdP config", zap.Error(err), zap.String("idp_id", idpID))
		c.JSON(http.StatusNotFound, gin.H{"error": "Identity provider not found"})
		return
	}

	// Generate AuthnRequest
	requestID := "_" + uuid.New().String()
	baseURL := s.getBaseURL(c)

	authnRequest := AuthnRequest{
		XMLNS:                       "urn:oasis:names:tc:SAML:2.0:protocol",
		XMLNSSAML:                   "urn:oasis:names:tc:SAML:2.0:assertion",
		ID:                          requestID,
		Version:                     "2.0",
		IssueInstant:                time.Now().UTC().Format(time.RFC3339),
		Destination:                 idp.SSOURL,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		AssertionConsumerServiceURL: baseURL + "/saml/acs",
		Issuer: AuthnRequestIssuer{
			Value: baseURL,
		},
		NameIDPolicy: &NameIDPolicy{
			Format:      "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
			AllowCreate: true,
		},
	}

	// Store request ID for validation
	s.storeSAMLRequestID(c.Request.Context(), requestID, idpID, relayState)

	// Encode AuthnRequest
	xmlBytes, err := xml.Marshal(authnRequest)
	if err != nil {
		s.logger.Error("Failed to marshal AuthnRequest", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create authentication request"})
		return
	}

	// Deflate and base64 encode for redirect binding
	encoded, err := deflateAndEncode(xmlBytes)
	if err != nil {
		s.logger.Error("Failed to encode AuthnRequest", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode authentication request"})
		return
	}

	// Build redirect URL
	redirectURL, _ := url.Parse(idp.SSOURL)
	q := redirectURL.Query()
	q.Set("SAMLRequest", encoded)
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	redirectURL.RawQuery = q.Encode()

	s.logger.Info("Initiating SAML SSO",
		zap.String("idp_id", idpID),
		zap.String("request_id", requestID),
	)

	c.Redirect(http.StatusFound, redirectURL.String())
}

// handleSAMLACS processes SAML Response from IdP
func (s *Service) handleSAMLACS(c *gin.Context) {
	var samlResponse string
	var relayState string

	if c.Request.Method == "POST" {
		samlResponse = c.PostForm("SAMLResponse")
		relayState = c.PostForm("RelayState")
	} else {
		samlResponse = c.Query("SAMLResponse")
		relayState = c.Query("RelayState")
	}

	if samlResponse == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing SAMLResponse"})
		return
	}

	// Decode SAML Response
	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		s.logger.Error("Failed to decode SAMLResponse", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid SAMLResponse encoding"})
		return
	}

	// Parse SAML Response
	var response SAMLResponse
	if err := xml.Unmarshal(decoded, &response); err != nil {
		s.logger.Error("Failed to parse SAMLResponse", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid SAMLResponse format"})
		return
	}

	// Validate response status
	if !strings.HasSuffix(response.Status.StatusCode.Value, "Success") {
		s.logger.Error("SAML authentication failed",
			zap.String("status", response.Status.StatusCode.Value),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "SAML authentication failed"})
		return
	}

	// Parse assertion
	assertion, err := s.parseSAMLAssertion(&response.Assertion)
	if err != nil {
		s.logger.Error("Failed to parse SAML assertion", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid SAML assertion"})
		return
	}

	// Validate assertion
	if err := s.validateSAMLAssertion(assertion); err != nil {
		s.logger.Error("SAML assertion validation failed", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Get or create user from assertion
	user, err := s.getOrCreateUserFromSAML(c.Request.Context(), assertion, response.Issuer)
	if err != nil {
		s.logger.Error("Failed to get/create user from SAML", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process user"})
		return
	}

	s.logger.Info("SAML authentication successful",
		zap.String("user_id", user.ID),
		zap.String("email", user.Email),
		zap.String("issuer", response.Issuer),
	)

	// Generate OAuth tokens for the user
	tokens, err := s.generateTokensForUser(c.Request.Context(), user, "admin-console", []string{"openid", "profile", "email"})
	if err != nil {
		s.logger.Error("Failed to generate tokens", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	// Redirect with tokens
	if relayState != "" {
		redirectURL, err := url.Parse(relayState)
		if err == nil {
			q := redirectURL.Query()
			q.Set("access_token", tokens.AccessToken)
			q.Set("token_type", "Bearer")
			q.Set("expires_in", fmt.Sprintf("%d", tokens.ExpiresIn))
			if tokens.IDToken != "" {
				q.Set("id_token", tokens.IDToken)
			}
			redirectURL.RawQuery = q.Encode()
			c.Redirect(http.StatusFound, redirectURL.String())
			return
		}
	}

	// Return tokens as JSON if no relay state
	c.JSON(http.StatusOK, tokens)
}

// handleSAMLLogout handles Single Logout
func (s *Service) handleSAMLLogout(c *gin.Context) {
	// For now, just clear the session and redirect
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// parseSAMLAssertion converts XML assertion to structured format
func (s *Service) parseSAMLAssertion(xmlAssertion *SAMLAssertionXML) (*SAMLAssertion, error) {
	issueInstant, _ := time.Parse(time.RFC3339, xmlAssertion.IssueInstant)
	notBefore, _ := time.Parse(time.RFC3339, xmlAssertion.Conditions.NotBefore)
	notOnOrAfter, _ := time.Parse(time.RFC3339, xmlAssertion.Conditions.NotOnOrAfter)
	authnInstant, _ := time.Parse(time.RFC3339, xmlAssertion.AuthnStatement.AuthnInstant)

	attributes := make(map[string][]string)
	for _, attr := range xmlAssertion.AttributeStatement.Attributes {
		var values []string
		for _, v := range attr.Values {
			values = append(values, v.Value)
		}
		attributes[attr.Name] = values
	}

	return &SAMLAssertion{
		ID:           xmlAssertion.ID,
		IssueInstant: issueInstant,
		Issuer:       xmlAssertion.Issuer,
		Subject: SAMLSubject{
			NameID:       xmlAssertion.Subject.NameID.Value,
			NameIDFormat: xmlAssertion.Subject.NameID.Format,
		},
		Conditions: SAMLConditions{
			NotBefore:    notBefore,
			NotOnOrAfter: notOnOrAfter,
			Audience:     xmlAssertion.Conditions.AudienceRestriction.Audience,
		},
		AttributeStmt: SAMLAttributeStatement{
			Attributes: attributes,
		},
		AuthnStatement: SAMLAuthnStatement{
			AuthnInstant: authnInstant,
			SessionIndex: xmlAssertion.AuthnStatement.SessionIndex,
		},
	}, nil
}

// validateSAMLAssertion validates the SAML assertion
func (s *Service) validateSAMLAssertion(assertion *SAMLAssertion) error {
	now := time.Now()

	// Check time validity
	if !assertion.Conditions.NotBefore.IsZero() && now.Before(assertion.Conditions.NotBefore) {
		return errors.New("assertion not yet valid")
	}

	if !assertion.Conditions.NotOnOrAfter.IsZero() && now.After(assertion.Conditions.NotOnOrAfter) {
		return errors.New("assertion expired")
	}

	// Check subject
	if assertion.Subject.NameID == "" {
		return errors.New("missing NameID in assertion")
	}

	return nil
}

// getSAMLIdPConfig retrieves SAML IdP configuration
func (s *Service) getSAMLIdPConfig(ctx context.Context, idpID string) (*SAMLIdentityProvider, error) {
	var idp SAMLIdentityProvider

	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, issuer_url, client_id
		FROM identity_providers
		WHERE id = $1 AND provider_type = 'saml' AND enabled = true
	`, idpID).Scan(&idp.ID, &idp.Name, &idp.EntityID, &idp.SSOURL)

	if err != nil {
		return nil, err
	}

	// For SAML, client_id stores the SSO URL
	return &idp, nil
}

// storeSAMLRequestID stores request ID for validation
func (s *Service) storeSAMLRequestID(ctx context.Context, requestID, idpID, relayState string) {
	// Store in Redis with 5-minute expiry
	key := "saml_request:" + requestID
	data := fmt.Sprintf("%s|%s", idpID, relayState)
	s.redis.Client.Set(ctx, key, data, 5*time.Minute)
}

// getOrCreateUserFromSAML gets or creates a user from SAML assertion
func (s *Service) getOrCreateUserFromSAML(ctx context.Context, assertion *SAMLAssertion, issuer string) (*SAMLUser, error) {
	email := assertion.Subject.NameID

	// Try common attribute names for email
	if attrs := assertion.AttributeStmt.Attributes; attrs != nil {
		for _, key := range []string{"email", "mail", "emailAddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"} {
			if vals, ok := attrs[key]; ok && len(vals) > 0 {
				email = vals[0]
				break
			}
		}
	}

	// Extract other attributes
	firstName := getFirstAttribute(assertion.AttributeStmt.Attributes, "firstName", "givenName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname")
	lastName := getFirstAttribute(assertion.AttributeStmt.Attributes, "lastName", "surname", "sn", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname")
	displayName := getFirstAttribute(assertion.AttributeStmt.Attributes, "displayName", "name", "cn")

	if displayName == "" && firstName != "" {
		displayName = firstName
		if lastName != "" {
			displayName += " " + lastName
		}
	}

	// Check if user exists
	var userID string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT id FROM users WHERE email = $1
	`, email).Scan(&userID)

	if err != nil {
		// Create new user (JIT provisioning)
		userID = uuid.New().String()
		username := strings.Split(email, "@")[0]

		_, err = s.db.Pool.Exec(ctx, `
			INSERT INTO users (id, username, email, first_name, last_name, enabled, email_verified, external_user_id)
			VALUES ($1, $2, $3, $4, $5, true, true, $6)
			ON CONFLICT (email) DO UPDATE SET
				first_name = COALESCE(EXCLUDED.first_name, users.first_name),
				last_name = COALESCE(EXCLUDED.last_name, users.last_name),
				updated_at = NOW()
			RETURNING id
		`, userID, username, email, firstName, lastName, assertion.Subject.NameID)

		if err != nil {
			return nil, err
		}

		s.logger.Info("Created user from SAML assertion",
			zap.String("user_id", userID),
			zap.String("email", email),
		)
	}

	return &SAMLUser{
		ID:        userID,
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		Name:      displayName,
	}, nil
}

// SAMLUser represents a user from SAML assertion
type SAMLUser struct {
	ID        string
	Email     string
	FirstName string
	LastName  string
	Name      string
}

// SAMLTokenResponse represents OAuth token response for SAML flow
type SAMLTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// generateTokensForUser creates OAuth tokens for authenticated user
func (s *Service) generateTokensForUser(ctx context.Context, user *SAMLUser, clientID string, scopes []string) (*SAMLTokenResponse, error) {
	now := time.Now()
	expiresIn := 3600 // 1 hour

	// Generate access token
	accessToken, err := s.generateAccessToken(user.ID, user.Email, user.Name, clientID, scopes, time.Duration(expiresIn)*time.Second)
	if err != nil {
		return nil, err
	}

	// Generate ID token if openid scope requested
	var idToken string
	for _, scope := range scopes {
		if scope == "openid" {
			idToken, err = s.generateIDToken(user.ID, user.Email, user.Name, clientID, "", now.Add(time.Duration(expiresIn)*time.Second))
			if err != nil {
				return nil, err
			}
			break
		}
	}

	// Generate refresh token
	refreshToken := uuid.New().String()

	// Store refresh token
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO oauth_refresh_tokens (token, client_id, user_id, scope, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, refreshToken, clientID, user.ID, strings.Join(scopes, " "), now.Add(24*time.Hour))

	if err != nil {
		s.logger.Warn("Failed to store refresh token", zap.Error(err))
	}

	return &SAMLTokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		IDToken:      idToken,
	}, nil
}

// getBaseURL returns the base URL for the service
func (s *Service) getBaseURL(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, c.Request.Host)
}

// Helper functions

func deflateAndEncode(data []byte) (string, error) {
	var buf strings.Builder
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return "", err
	}

	_, err = w.Write(data)
	if err != nil {
		return "", err
	}

	err = w.Close()
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString([]byte(buf.String())), nil
}

func inflateAndDecode(data string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	reader := flate.NewReader(strings.NewReader(string(decoded)))
	defer reader.Close()

	return io.ReadAll(reader)
}

func getFirstAttribute(attrs map[string][]string, keys ...string) string {
	for _, key := range keys {
		if vals, ok := attrs[key]; ok && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

// generateAccessToken creates an access token for the user
func (s *Service) generateAccessToken(userID, email, name, clientID string, scopes []string, expiresIn time.Duration) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"sub":    userID,
		"aud":    clientID,
		"iss":    s.issuer,
		"iat":    now.Unix(),
		"exp":    now.Add(expiresIn).Unix(),
		"email":  email,
		"name":   name,
		"scope":  strings.Join(scopes, " "),
		"typ":    "Bearer",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "openidx-key-1"
	return token.SignedString(s.privateKey)
}

// generateIDToken creates an ID token for the user
func (s *Service) generateIDToken(userID, email, name, clientID, nonce string, expiresAt time.Time) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"sub":   userID,
		"aud":   clientID,
		"iss":   s.issuer,
		"iat":   now.Unix(),
		"exp":   expiresAt.Unix(),
		"email": email,
		"name":  name,
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "openidx-key-1"
	return token.SignedString(s.privateKey)
}
