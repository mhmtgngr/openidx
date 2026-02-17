// Package oauth provides SAML Identity Provider functionality
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
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// SAMLServiceProvider represents a registered SP for our IdP role
type SAMLServiceProvider struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	EntityID          string            `json:"entity_id"`
	ACSURL            string            `json:"acs_url"`
	SLOURL            string            `json:"slo_url,omitempty"`
	Certificate       string            `json:"certificate,omitempty"`
	NameIDFormat      string            `json:"name_id_format"`
	AttributeMappings map[string]string `json:"attribute_mappings,omitempty"`
	Enabled           bool              `json:"enabled"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// --- XML types for IdP metadata ---

// IdPMetadata represents SAML IdP Metadata XML
type IdPMetadata struct {
	XMLName          xml.Name          `xml:"md:EntityDescriptor"`
	XMLNS            string            `xml:"xmlns:md,attr"`
	EntityID         string            `xml:"entityID,attr"`
	IDPSSODescriptor IDPSSODescriptor  `xml:"md:IDPSSODescriptor"`
}

// IDPSSODescriptor describes IdP capabilities
type IDPSSODescriptor struct {
	XMLName                    xml.Name              `xml:"md:IDPSSODescriptor"`
	WantAuthnRequestsSigned    bool                  `xml:"WantAuthnRequestsSigned,attr"`
	ProtocolSupportEnumeration string                `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptors             []IdPKeyDescriptor    `xml:"md:KeyDescriptor"`
	NameIDFormats              []NameIDFormat         `xml:"md:NameIDFormat"`
	SingleSignOnServices       []SingleSignOnService  `xml:"md:SingleSignOnService"`
	SingleLogoutServices       []SingleLogoutService  `xml:"md:SingleLogoutService"`
}

// IdPKeyDescriptor describes a signing key
type IdPKeyDescriptor struct {
	XMLName xml.Name   `xml:"md:KeyDescriptor"`
	Use     string     `xml:"use,attr"`
	KeyInfo IdPKeyInfo `xml:"ds:KeyInfo"`
}

// IdPKeyInfo holds key information
type IdPKeyInfo struct {
	XMLName  xml.Name     `xml:"ds:KeyInfo"`
	XMLNS    string       `xml:"xmlns:ds,attr"`
	X509Data IdPX509Data  `xml:"ds:X509Data"`
}

// IdPX509Data holds X.509 certificate data
type IdPX509Data struct {
	XMLName         xml.Name `xml:"ds:X509Data"`
	X509Certificate string   `xml:"ds:X509Certificate"`
}

// SingleSignOnService describes SSO endpoint
type SingleSignOnService struct {
	XMLName  xml.Name `xml:"md:SingleSignOnService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
}

// SingleLogoutService describes SLO endpoint
type SingleLogoutService struct {
	XMLName  xml.Name `xml:"md:SingleLogoutService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
}

// --- XML types for SAML IdP Response ---

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
	Signature    *IdPSignatureXML `xml:"ds:Signature,omitempty"`
}

// IdPIssuer is the Issuer element
type IdPIssuer struct {
	XMLName xml.Name `xml:"saml:Issuer"`
	Value   string   `xml:",chardata"`
}

// IdPStatus is the SAML response status
type IdPStatus struct {
	XMLName    xml.Name       `xml:"samlp:Status"`
	StatusCode IdPStatusCode  `xml:"samlp:StatusCode"`
}

// IdPStatusCode is the status code element
type IdPStatusCode struct {
	XMLName xml.Name `xml:"samlp:StatusCode"`
	Value   string   `xml:"Value,attr"`
}

// IdPAssertion represents a SAML Assertion
type IdPAssertion struct {
	XMLName            xml.Name                `xml:"saml:Assertion"`
	XMLNS              string                  `xml:"xmlns:saml,attr"`
	ID                 string                  `xml:"ID,attr"`
	Version            string                  `xml:"Version,attr"`
	IssueInstant       string                  `xml:"IssueInstant,attr"`
	Issuer             IdPIssuer               `xml:"saml:Issuer"`
	Subject            IdPSubject              `xml:"saml:Subject"`
	Conditions         IdPConditions           `xml:"saml:Conditions"`
	AuthnStatement     IdPAuthnStatement       `xml:"saml:AuthnStatement"`
	AttributeStatement IdPAttributeStatement   `xml:"saml:AttributeStatement"`
}

// IdPSubject contains subject details
type IdPSubject struct {
	XMLName             xml.Name                 `xml:"saml:Subject"`
	NameID              IdPNameID                `xml:"saml:NameID"`
	SubjectConfirmation IdPSubjectConfirmation   `xml:"saml:SubjectConfirmation"`
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
	Type    string   `xml:"xmlns:xsi,attr,omitempty"`
	XSType  string   `xml:"xsi:type,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

// IdPSignatureXML represents an XML Signature stub
type IdPSignatureXML struct {
	XMLName        xml.Name         `xml:"ds:Signature"`
	XMLNS          string           `xml:"xmlns:ds,attr"`
	SignedInfo     IdPSignedInfo     `xml:"ds:SignedInfo"`
	SignatureValue string            `xml:"ds:SignatureValue"`
}

// IdPSignedInfo describes what was signed
type IdPSignedInfo struct {
	XMLName                xml.Name                `xml:"ds:SignedInfo"`
	CanonicalizationMethod IdPAlgorithm            `xml:"ds:CanonicalizationMethod"`
	SignatureMethod        IdPAlgorithm            `xml:"ds:SignatureMethod"`
	Reference              IdPSignatureReference   `xml:"ds:Reference"`
}

// IdPAlgorithm specifies an algorithm URI
type IdPAlgorithm struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// IdPSignatureReference references the signed element
type IdPSignatureReference struct {
	XMLName    xml.Name         `xml:"ds:Reference"`
	URI        string           `xml:"URI,attr"`
	Transforms IdPTransforms    `xml:"ds:Transforms"`
	DigestMethod IdPAlgorithm   `xml:"ds:DigestMethod"`
	DigestValue  string         `xml:"ds:DigestValue"`
}

// IdPTransforms contains transform algorithms
type IdPTransforms struct {
	XMLName   xml.Name       `xml:"ds:Transforms"`
	Transform []IdPAlgorithm `xml:"ds:Transform"`
}

// IncomingAuthnRequest represents a parsed SAML AuthnRequest from an SP
type IncomingAuthnRequest struct {
	XMLName                     xml.Name `xml:"AuthnRequest"`
	ID                          string   `xml:"ID,attr"`
	Version                     string   `xml:"Version,attr"`
	IssueInstant                string   `xml:"IssueInstant,attr"`
	Destination                 string   `xml:"Destination,attr"`
	AssertionConsumerServiceURL string   `xml:"AssertionConsumerServiceURL,attr"`
	ProtocolBinding             string   `xml:"ProtocolBinding,attr"`
	Issuer                      string   `xml:"Issuer"`
}

// IncomingLogoutRequest represents a parsed SAML LogoutRequest from an SP
type IncomingLogoutRequest struct {
	XMLName      xml.Name `xml:"LogoutRequest"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Destination  string   `xml:"Destination,attr"`
	Issuer       string   `xml:"Issuer"`
	NameID       string   `xml:"NameID"`
	SessionIndex string   `xml:"SessionIndex"`
}

// IdPLogoutResponse represents a SAML LogoutResponse
type IdPLogoutResponse struct {
	XMLName      xml.Name  `xml:"samlp:LogoutResponse"`
	XMLNS        string    `xml:"xmlns:samlp,attr"`
	XMLNSSAML    string    `xml:"xmlns:saml,attr"`
	ID           string    `xml:"ID,attr"`
	Version      string    `xml:"Version,attr"`
	IssueInstant string    `xml:"IssueInstant,attr"`
	Destination  string    `xml:"Destination,attr"`
	InResponseTo string    `xml:"InResponseTo,attr"`
	Issuer       IdPIssuer `xml:"saml:Issuer"`
	Status       IdPStatus `xml:"samlp:Status"`
}

// RegisterSAMLIdPRoutes registers SAML IdP endpoints
func (s *Service) RegisterSAMLIdPRoutes(router *gin.Engine) {
	idp := router.Group("/saml/idp")
	{
		// IdP Metadata
		idp.GET("/metadata", s.handleIdPMetadata)

		// Single Sign-On endpoint
		idp.GET("/sso", s.handleIdPSSO)

		// Single Logout endpoint
		idp.GET("/slo", s.handleIdPSLO)
		idp.POST("/slo", s.handleIdPSLO)
	}

	// SP management endpoints
	sp := router.Group("/api/v1/saml/service-providers")
	{
		sp.GET("", s.handleListSAMLServiceProviders)
		sp.POST("", s.handleCreateSAMLServiceProvider)
		sp.PUT("/:id", s.handleUpdateSAMLServiceProvider)
		sp.DELETE("/:id", s.handleDeleteSAMLServiceProvider)
	}
}

// handleIdPMetadata returns SAML IdP metadata XML
func (s *Service) handleIdPMetadata(c *gin.Context) {
	baseURL := s.getBaseURL(c)

	// Encode public key as PEM-style X.509 certificate data (base64 DER of PKIX public key)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(s.publicKey)
	if err != nil {
		s.logger.Error("Failed to marshal public key for IdP metadata", zap.Error(err))
		c.String(http.StatusInternalServerError, "Failed to generate metadata")
		return
	}
	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: pubKeyBytes}
	certPEM := pem.EncodeToMemory(certBlock)
	// Strip PEM header/footer to get raw base64
	certBase64 := strings.TrimSpace(string(certPEM))
	certBase64 = strings.TrimPrefix(certBase64, "-----BEGIN CERTIFICATE-----")
	certBase64 = strings.TrimSuffix(certBase64, "-----END CERTIFICATE-----")
	certBase64 = strings.TrimSpace(certBase64)

	metadata := IdPMetadata{
		XMLNS:    "urn:oasis:names:tc:SAML:2.0:metadata",
		EntityID: s.issuer,
		IDPSSODescriptor: IDPSSODescriptor{
			WantAuthnRequestsSigned:    false,
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			KeyDescriptors: []IdPKeyDescriptor{
				{
					Use: "signing",
					KeyInfo: IdPKeyInfo{
						XMLNS: "http://www.w3.org/2000/09/xmldsig#",
						X509Data: IdPX509Data{
							X509Certificate: certBase64,
						},
					},
				},
			},
			NameIDFormats: []NameIDFormat{
				{Value: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"},
				{Value: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"},
				{Value: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"},
			},
			SingleSignOnServices: []SingleSignOnService{
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
					Location: baseURL + "/saml/idp/sso",
				},
			},
			SingleLogoutServices: []SingleLogoutService{
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
					Location: baseURL + "/saml/idp/slo",
				},
			},
		},
	}

	output, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		s.logger.Error("Failed to generate IdP metadata", zap.Error(err))
		c.String(http.StatusInternalServerError, "Failed to generate metadata")
		return
	}

	c.Header("Content-Type", "application/xml")
	c.String(http.StatusOK, xml.Header+string(output))
}

// handleIdPSSO handles SP-initiated SSO at the IdP
func (s *Service) handleIdPSSO(c *gin.Context) {
	samlRequest := c.Query("SAMLRequest")
	relayState := c.Query("RelayState")

	if samlRequest == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing SAMLRequest parameter"})
		return
	}

	// Decode the AuthnRequest (deflate + base64)
	decoded, err := inflateAndDecode(samlRequest)
	if err != nil {
		// Try plain base64 without deflate
		decoded, err = base64.StdEncoding.DecodeString(samlRequest)
		if err != nil {
			s.logger.Error("Failed to decode SAMLRequest", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid SAMLRequest encoding"})
			return
		}
	}

	// Parse AuthnRequest
	var authnReq IncomingAuthnRequest
	if err := xml.Unmarshal(decoded, &authnReq); err != nil {
		s.logger.Error("Failed to parse SAMLRequest", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid SAMLRequest format"})
		return
	}

	// Look up the SP by the Issuer (entity_id) in the AuthnRequest
	sp, err := s.getSAMLServiceProviderByEntityID(c.Request.Context(), authnReq.Issuer)
	if err != nil {
		s.logger.Error("Unknown service provider", zap.String("entity_id", authnReq.Issuer), zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown service provider"})
		return
	}

	if !sp.Enabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "Service provider is disabled"})
		return
	}

	// Check user authentication - look for session cookie or Authorization header
	userID, email, firstName, lastName, groups, err := s.getAuthenticatedIdPUser(c)
	if err != nil {
		// User is not authenticated - redirect to login page with a return URL
		// Store the SAML request context in Redis so we can resume after login
		ssoSession := GenerateRandomToken(32)
		ssoData := map[string]string{
			"sp_id":        sp.ID,
			"entity_id":    authnReq.Issuer,
			"request_id":   authnReq.ID,
			"acs_url":      sp.ACSURL,
			"relay_state":  relayState,
		}
		ssoDataJSON, _ := json.Marshal(ssoData)
		s.redis.Client.Set(c.Request.Context(), "saml_idp_sso:"+ssoSession, string(ssoDataJSON), 10*time.Minute)

		baseURL := s.getBaseURL(c)
		loginURL := fmt.Sprintf("%s/login?saml_sso_session=%s", baseURL, ssoSession)
		c.Redirect(http.StatusFound, loginURL)
		return
	}

	s.logger.Info("SAML IdP SSO: authenticated user",
		zap.String("user_id", userID),
		zap.String("email", email),
		zap.String("sp_entity_id", sp.EntityID),
	)

	// Build SAML Response
	samlResponseXML, err := s.buildSAMLResponse(userID, email, firstName, lastName, groups, sp, authnReq.ID)
	if err != nil {
		s.logger.Error("Failed to build SAML Response", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build SAML Response"})
		return
	}

	// Sign the SAML Response
	signedResponse, err := s.signSAMLXML([]byte(samlResponseXML))
	if err != nil {
		s.logger.Error("Failed to sign SAML Response", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign SAML Response"})
		return
	}

	// Base64-encode the response for the POST binding
	encodedResponse := base64.StdEncoding.EncodeToString([]byte(signedResponse))

	// Return auto-submit HTML form that POSTs to the SP's ACS URL
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>SAML SSO</title></head>
<body onload="document.forms[0].submit()">
<noscript><p>JavaScript is required. Please click the button below.</p></noscript>
<form method="POST" action="%s">
<input type="hidden" name="SAMLResponse" value="%s" />
<input type="hidden" name="RelayState" value="%s" />
<noscript><input type="submit" value="Continue" /></noscript>
</form>
</body>
</html>`, sp.ACSURL, encodedResponse, relayState)

	go s.logAuditEvent(context.Background(), "authentication", "saml_idp", "sso_response", "success",
		userID, c.ClientIP(), sp.EntityID, "service_provider",
		map[string]interface{}{"sp_entity_id": sp.EntityID, "sp_name": sp.Name})

	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, html)
}

// handleIdPSLO handles Single Logout at the IdP
func (s *Service) handleIdPSLO(c *gin.Context) {
	var samlRequest string
	if c.Request.Method == "POST" {
		samlRequest = c.PostForm("SAMLRequest")
	} else {
		samlRequest = c.Query("SAMLRequest")
	}

	if samlRequest == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing SAMLRequest parameter"})
		return
	}

	// Decode the LogoutRequest
	decoded, err := inflateAndDecode(samlRequest)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(samlRequest)
		if err != nil {
			s.logger.Error("Failed to decode SLO SAMLRequest", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid SAMLRequest encoding"})
			return
		}
	}

	var logoutReq IncomingLogoutRequest
	if err := xml.Unmarshal(decoded, &logoutReq); err != nil {
		s.logger.Error("Failed to parse SLO LogoutRequest", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid LogoutRequest format"})
		return
	}

	// Look up the SP
	sp, err := s.getSAMLServiceProviderByEntityID(c.Request.Context(), logoutReq.Issuer)
	if err != nil {
		s.logger.Error("Unknown SP in SLO request", zap.String("issuer", logoutReq.Issuer), zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown service provider"})
		return
	}

	// Invalidate the user session
	if logoutReq.NameID != "" {
		// Find user by email and delete their sessions
		var userID string
		err := s.db.Pool.QueryRow(c.Request.Context(),
			"SELECT id FROM users WHERE email = $1", logoutReq.NameID).Scan(&userID)
		if err == nil {
			_, _ = s.db.Pool.Exec(c.Request.Context(),
				"DELETE FROM sessions WHERE user_id = $1", userID)
			s.logger.Info("SAML IdP SLO: invalidated sessions",
				zap.String("user_id", userID),
				zap.String("sp_entity_id", sp.EntityID),
			)
		}
	}

	go s.logAuditEvent(context.Background(), "authentication", "saml_idp", "slo", "success",
		logoutReq.NameID, c.ClientIP(), sp.EntityID, "service_provider",
		map[string]interface{}{"sp_entity_id": sp.EntityID, "request_id": logoutReq.ID})

	// Build LogoutResponse
	now := time.Now().UTC()
	logoutResponse := IdPLogoutResponse{
		XMLNS:        "urn:oasis:names:tc:SAML:2.0:protocol",
		XMLNSSAML:    "urn:oasis:names:tc:SAML:2.0:assertion",
		ID:           "_" + uuid.New().String(),
		Version:      "2.0",
		IssueInstant: now.Format(time.RFC3339),
		Destination:  sp.SLOURL,
		InResponseTo: logoutReq.ID,
		Issuer: IdPIssuer{
			Value: s.issuer,
		},
		Status: IdPStatus{
			StatusCode: IdPStatusCode{
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
	}

	responseXML, err := xml.Marshal(logoutResponse)
	if err != nil {
		s.logger.Error("Failed to marshal LogoutResponse", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build LogoutResponse"})
		return
	}

	// If SP has an SLO URL, redirect with the response
	if sp.SLOURL != "" {
		encoded, err := idpDeflateAndEncode(responseXML)
		if err != nil {
			s.logger.Error("Failed to encode LogoutResponse", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode LogoutResponse"})
			return
		}

		redirectURL := sp.SLOURL
		if strings.Contains(redirectURL, "?") {
			redirectURL += "&"
		} else {
			redirectURL += "?"
		}
		redirectURL += "SAMLResponse=" + encoded
		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

// handleListSAMLServiceProviders lists all registered SPs
func (s *Service) handleListSAMLServiceProviders(c *gin.Context) {
	rows, err := s.db.Pool.Query(c.Request.Context(), `
		SELECT id, name, entity_id, acs_url, slo_url, certificate, name_id_format,
		       attribute_mappings, enabled, created_at, updated_at
		FROM saml_service_providers
		ORDER BY name ASC
	`)
	if err != nil {
		s.logger.Error("Failed to list SAML service providers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list service providers"})
		return
	}
	defer rows.Close()

	var providers []SAMLServiceProvider
	for rows.Next() {
		var sp SAMLServiceProvider
		var sloURL, certificate *string
		var attrMappingsJSON []byte

		if err := rows.Scan(&sp.ID, &sp.Name, &sp.EntityID, &sp.ACSURL, &sloURL,
			&certificate, &sp.NameIDFormat, &attrMappingsJSON, &sp.Enabled,
			&sp.CreatedAt, &sp.UpdatedAt); err != nil {
			s.logger.Error("Failed to scan SAML service provider", zap.Error(err))
			continue
		}

		if sloURL != nil {
			sp.SLOURL = *sloURL
		}
		if certificate != nil {
			sp.Certificate = *certificate
		}
		if len(attrMappingsJSON) > 0 {
			_ = json.Unmarshal(attrMappingsJSON, &sp.AttributeMappings)
		}

		providers = append(providers, sp)
	}

	if providers == nil {
		providers = []SAMLServiceProvider{}
	}

	c.JSON(http.StatusOK, providers)
}

// handleCreateSAMLServiceProvider creates a new SP registration
func (s *Service) handleCreateSAMLServiceProvider(c *gin.Context) {
	var req struct {
		Name              string            `json:"name" binding:"required"`
		EntityID          string            `json:"entity_id" binding:"required"`
		ACSURL            string            `json:"acs_url" binding:"required"`
		SLOURL            string            `json:"slo_url"`
		Certificate       string            `json:"certificate"`
		NameIDFormat      string            `json:"name_id_format"`
		AttributeMappings map[string]string `json:"attribute_mappings"`
		Enabled           bool              `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	if req.NameIDFormat == "" {
		req.NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	}

	id := uuid.New().String()
	attrMappingsJSON, _ := json.Marshal(req.AttributeMappings)
	now := time.Now()

	_, err := s.db.Pool.Exec(c.Request.Context(), `
		INSERT INTO saml_service_providers (id, name, entity_id, acs_url, slo_url, certificate,
		                                    name_id_format, attribute_mappings, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, id, req.Name, req.EntityID, req.ACSURL, req.SLOURL, req.Certificate,
		req.NameIDFormat, attrMappingsJSON, req.Enabled, now, now)

	if err != nil {
		s.logger.Error("Failed to create SAML service provider", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create service provider"})
		return
	}

	sp := SAMLServiceProvider{
		ID:                id,
		Name:              req.Name,
		EntityID:          req.EntityID,
		ACSURL:            req.ACSURL,
		SLOURL:            req.SLOURL,
		Certificate:       req.Certificate,
		NameIDFormat:      req.NameIDFormat,
		AttributeMappings: req.AttributeMappings,
		Enabled:           req.Enabled,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	s.logger.Info("Created SAML service provider",
		zap.String("id", id),
		zap.String("name", req.Name),
		zap.String("entity_id", req.EntityID),
	)

	c.JSON(http.StatusCreated, sp)
}

// handleUpdateSAMLServiceProvider updates an existing SP registration
func (s *Service) handleUpdateSAMLServiceProvider(c *gin.Context) {
	spID := c.Param("id")

	var req struct {
		Name              string            `json:"name"`
		EntityID          string            `json:"entity_id"`
		ACSURL            string            `json:"acs_url"`
		SLOURL            string            `json:"slo_url"`
		Certificate       string            `json:"certificate"`
		NameIDFormat      string            `json:"name_id_format"`
		AttributeMappings map[string]string `json:"attribute_mappings"`
		Enabled           *bool             `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	attrMappingsJSON, _ := json.Marshal(req.AttributeMappings)

	result, err := s.db.Pool.Exec(c.Request.Context(), `
		UPDATE saml_service_providers
		SET name = COALESCE(NULLIF($2, ''), name),
		    entity_id = COALESCE(NULLIF($3, ''), entity_id),
		    acs_url = COALESCE(NULLIF($4, ''), acs_url),
		    slo_url = $5,
		    certificate = $6,
		    name_id_format = COALESCE(NULLIF($7, ''), name_id_format),
		    attribute_mappings = COALESCE($8, attribute_mappings),
		    enabled = COALESCE($9, enabled),
		    updated_at = NOW()
		WHERE id = $1
	`, spID, req.Name, req.EntityID, req.ACSURL, req.SLOURL, req.Certificate,
		req.NameIDFormat, attrMappingsJSON, req.Enabled)

	if err != nil {
		s.logger.Error("Failed to update SAML service provider", zap.Error(err), zap.String("id", spID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update service provider"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Service provider not found"})
		return
	}

	s.logger.Info("Updated SAML service provider", zap.String("id", spID))
	c.JSON(http.StatusOK, gin.H{"message": "Service provider updated"})
}

// handleDeleteSAMLServiceProvider deletes an SP registration
func (s *Service) handleDeleteSAMLServiceProvider(c *gin.Context) {
	spID := c.Param("id")

	result, err := s.db.Pool.Exec(c.Request.Context(),
		"DELETE FROM saml_service_providers WHERE id = $1", spID)
	if err != nil {
		s.logger.Error("Failed to delete SAML service provider", zap.Error(err), zap.String("id", spID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete service provider"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Service provider not found"})
		return
	}

	s.logger.Info("Deleted SAML service provider", zap.String("id", spID))
	c.JSON(http.StatusOK, gin.H{"message": "Service provider deleted"})
}

// --- Helper functions ---

// getSAMLServiceProviderByEntityID looks up an SP by its entity_id
func (s *Service) getSAMLServiceProviderByEntityID(ctx context.Context, entityID string) (*SAMLServiceProvider, error) {
	var sp SAMLServiceProvider
	var sloURL, certificate *string
	var attrMappingsJSON []byte

	err := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, entity_id, acs_url, slo_url, certificate, name_id_format,
		       attribute_mappings, enabled, created_at, updated_at
		FROM saml_service_providers
		WHERE entity_id = $1
	`, entityID).Scan(&sp.ID, &sp.Name, &sp.EntityID, &sp.ACSURL, &sloURL,
		&certificate, &sp.NameIDFormat, &attrMappingsJSON, &sp.Enabled,
		&sp.CreatedAt, &sp.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("service provider not found: %w", err)
	}

	if sloURL != nil {
		sp.SLOURL = *sloURL
	}
	if certificate != nil {
		sp.Certificate = *certificate
	}
	if len(attrMappingsJSON) > 0 {
		_ = json.Unmarshal(attrMappingsJSON, &sp.AttributeMappings)
	}

	return &sp, nil
}

// getAuthenticatedIdPUser checks if the current request has a valid user session
// Returns userID, email, firstName, lastName, groups or error if not authenticated
func (s *Service) getAuthenticatedIdPUser(c *gin.Context) (string, string, string, string, []string, error) {
	// Check Authorization header for a Bearer token
	authHeader := c.GetHeader("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		return s.extractUserFromToken(tokenStr)
	}

	// Check for session cookie
	sessionCookie, err := c.Cookie("openidx_session")
	if err == nil && sessionCookie != "" {
		return s.extractUserFromSession(c.Request.Context(), sessionCookie)
	}

	return "", "", "", "", nil, fmt.Errorf("user not authenticated")
}

// extractUserFromToken parses a JWT and extracts user details
func (s *Service) extractUserFromToken(tokenStr string) (string, string, string, string, []string, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.publicKey, nil
	})
	if err != nil {
		return "", "", "", "", nil, fmt.Errorf("invalid token: %w", err)
	}
	if !token.Valid {
		return "", "", "", "", nil, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", "", "", nil, fmt.Errorf("invalid token claims")
	}

	userID, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)

	if userID == "" {
		return "", "", "", "", nil, fmt.Errorf("missing sub claim")
	}

	// Fetch user details from database
	var firstName, lastName string
	_ = s.db.Pool.QueryRow(context.Background(),
		"SELECT COALESCE(first_name, ''), COALESCE(last_name, '') FROM users WHERE id = $1",
		userID).Scan(&firstName, &lastName)

	// Fetch groups
	groups := s.getUserGroups(context.Background(), userID)

	return userID, email, firstName, lastName, groups, nil
}

// extractUserFromSession resolves a session cookie to user details
func (s *Service) extractUserFromSession(ctx context.Context, sessionID string) (string, string, string, string, []string, error) {
	var userID string
	err := s.db.Pool.QueryRow(ctx,
		"SELECT user_id FROM sessions WHERE id = $1 AND expires_at > NOW()",
		sessionID).Scan(&userID)
	if err != nil {
		return "", "", "", "", nil, fmt.Errorf("invalid session: %w", err)
	}

	var email, firstName, lastName string
	err = s.db.Pool.QueryRow(ctx,
		"SELECT COALESCE(email, ''), COALESCE(first_name, ''), COALESCE(last_name, '') FROM users WHERE id = $1",
		userID).Scan(&email, &firstName, &lastName)
	if err != nil {
		return "", "", "", "", nil, fmt.Errorf("user not found: %w", err)
	}

	groups := s.getUserGroups(ctx, userID)

	return userID, email, firstName, lastName, groups, nil
}

// getUserGroups fetches group names for a user
func (s *Service) getUserGroups(ctx context.Context, userID string) []string {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT g.name FROM groups g
		INNER JOIN group_memberships gm ON gm.group_id = g.id
		WHERE gm.user_id = $1
	`, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var groups []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			groups = append(groups, name)
		}
	}
	return groups
}

// buildSAMLResponse builds a SAML Response XML string
func (s *Service) buildSAMLResponse(userID, email, firstName, lastName string, groups []string, sp *SAMLServiceProvider, requestID string) (string, error) {
	now := time.Now().UTC()
	responseID := "_" + uuid.New().String()
	assertionID := "_" + uuid.New().String()
	sessionIndex := "_" + uuid.New().String()

	notBefore := now.Add(-5 * time.Minute)
	notOnOrAfter := now.Add(5 * time.Minute)

	// Determine NameID value based on format
	nameIDValue := email
	nameIDFormat := sp.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	}
	if nameIDFormat == "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" {
		nameIDValue = userID
	}

	// Build attributes
	attributes := []IdPAttribute{
		{
			Name:       "email",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:     []IdPAttributeValue{{Value: email}},
		},
		{
			Name:       "firstName",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:     []IdPAttributeValue{{Value: firstName}},
		},
		{
			Name:       "lastName",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:     []IdPAttributeValue{{Value: lastName}},
		},
	}

	// Apply attribute mappings if configured
	if sp.AttributeMappings != nil {
		mappedAttrs := make([]IdPAttribute, 0, len(attributes))
		for _, attr := range attributes {
			mappedName := attr.Name
			if mapped, ok := sp.AttributeMappings[attr.Name]; ok {
				mappedName = mapped
			}
			attr.Name = mappedName
			mappedAttrs = append(mappedAttrs, attr)
		}
		attributes = mappedAttrs
	}

	// Add groups attribute
	if len(groups) > 0 {
		groupValues := make([]IdPAttributeValue, len(groups))
		for i, g := range groups {
			groupValues[i] = IdPAttributeValue{Value: g}
		}
		groupAttrName := "groups"
		if sp.AttributeMappings != nil {
			if mapped, ok := sp.AttributeMappings["groups"]; ok {
				groupAttrName = mapped
			}
		}
		attributes = append(attributes, IdPAttribute{
			Name:       groupAttrName,
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:     groupValues,
		})
	}

	response := IdPSAMLResponse{
		XMLNS:        "urn:oasis:names:tc:SAML:2.0:protocol",
		XMLNSSAML:    "urn:oasis:names:tc:SAML:2.0:assertion",
		ID:           responseID,
		Version:      "2.0",
		IssueInstant: now.Format(time.RFC3339),
		Destination:  sp.ACSURL,
		InResponseTo: requestID,
		Issuer: IdPIssuer{
			Value: s.issuer,
		},
		Status: IdPStatus{
			StatusCode: IdPStatusCode{
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
		Assertion: IdPAssertion{
			XMLNS:        "urn:oasis:names:tc:SAML:2.0:assertion",
			ID:           assertionID,
			Version:      "2.0",
			IssueInstant: now.Format(time.RFC3339),
			Issuer: IdPIssuer{
				Value: s.issuer,
			},
			Subject: IdPSubject{
				NameID: IdPNameID{
					Format: nameIDFormat,
					Value:  nameIDValue,
				},
				SubjectConfirmation: IdPSubjectConfirmation{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: IdPSubjectConfirmationData{
						NotOnOrAfter: notOnOrAfter.Format(time.RFC3339),
						Recipient:    sp.ACSURL,
						InResponseTo: requestID,
					},
				},
			},
			Conditions: IdPConditions{
				NotBefore:    notBefore.Format(time.RFC3339),
				NotOnOrAfter: notOnOrAfter.Format(time.RFC3339),
				AudienceRestriction: IdPAudienceRestriction{
					Audience: sp.EntityID,
				},
			},
			AuthnStatement: IdPAuthnStatement{
				AuthnInstant: now.Format(time.RFC3339),
				SessionIndex: sessionIndex,
				AuthnContext: IdPAuthnContext{
					AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				},
			},
			AttributeStatement: IdPAttributeStatement{
				Attributes: attributes,
			},
		},
	}

	output, err := xml.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SAML response: %w", err)
	}

	return xml.Header + string(output), nil
}

// signSAMLXML signs SAML XML with RSA-SHA256 and embeds the signature
func (s *Service) signSAMLXML(xmlData []byte) (string, error) {
	// Compute SHA-256 digest of the XML content
	digest := sha256.Sum256(xmlData)
	digestBase64 := base64.StdEncoding.EncodeToString(digest[:])

	// Sign the digest with RSA-SHA256
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign XML: %w", err)
	}
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	// Build XML Signature element
	sig := IdPSignatureXML{
		XMLNS: "http://www.w3.org/2000/09/xmldsig#",
		SignedInfo: IdPSignedInfo{
			CanonicalizationMethod: IdPAlgorithm{
				Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
			},
			SignatureMethod: IdPAlgorithm{
				Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			},
			Reference: IdPSignatureReference{
				URI: "",
				Transforms: IdPTransforms{
					Transform: []IdPAlgorithm{
						{Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature"},
						{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
					},
				},
				DigestMethod: IdPAlgorithm{
					Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
				},
				DigestValue: digestBase64,
			},
		},
		SignatureValue: signatureBase64,
	}

	sigXML, err := xml.MarshalIndent(sig, "  ", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal signature: %w", err)
	}

	// Insert signature into the Response (after the Issuer element)
	xmlStr := string(xmlData)
	issuerClose := "</saml:Issuer>"
	idx := strings.Index(xmlStr, issuerClose)
	if idx == -1 {
		// Fallback: just append signature before closing tag
		return xmlStr, nil
	}

	insertPos := idx + len(issuerClose)
	signedXML := xmlStr[:insertPos] + "\n" + string(sigXML) + xmlStr[insertPos:]

	return signedXML, nil
}

// idpDeflateAndEncode deflates and base64 encodes data for HTTP-Redirect binding
func idpDeflateAndEncode(data []byte) (string, error) {
	var buf strings.Builder
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(data); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(buf.String())), nil
}

