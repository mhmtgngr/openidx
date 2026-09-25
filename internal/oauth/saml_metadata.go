// Package oauth provides SAML IdP Metadata functionality
package oauth

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// IdPMetadata represents the complete SAML IdP Metadata XML structure
type IdPMetadata struct {
	XMLName          xml.Name          `xml:"md:EntityDescriptor"`
	XMLNS            string            `xml:"xmlns:md,attr"`
	XMLNSDSig        string            `xml:"xmlns:ds,attr"`
	XMLNSSAML        string            `xml:"xmlns:saml,attr"`
	EntityID         string            `xml:"entityID,attr"`
	ID               string            `xml:"ID,attr,omitempty"`
	ValidUntil       string            `xml:"validUntil,attr,omitempty"`
	CacheDuration    string            `xml:"cacheDuration,attr,omitempty"`
	IDPSSODescriptor IDPSSODescriptor  `xml:"md:IDPSSODescriptor"`
	Organization     *IdPOrganization  `xml:"md:Organization,omitempty"`
	ContactPerson    *IdPContactPerson `xml:"md:ContactPerson,omitempty"`
}

// IDPSSODescriptor describes the IdP's SSO capabilities
type IDPSSODescriptor struct {
	XMLName                    xml.Name                       `xml:"md:IDPSSODescriptor"`
	WantAuthnRequestsSigned    bool                           `xml:"WantAuthnRequestsSigned,attr"`
	ProtocolSupportEnumeration string                         `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptors             []IdPKeyDescriptor             `xml:"md:KeyDescriptor"`
	NameIDFormats              []IdPNameIDFormat              `xml:"md:NameIDFormat"`
	SingleSignOnServices       []IdPSingleSignOnService       `xml:"md:SingleSignOnService"`
	SingleLogoutServices       []IdPSingleLogoutService       `xml:"md:SingleLogoutService,omitempty"`
	ArtifactResolutionServices []IdPArtifactResolutionService `xml:"md:ArtifactResolutionService,omitempty"`
}

// IdPKeyDescriptor describes a cryptographic key used by the IdP
type IdPKeyDescriptor struct {
	XMLName xml.Name   `xml:"md:KeyDescriptor"`
	Use     string     `xml:"use,attr"` // "signing" or "encryption"
	KeyInfo IdPKeyInfo `xml:"ds:KeyInfo"`
}

// IdPKeyInfo holds key information as defined in XML DSig
type IdPKeyInfo struct {
	XMLName  xml.Name    `xml:"ds:KeyInfo"`
	X509Data IdPX509Data `xml:"ds:X509Data"`
}

// IdPX509Data holds X.509 certificate data
type IdPX509Data struct {
	XMLName         xml.Name `xml:"ds:X509Data"`
	X509Certificate string   `xml:"ds:X509Certificate"`
}

// IdPNameIDFormat specifies a supported NameID format
type IdPNameIDFormat struct {
	XMLName xml.Name `xml:"md:NameIDFormat"`
	Value   string   `xml:",chardata"`
}

// IdPSingleSignOnService describes an SSO endpoint
type IdPSingleSignOnService struct {
	XMLName  xml.Name `xml:"md:SingleSignOnService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
}

// IdPSingleLogoutService describes an SLO endpoint
type IdPSingleLogoutService struct {
	XMLName  xml.Name `xml:"md:SingleLogoutService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
}

// IdPArtifactResolutionService describes an artifact resolution endpoint
type IdPArtifactResolutionService struct {
	XMLName  xml.Name `xml:"md:ArtifactResolutionService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
	Index    int      `xml:"index,attr"`
}

// IdPOrganization describes the organization. The child element names come
// from the SAML 2.0 metadata schema: md:OrganizationName,
// md:OrganizationDisplayName, md:OrganizationURL — NOT md:Name / md:DisplayName
// / md:URL, which the previous version used (and which would have produced
// malformed metadata that SPs reject).
type IdPOrganization struct {
	XMLName     xml.Name         `xml:"md:Organization"`
	Name        IdPLocalizedName `xml:"md:OrganizationName"`
	DisplayName IdPLocalizedName `xml:"md:OrganizationDisplayName"`
	URL         IdPLocalizedName `xml:"md:OrganizationURL"`
}

// IdPLocalizedName holds a localized string. It's embedded as multiple
// distinct child elements of IdPOrganization (Name / DisplayName / URL), so
// the element name comes from the parent field's xml tag — no XMLName here
// (an XMLName would force every use site to emit the same element name).
type IdPLocalizedName struct {
	Value string `xml:",chardata"`
	Lang  string `xml:"lang,attr,omitempty"`
}

// IdPContactPerson describes a contact person
type IdPContactPerson struct {
	XMLName      xml.Name `xml:"md:ContactPerson"`
	ContactType  string   `xml:"contactType,attr"`
	Company      string   `xml:"md:Company,omitempty"`
	GivenName    string   `xml:"md:GivenName,omitempty"`
	SurName      string   `xml:"md:SurName,omitempty"`
	EmailAddress string   `xml:"md:EmailAddress,omitempty"`
}

// MetadataBuilder builds SAML IdP metadata
type MetadataBuilder struct {
	idp             *Service
	entityID        string
	baseURL         string
	validUntil      time.Time
	cacheDuration   string
	wantAuthnSigned bool
	organization    *IdPOrganization
	contactPerson   *IdPContactPerson
}

// NewMetadataBuilder creates a new metadata builder
func (s *Service) NewMetadataBuilder() *MetadataBuilder {
	return &MetadataBuilder{
		idp:             s,
		validUntil:      time.Now().UTC().Add(24 * time.Hour),
		cacheDuration:   "PT1H", // 1 hour in ISO 8601 duration format
		wantAuthnSigned: false,
	}
}

// SetEntityID sets the IdP entity ID
func (b *MetadataBuilder) SetEntityID(entityID string) *MetadataBuilder {
	b.entityID = entityID
	return b
}

// SetBaseURL sets the base URL for constructing endpoint URLs
func (b *MetadataBuilder) SetBaseURL(baseURL string) *MetadataBuilder {
	b.baseURL = baseURL
	return b
}

// SetValidUntil sets the metadata validity period
func (b *MetadataBuilder) SetValidUntil(until time.Time) *MetadataBuilder {
	b.validUntil = until
	return b
}

// SetCacheDuration sets the recommended cache duration
func (b *MetadataBuilder) SetCacheDuration(duration string) *MetadataBuilder {
	b.cacheDuration = duration
	return b
}

// SetWantAuthnSigned sets whether AuthnRequests must be signed
func (b *MetadataBuilder) SetWantAuthnSigned(want bool) *MetadataBuilder {
	b.wantAuthnSigned = want
	return b
}

// SetOrganization sets the organization information
func (b *MetadataBuilder) SetOrganization(name, displayName, url string) *MetadataBuilder {
	b.organization = &IdPOrganization{
		Name:        IdPLocalizedName{Value: name},
		DisplayName: IdPLocalizedName{Value: displayName},
		URL:         IdPLocalizedName{Value: url},
	}
	return b
}

// SetContactPerson sets the contact person information
func (b *MetadataBuilder) SetContactPerson(contactType, company, givenName, surName, email string) *MetadataBuilder {
	b.contactPerson = &IdPContactPerson{
		ContactType:  contactType,
		Company:      company,
		GivenName:    givenName,
		SurName:      surName,
		EmailAddress: email,
	}
	return b
}

// Build generates the metadata XML
func (b *MetadataBuilder) Build() (*IdPMetadata, error) {
	if b.entityID == "" {
		b.entityID = b.idp.issuer
	}

	// Get the X.509 certificate data (public key as cert format)
	certData, err := b.idp.getSigningCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing certificate: %w", err)
	}

	// Build the SSO URLs
	ssoURL := b.baseURL + "/saml/idp/sso"
	sloURL := b.baseURL + "/saml/idp/slo"

	metadata := &IdPMetadata{
		XMLNS:         SAMLMetadataNamespace,
		XMLNSDSig:     XMLDSigNamespace,
		XMLNSSAML:     SAMLAssertionNamespace,
		EntityID:      b.entityID,
		ID:            "_" + uuid.New().String(),
		ValidUntil:    b.validUntil.Format(time.RFC3339),
		CacheDuration: b.cacheDuration,
		IDPSSODescriptor: IDPSSODescriptor{
			WantAuthnRequestsSigned:    b.wantAuthnSigned,
			ProtocolSupportEnumeration: SAMLProtocolNamespace,
			KeyDescriptors: []IdPKeyDescriptor{
				{
					Use: "signing",
					KeyInfo: IdPKeyInfo{
						X509Data: IdPX509Data{
							X509Certificate: certData,
						},
					},
				},
				{
					Use: "encryption",
					KeyInfo: IdPKeyInfo{
						X509Data: IdPX509Data{
							X509Certificate: certData,
						},
					},
				},
			},
			NameIDFormats: []IdPNameIDFormat{
				{Value: NameIDFormatEmail},
				{Value: NameIDFormatPersistent},
				{Value: NameIDFormatTransient},
				{Value: NameIDFormatUnspecified},
			},
			SingleSignOnServices: []IdPSingleSignOnService{
				{
					Binding:  SAMLBindingHTTPRedirect,
					Location: ssoURL,
				},
				{
					Binding:  SAMLBindingHTTPPost,
					Location: ssoURL,
				},
			},
			SingleLogoutServices: []IdPSingleLogoutService{
				{
					Binding:  SAMLBindingHTTPRedirect,
					Location: sloURL,
				},
				{
					Binding:  SAMLBindingHTTPPost,
					Location: sloURL,
				},
			},
		},
		Organization:  b.organization,
		ContactPerson: b.contactPerson,
	}

	return metadata, nil
}

// handleIdPMetadata returns the SAML IdP metadata XML
// GET /saml/idp/metadata
func (s *Service) handleIdPMetadata(c *gin.Context) {
	baseURL := s.getBaseURL(c)

	builder := s.NewMetadataBuilder()
	builder.SetBaseURL(baseURL)

	// Set organization info
	orgName := "OpenIDX"
	builder.SetOrganization(orgName, orgName, s.getBaseURL(c))

	// Set technical contact
	techContact := "tech@example.com"
	builder.SetContactPerson("technical", orgName, "Technical", "Contact", techContact)

	metadata, err := builder.Build()
	if err != nil {
		s.logger.Error("Failed to build IdP metadata", zap.Error(err))
		c.String(http.StatusInternalServerError, "Failed to generate metadata")
		return
	}

	// Marshal to XML with proper formatting
	output, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		s.logger.Error("Failed to marshal IdP metadata", zap.Error(err))
		c.String(http.StatusInternalServerError, "Failed to generate metadata")
		return
	}

	// Set appropriate headers
	c.Header("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	c.Header("Cache-Control", "public, max-age=3600") // Cache for 1 hour

	c.String(http.StatusOK, xml.Header+string(output))
}

// getSigningCertificate returns the base64 DER of the IdP's real self-signed
// X.509 signing certificate for publication in SAML metadata. (The previous
// implementation published a bare PKIX public key wrapped in a CERTIFICATE PEM
// header, which is not a valid X.509 certificate and breaks SP onboarding.)
func (s *Service) getSigningCertificate() (string, error) {
	return s.samlSigningCertBase64()
}

// GenerateIdPMetadataXML generates and returns the IdP metadata as a string
// This is useful for testing and programmatic access
func (s *Service) GenerateIdPMetadataXML(baseURL string) (string, error) {
	builder := s.NewMetadataBuilder()
	builder.SetBaseURL(baseURL)
	builder.SetOrganization("OpenIDX", "OpenIDX", baseURL)
	builder.SetContactPerson("technical", "OpenIDX", "Technical", "Contact", "tech@example.com")

	metadata, err := builder.Build()
	if err != nil {
		return "", err
	}

	output, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return "", err
	}

	return xml.Header + string(output), nil
}

// StoreSAMLMetadata stores a SP's metadata in the database
// This is used when an SP uploads their metadata
func (s *Service) StoreSAMLMetadata(ctx context.Context, spID string, metadataXML string) error {
	// Parse the metadata to extract key information
	var spMetadata SPMetadata
	if err := xml.Unmarshal([]byte(metadataXML), &spMetadata); err != nil {
		return fmt.Errorf("failed to parse SP metadata: %w", err)
	}

	// Extract the ACS URL and the certificates. The signing certificate is the
	// one requests are verified against, so it is taken from a key the
	// metadata offers for signing -- never from an encryption-only key, which
	// is what the first KeyDescriptor used to be taken as whatever its use.
	acsURL := spMetadata.PostACSURL()
	certificate, encryptionCertificate := spMetadata.Certificates()

	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Update the SP record with the metadata info. This rewrites entity_id, the
	// ACS URL and the certificates from a document fetched over the network, so
	// a bare id here let a refresh triggered in one tenant repoint another
	// tenant's assertions.
	_, err = s.db.Pool.Exec(ctx, `
		UPDATE saml_service_providers
		SET entity_id = $1,
		    acs_url = COALESCE($2, acs_url),
		    certificate = COALESCE($3, certificate),
		    metadata_xml = $4,
		    encryption_certificate = $5,
		    require_signed_authn_requests = require_signed_authn_requests OR $6,
		    updated_at = NOW()
		WHERE id = $7 AND org_id = $8
	`, spMetadata.EntityID, nullIfBlank(acsURL), nullIfBlank(certificate), metadataXML,
		nullIfBlank(encryptionCertificate), spMetadata.SPSSODescriptor.AuthnRequestsSigned, spID, org.ID)

	return err
}

// SPMetadata is a service provider's SAML metadata document, parsed.
//
// These types are for PARSING, so their tags name the namespace URI, not a
// prefix. encoding/xml matches a tag like "md:EntityDescriptor" against the
// element's local name, which is never "md:EntityDescriptor", so the earlier
// prefixed tags could not parse any real metadata document: every import by
// URL or by pasted XML failed with "expected element type
// <md:EntityDescriptor> but have <EntityDescriptor>". The IdP's own metadata
// types above keep their prefixes, because they are only ever marshalled.
type SPMetadata struct {
	XMLName         xml.Name        `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID        string          `xml:"entityID,attr"`
	SPSSODescriptor SPSSODescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
}

// SPSSODescriptor describes the SP's SSO capabilities
type SPSSODescriptor struct {
	AuthnRequestsSigned        bool                         `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned       bool                         `xml:"WantAssertionsSigned,attr"`
	ProtocolSupportEnumeration string                       `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptors             []SPKeyDescriptor            `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	NameIDFormats              []string                     `xml:"urn:oasis:names:tc:SAML:2.0:metadata NameIDFormat"`
	AssertionConsumerServices  []SPAssertionConsumerService `xml:"urn:oasis:names:tc:SAML:2.0:metadata AssertionConsumerService"`
	SingleLogoutServices       []SPSingleLogoutService      `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService"`
}

// SPKeyDescriptor is a key in service provider metadata. An empty Use means
// the key serves both signing and encryption.
type SPKeyDescriptor struct {
	Use             string `xml:"use,attr"`
	X509Certificate string `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo>X509Data>X509Certificate"`
}

// SPAssertionConsumerService describes the SP's ACS endpoint
type SPAssertionConsumerService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    int    `xml:"index,attr"`
}

// SPSingleLogoutService describes the SP's SLO endpoint
type SPSingleLogoutService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

// Certificates returns the service provider's signing and encryption
// certificates. A KeyDescriptor without use serves both, and one with
// use="encryption" only encryption; the signing certificate is the one the IdP
// verifies requests against, so an encryption-only key must never land there.
// encryption is empty when the service provider publishes no key specifically
// for encryption, which means "encrypt to the signing certificate".
func (md *SPMetadata) Certificates() (signing, encryption string) {
	for _, kd := range md.SPSSODescriptor.KeyDescriptors {
		cert := strings.Join(strings.Fields(kd.X509Certificate), "")
		if cert == "" {
			continue
		}
		switch kd.Use {
		case "signing":
			if signing == "" {
				signing = cert
			}
		case "encryption":
			if encryption == "" {
				encryption = cert
			}
		case "":
			if signing == "" {
				signing = cert
			}
		}
	}
	if encryption == signing {
		encryption = ""
	}
	return signing, encryption
}

// PostACSURL returns the service provider's HTTP-POST AssertionConsumerService
// (the only binding this IdP answers with), falling back to the first one.
func (md *SPMetadata) PostACSURL() string {
	for _, acs := range md.SPSSODescriptor.AssertionConsumerServices {
		if acs.Binding == SAMLBindingHTTPPost && acs.Location != "" {
			return acs.Location
		}
	}
	if len(md.SPSSODescriptor.AssertionConsumerServices) > 0 {
		return md.SPSSODescriptor.AssertionConsumerServices[0].Location
	}
	return ""
}

// RedirectSLOURL returns the service provider's HTTP-Redirect
// SingleLogoutService (the binding this IdP sends LogoutRequests and
// LogoutResponses with), falling back to the first one.
func (md *SPMetadata) RedirectSLOURL() string {
	for _, slo := range md.SPSSODescriptor.SingleLogoutServices {
		if slo.Binding == SAMLBindingHTTPRedirect && slo.Location != "" {
			return slo.Location
		}
	}
	if len(md.SPSSODescriptor.SingleLogoutServices) > 0 {
		return md.SPSSODescriptor.SingleLogoutServices[0].Location
	}
	return ""
}

// FetchSAMLMetadata fetches and parses metadata from a remote URL
func (s *Service) FetchSAMLMetadata(ctx context.Context, metadataURL string) (*SPMetadata, error) {
	client := s.outboundHTTPClient("saml-metadata", 30*time.Second)

	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata fetch failed with status %d", resp.StatusCode)
	}

	var metadata SPMetadata
	if err := xml.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata XML: %w", err)
	}

	return &metadata, nil
}

// ValidateSAMLMetadata validates that SP metadata contains required fields
func ValidateSAMLMetadata(metadata *SPMetadata) error {
	if metadata.EntityID == "" {
		return fmt.Errorf("missing entityID")
	}

	if len(metadata.SPSSODescriptor.AssertionConsumerServices) == 0 {
		return fmt.Errorf("missing AssertionConsumerService")
	}

	for i, acs := range metadata.SPSSODescriptor.AssertionConsumerServices {
		if acs.Location == "" {
			return fmt.Errorf("AssertionConsumerService[%d] missing Location", i)
		}
	}

	if metadata.SPSSODescriptor.ProtocolSupportEnumeration == "" {
		return fmt.Errorf("missing ProtocolSupportEnumeration")
	}

	return nil
}
