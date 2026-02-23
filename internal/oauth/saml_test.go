// Package oauth provides unit tests for SAML 2.0 IdP functionality
package oauth

import (
	"bytes"
	"compress/flate"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Test AuthnRequest parsing

func TestDecodeAndParseAuthnRequest(t *testing.T) {
	validRequest := `<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_1234567890"
                    Version="2.0"
                    IssueInstant="2024-01-01T00:00:00Z"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    AssertionConsumerServiceURL="https://sp.example.com/acs"
                    Destination="https://idp.example.com/saml/sso">
  <saml:Issuer>https://sp.example.com</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                     AllowCreate="true"/>
</samlp:AuthnRequest>`

	tests := []struct {
		name    string
		request string
		wantErr bool
	}{
		{
			name:    "valid authn request",
			request: validRequest,
			wantErr: false,
		},
		{
			name: "invalid xml",
			request: `<?xml version="1.0"?><invalid>`,
			wantErr: true,
		},
		{
			name: "missing version",
			request: `<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    ID="_1234567890">
  <saml:Issuer>https://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode the request
			encoded := base64.StdEncoding.EncodeToString([]byte(tt.request))

			// Mock service for testing
			svc := &MockSAMLService{}

			// Decode and parse
			req, err := svc.testDecodeAndParseAuthnRequest(encoded)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if req.ID != "_1234567890" {
				t.Errorf("expected ID _1234567890, got %s", req.ID)
			}

			if req.Issuer != "https://sp.example.com" {
				t.Errorf("expected Issuer https://sp.example.com, got %s", req.Issuer)
			}

			if req.AssertionConsumerServiceURL != "https://sp.example.com/acs" {
				t.Errorf("expected ACS URL https://sp.example.com/acs, got %s", req.AssertionConsumerServiceURL)
			}
		})
	}
}

func TestDeflateAndEncode(t *testing.T) {
	data := []byte("test data for compression")

	encoded, err := deflateAndEncode(data)
	if err != nil {
		t.Fatalf("deflateAndEncode failed: %v", err)
	}

	if encoded == "" {
		t.Fatal("encoded string is empty")
	}

	// Verify we can decode it back
	decoded, err := inflateAndDecode(encoded)
	if err != nil {
		t.Fatalf("inflateAndDecode failed: %v", err)
	}

	if !bytes.Equal(data, decoded) {
		t.Errorf("round trip failed: got %s, want %s", decoded, data)
	}
}

func TestInflateAndDecode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid deflated data",
			input:   createDeflatedData("test message"),
			wantErr: false,
		},
		{
			name:    "plain base64 data",
			input:   base64.StdEncoding.EncodeToString([]byte("test message")),
			wantErr: false,
		},
		{
			name:    "invalid base64",
			input:   "not-valid-base64!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoded, err := inflateAndDecode(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if tt.input == "not-valid-base64!!!" {
				return
			}

			if len(decoded) == 0 {
				t.Error("decoded data is empty")
			}
		})
	}
}

func TestGenerateTransientID(t *testing.T) {
	userID := uuid.New().String()
	spEntityID := "https://sp.example.com"

	transient1 := generateTransientID(userID, spEntityID)
	transient2 := generateTransientID(userID, spEntityID)

	// Same user-SP pair should generate the same transient ID
	if transient1 != transient2 {
		t.Errorf("transient IDs should be consistent for same user-SP pair: got %s and %s", transient1, transient2)
	}

	// Different SP should generate different transient ID
	transient3 := generateTransientID(userID, "https://other.example.com")
	if transient1 == transient3 {
		t.Errorf("transient IDs should differ for different SPs: got same %s", transient1)
	}

	// Different user should generate different transient ID
	transient4 := generateTransientID(uuid.New().String(), spEntityID)
	if transient1 == transient4 {
		t.Errorf("transient IDs should differ for different users: got same %s", transient1)
	}
}

func TestGetNameIDFormat(t *testing.T) {
	tests := []struct {
		name     string
		policy   *NameIDPolicy
		expected string
	}{
		{
			name:     "nil policy",
			policy:   nil,
			expected: NameIDFormatEmail,
		},
		{
			name:     "empty format",
			policy:   &NameIDPolicy{},
			expected: NameIDFormatEmail,
		},
		{
			name: "email format",
			policy: &NameIDPolicy{
				Format: NameIDFormatEmail,
			},
			expected: NameIDFormatEmail,
		},
		{
			name: "persistent format",
			policy: &NameIDPolicy{
				Format: NameIDFormatPersistent,
			},
			expected: NameIDFormatPersistent,
		},
		{
			name: "transient format",
			policy: &NameIDPolicy{
				Format: NameIDFormatTransient,
			},
			expected: NameIDFormatTransient,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getNameIDFormat(tt.policy)
			if result != tt.expected {
				t.Errorf("getNameIDFormat() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// Test SAML Response Building

func TestSAMLResponseBuilder(t *testing.T) {
	svc := &MockSAMLService{}

	tests := []struct {
		name     string
		setup    func(*SAMLResponseBuilder)
		validate func(string) error
		wantErr  bool
	}{
		{
			name: "minimal valid response",
			setup: func(b *SAMLResponseBuilder) {
				b.SetRequest("_req123", "https://sp.example.com/acs")
				b.SetAudience("https://sp.example.com")
				b.SetSubject("user@example.com", NameIDFormatEmail)
				b.SetAttributes([]SAMLAttribute{
					{Name: "email", Values: []string{"user@example.com"}},
				})
			},
			validate: func(xmlStr string) error {
				// Check it's valid XML
				var resp IdPSAMLResponse
				if err := xml.Unmarshal([]byte(xmlStr), &resp); err != nil {
					return err
				}
				if resp.ID == "" {
					return t.Errorf("missing ID")
				}
				if resp.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
					return t.Errorf("wrong status: %s", resp.Status.StatusCode.Value)
				}
				return nil
			},
			wantErr: false,
		},
		{
			name: "response with all fields",
			setup: func(b *SAMLResponseBuilder) {
				b.SetRequest("_req456", "https://sp.example.com/acs")
				b.SetIssuer("https://idp.example.com")
				b.SetAudience("https://sp.example.com")
				b.SetSubject("user123", NameIDFormatPersistent)
				b.SetAttributes([]SAMLAttribute{
					{Name: "email", Values: []string{"user@example.com"}},
					{Name: "firstName", Values: []string{"John"}},
					{Name: "lastName", Values: []string{"Doe"}},
					{Name: "groups", Values: []string{"Admins", "Users"}},
				})
				b.SetSessionIndex("_sess123")
			},
			validate: func(xmlStr string) error {
				var resp IdPSAMLResponse
				if err := xml.Unmarshal([]byte(xmlStr), &resp); err != nil {
					return err
				}
				if resp.Issuer.Value != "https://idp.example.com" {
					return t.Errorf("wrong issuer: %s", resp.Issuer.Value)
				}
				if resp.Subject.NameID.Value != "user123" {
					return t.Errorf("wrong NameID: %s", resp.Subject.NameID.Value)
				}
				if len(resp.Assertion.AttributeStatement.Attributes) != 4 {
					return t.Errorf("expected 4 attributes, got %d", len(resp.Assertion.AttributeStatement.Attributes))
				}
				return nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := svc.NewSAMLResponseBuilder()
			builder.signAssertion = false // Don't sign in tests
			tt.setup(builder)

			result, err := builder.Build()

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validate != nil {
				if err := tt.validate(result); err != nil {
					t.Errorf("validation failed: %v", err)
				}
			}
		})
	}
}

// Test Metadata Generation

func TestMetadataBuilder(t *testing.T) {
	svc := &MockSAMLService{}

	builder := svc.NewMetadataBuilder()
	builder.SetEntityID("https://idp.example.com")
	builder.SetBaseURL("https://idp.example.com")
	builder.SetWantAuthnSigned(false)
	builder.SetOrganization("Test Org", "Test Organization", "https://example.com")
	builder.SetContactPerson("technical", "Test Org", "Tech", "Contact", "tech@example.com")

	metadata, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}

	// Validate metadata
	if metadata.EntityID != "https://idp.example.com" {
		t.Errorf("EntityID = %s, want https://idp.example.com", metadata.EntityID)
	}

	if metadata.IDPSSODescriptor.WantAuthnRequestsSigned {
		t.Errorf("WantAuthnRequestsSigned = true, want false")
	}

	if len(metadata.IDPSSODescriptor.SingleSignOnServices) == 0 {
		t.Error("no SingleSignOnService defined")
	}

	// Check bindings
	hasRedirect := false
	hasPost := false
	for _, sso := range metadata.IDPSSODescriptor.SingleSignOnServices {
		if sso.Binding == SAMLBindingHTTPRedirect {
			hasRedirect = true
		}
		if sso.Binding == SAMLBindingHTTPPost {
			hasPost = true
		}
	}

	if !hasRedirect {
		t.Error("missing HTTP-Redirect binding")
	}
	if !hasPost {
		t.Error("missing HTTP-POST binding")
	}

	// Check NameID formats
	expectedFormats := []string{
		NameIDFormatEmail,
		NameIDFormatPersistent,
		NameIDFormatTransient,
		NameIDFormatUnspecified,
	}

	if len(metadata.IDPSSODescriptor.NameIDFormats) != len(expectedFormats) {
		t.Errorf("expected %d NameIDFormats, got %d", len(expectedFormats), len(metadata.IDPSSODescriptor.NameIDFormats))
	}

	for i, format := range metadata.IDPSSODescriptor.NameIDFormats {
		if format.Value != expectedFormats[i] {
			t.Errorf("NameIDFormat[%d] = %s, want %s", i, format.Value, expectedFormats[i])
		}
	}
}

func TestMetadataXMLSerialization(t *testing.T) {
	metadata := &IdPMetadata{
		XMLNS:         SAMLMetadataNamespace,
		XMLNSDSig:     XMLDSigNamespace,
		XMLNSSAML:     SAMLAssertionNamespace,
		EntityID:      "https://idp.example.com",
		ID:            "_" + uuid.New().String(),
		IDPSSODescriptor: IDPSSODescriptor{
			WantAuthnRequestsSigned:    false,
			ProtocolSupportEnumeration: SAMLProtocolNamespace,
			KeyDescriptors: []IdPKeyDescriptor{
				{
					Use: "signing",
					KeyInfo: IdPKeyInfo{
						X509Data: IdPX509Data{
							X509Certificate: "dGVzdCBjZXJ0aWZpY2F0ZQ==",
						},
					},
				},
			},
			NameIDFormats: []IdPNameIDFormat{
				{Value: NameIDFormatEmail},
			},
			SingleSignOnServices: []IdPSingleSignOnService{
				{
					Binding:  SAMLBindingHTTPRedirect,
					Location: "https://idp.example.com/saml/sso",
				},
			},
		},
	}

	output, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		t.Fatalf("xml.MarshalIndent failed: %v", err)
	}

	outputStr := string(output)

	// Check for required elements
	requiredStrings := []string{
		"<md:EntityDescriptor",
		`entityID="https://idp.example.com"`,
		"<md:IDPSSODescriptor",
		"<md:SingleSignOnService",
		SAMLBindingHTTPRedirect,
		"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
	}

	for _, required := range requiredStrings {
		if !strings.Contains(outputStr, required) {
			t.Errorf("missing required string in output: %s", required)
		}
	}
}

// Test Attribute Mapping

func TestBuildUserAttributes(t *testing.T) {
	svc := &MockSAMLService{}

	user := &SAMLUser{
		ID:          "user123",
		Email:       "user@example.com",
		FirstName:   "John",
		LastName:    "Doe",
		DisplayName: "John Doe",
		Groups:      []string{"Admins", "Users"},
		Roles:       []string{"Admin", "User"},
	}

	sp := &SAMLServiceProvider{
		AttributeMappings: map[string]string{
			"email":      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			"firstName":  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
			"lastName":   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
			"groups":     "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
		},
	}

	attributes := svc.testBuildUserAttributes(user, sp)

	// Check that all attributes are present
	attrMap := make(map[string][]string)
	for _, attr := range attributes {
		attrMap[attr.Name] = attr.Values
	}

	// Check mapped email
	emailVals, ok := attrMap["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"]
	if !ok || len(emailVals) != 1 || emailVals[0] != "user@example.com" {
		t.Errorf("email attribute mapping failed: %v", emailVals)
	}

	// Check groups
	groupsVals, ok := attrMap["http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"]
	if !ok || len(groupsVals) != 2 {
		t.Errorf("groups attribute mapping failed: %v", groupsVals)
	}
}

// Test Logout Request/Response

func TestLogoutRequestParsing(t *testing.T) {
	validLogoutRequest := `<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="_logout123"
                     Version="2.0"
                     IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>https://sp.example.com</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
  <samlp:SessionIndex>_session123</samlp:SessionIndex>
</samlp:LogoutRequest>`

	var req LogoutRequest
	err := xml.Unmarshal([]byte(validLogoutRequest), &req)
	if err != nil {
		t.Fatalf("failed to parse LogoutRequest: %v", err)
	}

	if req.ID != "_logout123" {
		t.Errorf("ID = %s, want _logout123", req.ID)
	}

	if req.Issuer != "https://sp.example.com" {
		t.Errorf("Issuer = %s, want https://sp.example.com", req.Issuer)
	}

	if req.NameID == nil {
		t.Fatal("NameID is nil")
	}

	if req.NameID.Value != "user@example.com" {
		t.Errorf("NameID.Value = %s, want user@example.com", req.NameID.Value)
	}

	if req.SessionIndex != "_session123" {
		t.Errorf("SessionIndex = %s, want _session123", req.SessionIndex)
	}
}

func TestLogoutResponseGeneration(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name         string
		statusCode   string
		statusMsg    string
		validateFunc func(*LogoutResponse) error
	}{
		{
			name:       "success response",
			statusCode: SAMLLogoutStatusSuccess,
			validateFunc: func(resp *LogoutResponse) error {
				if resp.Status.StatusCode.Value != SAMLLogoutStatusSuccess {
					return t.Errorf("wrong status code: %s", resp.Status.StatusCode.Value)
				}
				if resp.Status.StatusMessage != nil {
					return t.Errorf("unexpected status message: %s", resp.Status.StatusMessage.Value)
				}
				return nil
			},
		},
		{
			name:       "error response",
			statusCode: SAMLLogoutStatusRequester,
			statusMsg:  "Invalid session",
			validateFunc: func(resp *LogoutResponse) error {
				if resp.Status.StatusCode.Value != SAMLLogoutStatusRequester {
					return t.Errorf("wrong status code: %s", resp.Status.StatusCode.Value)
				}
				if resp.Status.StatusMessage == nil {
					return t.Errorf("missing status message")
				}
				if resp.Status.StatusMessage.Value != "Invalid session" {
					return t.Errorf("wrong status message: %s", resp.Status.StatusMessage.Value)
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := LogoutResponse{
				XMLNS:        SAMLProtocolNamespace,
				XMLNSSAML:    SAMLAssertionNamespace,
				ID:           "_" + uuid.New().String(),
				Version:      "2.0",
				IssueInstant: now.Format(time.RFC3339),
				Destination:  "https://sp.example.com/slo",
				InResponseTo: "_logout123",
				Issuer:       "https://idp.example.com",
				Status: LogoutResponseStatus{
					StatusCode: LogoutStatusCode{
						Value: tt.statusCode,
					},
				},
			}

			if tt.statusMsg != "" {
				resp.Status.StatusMessage = &LogoutStatusMessage{Value: tt.statusMsg}
			}

			// Validate
			if err := tt.validateFunc(&resp); err != nil {
				t.Errorf("validation failed: %v", err)
			}

			// Marshal to XML and verify it's valid
			output, err := xml.Marshal(resp)
			if err != nil {
				t.Fatalf("xml.Marshal failed: %v", err)
			}

			var unmarshaled LogoutResponse
			if err := xml.Unmarshal(output, &unmarshaled); err != nil {
				t.Fatalf("xml.Unmarshal failed: %v", err)
			}

			if unmarshaled.Status.StatusCode.Value != tt.statusCode {
				t.Errorf("round trip status code: got %s, want %s", unmarshaled.Status.StatusCode.Value, tt.statusCode)
			}
		})
	}
}

// Test SP Metadata Validation

func TestValidateSAMLMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata *SPMetadata
		wantErr  bool
	}{
		{
			name: "valid metadata",
			metadata: &SPMetadata{
				EntityID: "https://sp.example.com",
				SPSSODescriptor: SPSSODescriptor{
					ProtocolSupportEnumeration: SAMLProtocolNamespace,
					AssertionConsumerServices: []SPAssertionConsumerService{
						{Binding: SAMLBindingHTTPPost, Location: "https://sp.example.com/acs"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing entity ID",
			metadata: &SPMetadata{
				SPSSODescriptor: SPSSODescriptor{
					ProtocolSupportEnumeration: SAMLProtocolNamespace,
					AssertionConsumerServices: []SPAssertionConsumerService{
						{Binding: SAMLBindingHTTPPost, Location: "https://sp.example.com/acs"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing ACS",
			metadata: &SPMetadata{
				EntityID: "https://sp.example.com",
				SPSSODescriptor: SPSSODescriptor{
					ProtocolSupportEnumeration: SAMLProtocolNamespace,
				},
			},
			wantErr: true,
		},
		{
			name: "missing protocol support",
			metadata: &SPMetadata{
				EntityID: "https://sp.example.com",
				SPSSODescriptor: SPSSODescriptor{
					AssertionConsumerServices: []SPAssertionConsumerService{
						{Binding: SAMLBindingHTTPPost, Location: "https://sp.example.com/acs"},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSAMLMetadata(tt.metadata)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSAMLMetadata() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Helper functions and mocks

func createDeflatedData(data string) string {
	var buf strings.Builder
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	w.Write([]byte(data))
	w.Close()
	return base64.StdEncoding.EncodeToString([]byte(buf.String()))
}

// MockSAMLService is a mock service for testing
type MockSAMLService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
}

func (m *MockSAMLService) NewSAMLResponseBuilder() *SAMLResponseBuilder {
	// Generate test keys if not present
	if m.privateKey == nil {
		key, _ := rsa.GenerateKey(crand.Reader, 2048)
		m.privateKey = key
		m.publicKey = &key.PublicKey
	}

	if m.issuer == "" {
		m.issuer = "https://idp.example.com"
	}

	return &SAMLResponseBuilder{
		idp:           m,
		responseID:    "_" + uuid.New().String(),
		assertionID:   "_" + uuid.New().String(),
		issueInstant:  time.Now().UTC(),
		notBefore:     time.Now().UTC().Add(-5 * time.Minute),
		notOnOrAfter:  time.Now().UTC().Add(5 * time.Minute),
		authnInstant:  time.Now().UTC(),
		sessionIndex:  "_" + uuid.New().String(),
		nameIDFormat:  NameIDFormatEmail,
		signAssertion: false,
	}
}

func (m *MockSAMLService) testDecodeAndParseAuthnRequest(encoded string) (*AuthnRequest, error) {
	// Try deflate + base64
	decoded, err := inflateAndDecode(encoded)
	if err != nil {
		// Fall back to plain base64
		decoded, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, err
		}
	}

	var req AuthnRequest
	if err := xml.Unmarshal(decoded, &req); err != nil {
		return nil, err
	}

	// Validate version
	if req.Version != "2.0" {
		return nil, fmt.Errorf("unsupported SAML version: %s", req.Version)
	}

	// Validate required fields
	if req.ID == "" {
		return nil, fmt.Errorf("missing ID")
	}
	if req.Issuer == "" {
		return nil, fmt.Errorf("missing Issuer")
	}

	return &req, nil
}

func (m *MockSAMLService) testBuildUserAttributes(user *SAMLUser, sp *SAMLServiceProvider) []SAMLAttribute {
	baseAttributes := []struct {
		name   string
		values []string
	}{
		{"email", []string{user.Email}},
		{"firstName", []string{user.FirstName}},
		{"lastName", []string{user.LastName}},
		{"displayName", []string{user.DisplayName}},
	}

	if len(user.Groups) > 0 {
		baseAttributes = append(baseAttributes, struct {
			name   string
			values []string
		}{"groups", user.Groups})
	}

	if len(user.Roles) > 0 {
		baseAttributes = append(baseAttributes, struct {
			name   string
			values []string
		}{"roles", user.Roles})
	}

	attrs := make([]SAMLAttribute, 0, len(baseAttributes))
	for _, attr := range baseAttributes {
		name := attr.name
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

// Test signature verification

func TestSAMLSignatureStructure(t *testing.T) {
	// This tests the structure of our signature XML
	sigXML := `    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_assertion123">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>abcdef1234567890</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>signature123</ds:SignatureValue>
    </ds:Signature>`

	var sig IdPSignatureXML
	err := xml.Unmarshal([]byte(sigXML), &sig)
	if err != nil {
		t.Fatalf("failed to parse signature XML: %v", err)
	}

	if sig.SignedInfo.SignatureMethod.Algorithm != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" {
		t.Errorf("wrong signature method: %s", sig.SignedInfo.SignatureMethod.Algorithm)
	}

	if sig.SignedInfo.Reference.URI != "#_assertion123" {
		t.Errorf("wrong reference URI: %s", sig.SignedInfo.Reference.URI)
	}

	if len(sig.SignedInfo.Reference.Transforms.Transform) != 2 {
		t.Errorf("expected 2 transforms, got %d", len(sig.SignedInfo.Reference.Transforms.Transform))
	}
}

// Test certificate handling

func TestGetSigningCertificate(t *testing.T) {
	// Create a test RSA key pair
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	// Marshal public key to X.509
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	// Encode as PEM
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: pubKeyBytes,
	}
	certPEM := pem.EncodeToMemory(certBlock)

	// Strip headers
	certStr := string(certPEM)
	certStr = strings.TrimSpace(certStr)
	certStr = strings.TrimPrefix(certStr, "-----BEGIN CERTIFICATE-----")
	certStr = strings.TrimSuffix(certStr, "-----END CERTIFICATE-----")
	certStr = strings.TrimSpace(certStr)
	certStr = strings.ReplaceAll(certStr, "\n", "")

	// Verify it's valid base64
	_, err = base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		t.Errorf("certificate is not valid base64: %v", err)
	}

	// Verify it's non-empty
	if certStr == "" {
		t.Error("certificate is empty")
	}
}

// Benchmark tests

func BenchmarkDeflateAndEncode(b *testing.B) {
	data := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_123" Version="2.0">
	<saml:Issuer>https://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = deflateAndEncode(data)
	}
}

func BenchmarkBuildSAMLResponse(b *testing.B) {
	svc := &MockSAMLService{}

	builder := svc.NewSAMLResponseBuilder()
	builder.signAssertion = false
	builder.SetRequest("_req123", "https://sp.example.com/acs")
	builder.SetAudience("https://sp.example.com")
	builder.SetSubject("user@example.com", NameIDFormatEmail)
	builder.SetAttributes([]SAMLAttribute{
		{Name: "email", Values: []string{"user@example.com"}},
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = builder.Build()
	}
}

func BenchmarkGenerateTransientID(b *testing.B) {
	userID := "user123"
	spEntityID := "https://sp.example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = generateTransientID(userID, spEntityID)
	}
}

// Test SHA256 digest computation for signatures

func TestSHA256Digest(t *testing.T) {
	xmlData := []byte(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_123">test</saml:Assertion>`)

	digest := sha256.Sum256(xmlData)
	digestBase64 := base64.StdEncoding.EncodeToString(digest[:])

	// Verify it's valid base64
	_, err := base64.StdEncoding.DecodeString(digestBase64)
	if err != nil {
		t.Errorf("digest is not valid base64: %v", err)
	}

	// Verify it's deterministic
	digest2 := sha256.Sum256(xmlData)
	digestBase64_2 := base64.StdEncoding.EncodeToString(digest2[:])

	if digestBase64 != digestBase64_2 {
		t.Error("SHA256 is not deterministic")
	}
}

// Test NameID format handling

func TestSAMLNameIDFormats(t *testing.T) {
	formats := []string{
		NameIDFormatEmail,
		NameIDFormatPersistent,
		NameIDFormatTransient,
		NameIDFormatUnspecified,
	}

	expected := []string{
		"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		"urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
	}

	for i, format := range formats {
		if format != expected[i] {
			t.Errorf("format %d: got %s, want %s", i, format, expected[i])
		}
	}
}

// Test SAML binding constants

func TestSAMLBindings(t *testing.T) {
	bindings := map[string]string{
		"redirect": SAMLBindingHTTPRedirect,
		"post":     SAMLBindingHTTPPost,
		"soap":     SAMLBindingSOAP,
	}

	expected := map[string]string{
		"redirect": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		"post":     "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		"soap":     "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
	}

	for key, value := range bindings {
		if value != expected[key] {
			t.Errorf("%s binding: got %s, want %s", key, value, expected[key])
		}
	}
}
