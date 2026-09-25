// Package oauth - SAML protocol messages a service provider sends to the IdP.
//
// Two bindings deliver them through the browser, and they carry signatures in
// different places. HTTP-Redirect puts the deflated message in the URL query
// and signs the query (SigAlg and Signature parameters, SAML Bindings
// 3.4.4.1). HTTP-POST puts the message in a form field and signs the XML
// itself (an enveloped <ds:Signature>). A verifier that looks in only one of
// the two places ignores every signature sent the other way, so this file
// reads both.
package oauth

import (
	"errors"
	"fmt"

	"github.com/beevik/etree"
	"github.com/gin-gonic/gin"
)

// errSAMLMessageMissing reports that the request carries no message in the
// parameter asked for.
var errSAMLMessageMissing = errors.New("no SAML message in the request")

// samlInbound is one SAML protocol message received from a service provider.
type samlInbound struct {
	// param is where it arrived: SAMLRequest or SAMLResponse.
	param string
	// redirect is true for the HTTP-Redirect binding (the message was in the
	// URL query) and false for HTTP-POST.
	redirect bool
	// rawQuery is the query string as received, which is what a redirect
	// binding signature covers.
	rawQuery   string
	relayState string
	xml        []byte
	root       *etree.Element
	// detachedSignature is set when the query carries a Signature parameter.
	detachedSignature bool
}

// readSAMLInbound decodes the message in param. The query string wins over
// the form, as it does for the parameter lookups the handlers already make.
func readSAMLInbound(c *gin.Context, param string) (*samlInbound, error) {
	msg := &samlInbound{param: param}
	encoded := c.Query(param)
	if encoded != "" {
		msg.redirect = true
		msg.rawQuery = c.Request.URL.RawQuery
		msg.relayState = c.Query("RelayState")
		msg.detachedSignature = c.Query("Signature") != ""
	} else {
		encoded = c.PostForm(param)
		if encoded == "" {
			return nil, errSAMLMessageMissing
		}
		msg.relayState = c.PostForm("RelayState")
	}

	decoded, err := inflateAndDecode(encoded)
	if err != nil {
		decoded, err = base64Decode(encoded)
		if err != nil {
			return nil, fmt.Errorf("%s is not base64: %w", param, err)
		}
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(decoded); err != nil {
		return nil, fmt.Errorf("%s is not XML: %w", param, err)
	}
	if doc.Root() == nil {
		return nil, fmt.Errorf("%s has no root element", param)
	}
	msg.xml = decoded
	msg.root = doc.Root()
	return msg, nil
}

// signatureState is what verifyInboundSignature found.
type signatureState int

const (
	// messageUnsigned: the message carries no signature at all.
	messageUnsigned signatureState = iota
	// messageSigned: every signature the message carries verified against the
	// service provider's certificate, and there was at least one.
	messageSigned
)

// verifyInboundSignature checks every signature msg carries -- the query
// signature of the redirect binding and an enveloped signature on the message
// itself, in either binding -- against the certificate registered for sp.
//
// A signature that is present and does not verify is an error whether or not
// the caller requires one: a message that claims a signature it cannot back is
// not a message this IdP acts on. Whether an UNSIGNED message is acceptable is
// the caller's decision, made on the returned state.
func verifyInboundSignature(msg *samlInbound, sp *SAMLServiceProvider) (signatureState, error) {
	embedded := hasEnvelopedSignature(msg.root)
	if !msg.detachedSignature && !embedded {
		return messageUnsigned, nil
	}
	cert, err := parseSAMLCertificate(sp.Certificate)
	if err != nil {
		return messageUnsigned, fmt.Errorf("the message is signed but the service provider's certificate is unusable: %w", err)
	}
	if msg.detachedSignature {
		if err := verifyRedirectBindingSignature(msg.rawQuery, msg.param, cert); err != nil {
			return messageUnsigned, fmt.Errorf("query signature: %w", err)
		}
	}
	if embedded {
		if err := verifyEnvelopedRootSignature(msg.root, cert); err != nil {
			return messageUnsigned, fmt.Errorf("XML signature: %w", err)
		}
	}
	return messageSigned, nil
}
