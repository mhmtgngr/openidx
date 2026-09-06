package oauth

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// httptestHandler adapts a query-capturing func into the SP's SLO endpoint.
func httptestHandler(fn func(rawQuery string, values url.Values)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fn(r.URL.RawQuery, r.URL.Query())
		w.WriteHeader(http.StatusOK)
	})
}

// TestSendLogoutRequestToSPDeliversSignedRequest pins the fix for the SLO
// that never left the building: sendLogoutRequestToSP built the redirect
// binding URL and only logged it, so the IdP reported SP sessions ended
// while no SP had been contacted. The test stands in as the SP and asserts
// (1) an HTTP request actually arrives, (2) it carries a LogoutRequest that
// inflates to the session being ended, and (3) the SigAlg/Signature pair
// verifies over the exact raw query per SAML Bindings 3.4.4.1.
func TestSendLogoutRequestToSPDeliversSignedRequest(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	type received struct {
		rawQuery string
		values   url.Values
	}
	got := make(chan received, 1)
	sp := httptest.NewServer(httptestHandler(func(rawQuery string, values url.Values) {
		got <- received{rawQuery: rawQuery, values: values}
	}))
	defer sp.Close()

	s := &Service{privateKey: pk, logger: zap.NewNop()}
	logoutReq := s.createLogoutRequest(
		SAMLSession{SessionIndex: "_sess-42", NameID: "alice@example.com", NameIDFormat: "urn:x:persistent"},
		&SAMLServiceProvider{SLOURL: sp.URL + "/slo"},
	)

	s.sendLogoutRequestToSP(context.Background(), logoutReq, sp.URL+"/slo")

	var r received
	select {
	case r = <-got:
	default:
		t.Fatal("no request reached the SP — the LogoutRequest was not delivered")
	}

	// (2) the payload is the LogoutRequest for this session.
	deflated, err := base64.StdEncoding.DecodeString(r.values.Get("SAMLRequest"))
	if err != nil {
		t.Fatalf("SAMLRequest not base64: %v", err)
	}
	inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	if err != nil {
		t.Fatalf("SAMLRequest not deflate-compressed: %v", err)
	}
	var parsed struct {
		XMLName      xml.Name `xml:"LogoutRequest"`
		SessionIndex string   `xml:"SessionIndex"`
		NameID       string   `xml:"NameID"`
	}
	if err := xml.Unmarshal(inflated, &parsed); err != nil {
		t.Fatalf("payload is not a LogoutRequest: %v\n%s", err, inflated)
	}
	if parsed.SessionIndex != "_sess-42" || parsed.NameID != "alice@example.com" {
		t.Errorf("LogoutRequest carries session %q / name %q, want _sess-42 / alice@example.com",
			parsed.SessionIndex, parsed.NameID)
	}

	// (3) the redirect-binding signature verifies over the exact raw query
	// up to (excluding) &Signature=, with the sender's encoding preserved.
	if r.values.Get("SigAlg") != samlRedirectSigAlg {
		t.Fatalf("SigAlg = %q, want %q", r.values.Get("SigAlg"), samlRedirectSigAlg)
	}
	idx := strings.Index(r.rawQuery, "&Signature=")
	if idx < 0 {
		t.Fatal("no Signature parameter on the request")
	}
	signedPart := r.rawQuery[:idx]
	sig, err := base64.StdEncoding.DecodeString(r.values.Get("Signature"))
	if err != nil {
		t.Fatalf("Signature not base64: %v", err)
	}
	digest := sha256.Sum256([]byte(signedPart))
	if err := rsa.VerifyPKCS1v15(&pk.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Errorf("redirect-binding signature does not verify: %v", err)
	}
}

// TestSendLogoutRequestToSPUnsignedWithoutKey: with no signing key the
// request is still delivered (SPs that don't require SLO signatures can act
// on it) — just without SigAlg/Signature, and never silently dropped.
func TestSendLogoutRequestToSPUnsignedWithoutKey(t *testing.T) {
	got := make(chan url.Values, 1)
	sp := httptest.NewServer(httptestHandler(func(_ string, values url.Values) {
		got <- values
	}))
	defer sp.Close()

	s := &Service{logger: zap.NewNop()}
	logoutReq := s.createLogoutRequest(
		SAMLSession{SessionIndex: "_sess-1", NameID: "bob@example.com"},
		&SAMLServiceProvider{SLOURL: sp.URL},
	)
	s.sendLogoutRequestToSP(context.Background(), logoutReq, sp.URL)

	select {
	case v := <-got:
		if v.Get("SAMLRequest") == "" {
			t.Error("delivered request carries no SAMLRequest")
		}
		if v.Get("Signature") != "" {
			t.Error("keyless service must not fabricate a Signature parameter")
		}
	default:
		t.Fatal("no request reached the SP")
	}
}
