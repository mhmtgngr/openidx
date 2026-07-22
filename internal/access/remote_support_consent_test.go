package access

import "testing"

// consentStatusFor: required -> pending (device must Allow); not required ->
// granted (unattended/server, no behavior change).
func TestConsentStatusFor(t *testing.T) {
	if consentStatusFor(true) != "pending" {
		t.Errorf("consent-required session must start 'pending', got %q", consentStatusFor(true))
	}
	if consentStatusFor(false) != "granted" {
		t.Errorf("non-consent session must start 'granted', got %q", consentStatusFor(false))
	}
}
