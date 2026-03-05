package email

import (
	"testing"
)

func TestGenerateToken(t *testing.T) {
	token1 := generateToken()
	token2 := generateToken()

	if len(token1) != 64 {
		t.Errorf("expected token length 64, got %d", len(token1))
	}
	if len(token2) != 64 {
		t.Errorf("expected token length 64, got %d", len(token2))
	}
	if token1 == token2 {
		t.Error("expected unique tokens, got duplicates")
	}
}

func TestGenerateTokenHexFormat(t *testing.T) {
	token := generateToken()
	for _, c := range token {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("token contains non-hex character: %c", c)
		}
	}
}

func TestEmailMessageSerialization(t *testing.T) {
	msg := EmailMessage{
		To:           "user@example.com",
		Subject:      "Test Subject",
		TemplateName: "welcome",
		Data: map[string]interface{}{
			"Name": "John",
		},
	}

	if msg.To != "user@example.com" {
		t.Errorf("expected To=user@example.com, got %s", msg.To)
	}
	if msg.Subject != "Test Subject" {
		t.Errorf("expected Subject=Test Subject, got %s", msg.Subject)
	}
	if msg.TemplateName != "welcome" {
		t.Errorf("expected TemplateName=welcome, got %s", msg.TemplateName)
	}
	if msg.Data["Name"] != "John" {
		t.Errorf("expected Data.Name=John, got %v", msg.Data["Name"])
	}
}
