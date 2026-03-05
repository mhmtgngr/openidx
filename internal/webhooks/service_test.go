package webhooks

import (
	"testing"
	"time"
)

func TestComputeSignature(t *testing.T) {
	secret := "test-secret"
	body := []byte(`{"event":"user.created","user_id":"123"}`)

	sig1 := computeSignature(secret, body)
	sig2 := computeSignature(secret, body)

	if sig1 == "" {
		t.Error("expected non-empty signature")
	}
	if sig1 != sig2 {
		t.Error("expected deterministic signatures for same input")
	}

	// Different secret should produce different signature
	sig3 := computeSignature("other-secret", body)
	if sig1 == sig3 {
		t.Error("expected different signature for different secret")
	}

	// Different body should produce different signature
	sig4 := computeSignature(secret, []byte(`{"event":"user.deleted"}`))
	if sig1 == sig4 {
		t.Error("expected different signature for different body")
	}
}

func TestComputeSignatureLength(t *testing.T) {
	sig := computeSignature("secret", []byte("body"))
	// HMAC-SHA256 produces 32 bytes = 64 hex chars
	if len(sig) != 64 {
		t.Errorf("expected signature length 64, got %d", len(sig))
	}
}

func TestSubscriptionStruct(t *testing.T) {
	createdBy := "admin"
	sub := Subscription{
		ID:        "sub-001",
		Name:      "Test Webhook",
		URL:       "https://example.com/webhook",
		Secret:    "secret123",
		Events:    []string{EventUserCreated, EventUserDeleted},
		Status:    "active",
		CreatedBy: &createdBy,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if sub.ID != "sub-001" {
		t.Errorf("expected ID=sub-001, got %s", sub.ID)
	}
	if len(sub.Events) != 2 {
		t.Errorf("expected 2 events, got %d", len(sub.Events))
	}
	if sub.Events[0] != EventUserCreated {
		t.Errorf("expected first event=%s, got %s", EventUserCreated, sub.Events[0])
	}
}

func TestDeliveryStruct(t *testing.T) {
	statusCode := 200
	respBody := "OK"
	now := time.Now()

	delivery := Delivery{
		ID:             "del-001",
		SubscriptionID: "sub-001",
		EventType:      EventUserCreated,
		Payload:        `{"user_id":"123"}`,
		ResponseStatus: &statusCode,
		ResponseBody:   &respBody,
		Attempt:        1,
		Status:         "delivered",
		CreatedAt:      now,
		DeliveredAt:    &now,
	}

	if delivery.Status != "delivered" {
		t.Errorf("expected status=delivered, got %s", delivery.Status)
	}
	if *delivery.ResponseStatus != 200 {
		t.Errorf("expected response status 200, got %d", *delivery.ResponseStatus)
	}
}

func TestEventTypeConstants(t *testing.T) {
	events := map[string]string{
		"EventUserCreated":     EventUserCreated,
		"EventUserUpdated":     EventUserUpdated,
		"EventUserDeleted":     EventUserDeleted,
		"EventUserLocked":      EventUserLocked,
		"EventLoginSuccess":    EventLoginSuccess,
		"EventLoginFailed":     EventLoginFailed,
		"EventLoginHighRisk":   EventLoginHighRisk,
		"EventGroupUpdated":    EventGroupUpdated,
		"EventRoleUpdated":     EventRoleUpdated,
		"EventPolicyViolated":  EventPolicyViolated,
		"EventReviewCompleted": EventReviewCompleted,
	}

	for name, value := range events {
		if value == "" {
			t.Errorf("event constant %s is empty", name)
		}
	}

	// Verify format (should be dot-separated)
	for name, value := range events {
		found := false
		for _, c := range value {
			if c == '.' {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("event constant %s (%s) should contain a dot separator", name, value)
		}
	}
}
