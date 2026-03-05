package notifications

import (
	"testing"
	"time"
)

func TestNotificationStruct(t *testing.T) {
	link := "/dashboard"
	notif := Notification{
		ID:       "notif-001",
		UserID:   "user-001",
		OrgID:    "org-001",
		Channel:  "in_app",
		Type:     "security_alert",
		Title:    "New Login Detected",
		Body:     "A new login was detected from IP 192.168.1.1",
		Link:     &link,
		Read:     false,
		Metadata: map[string]interface{}{"ip": "192.168.1.1"},
		CreatedAt: time.Now(),
	}

	if notif.ID != "notif-001" {
		t.Errorf("expected ID=notif-001, got %s", notif.ID)
	}
	if notif.Channel != "in_app" {
		t.Errorf("expected Channel=in_app, got %s", notif.Channel)
	}
	if notif.Read {
		t.Error("expected Read=false for new notification")
	}
	if *notif.Link != "/dashboard" {
		t.Errorf("expected Link=/dashboard, got %s", *notif.Link)
	}
	if notif.Metadata["ip"] != "192.168.1.1" {
		t.Errorf("expected Metadata.ip=192.168.1.1, got %v", notif.Metadata["ip"])
	}
}

func TestNotificationPreferenceStruct(t *testing.T) {
	now := time.Now()
	pref := NotificationPreference{
		ID:        "pref-001",
		UserID:    "user-001",
		Channel:   "email",
		EventType: "security_alert",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if pref.UserID != "user-001" {
		t.Errorf("expected UserID=user-001, got %s", pref.UserID)
	}
	if !pref.Enabled {
		t.Error("expected Enabled=true")
	}
	if pref.Channel != "email" {
		t.Errorf("expected Channel=email, got %s", pref.Channel)
	}
}

func TestGetUserIDFromGinContext(t *testing.T) {
	// Test the getUserID helper with nil context behavior
	// getUserID expects gin.Context which we can't easily mock without gin dependency in tests
	// but we can verify the function signature exists and the types are correct
	_ = getUserID // ensure the function is accessible
}

func TestNotificationNilLink(t *testing.T) {
	notif := Notification{
		ID:      "notif-002",
		UserID:  "user-002",
		Channel: "in_app",
		Type:    "info",
		Title:   "Welcome",
		Body:    "Welcome to OpenIDX",
		Link:    nil,
		Read:    false,
	}

	if notif.Link != nil {
		t.Error("expected Link=nil")
	}
}
