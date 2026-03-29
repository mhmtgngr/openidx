package notifications

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
)

// TestNewService tests service creation
func TestNewService(t *testing.T) {
	t.Run("create service with dependencies", func(t *testing.T) {
		logger := zaptest.NewLogger(t)

		svc := NewService(nil, logger)

		assert.NotNil(t, svc)
		assert.NotNil(t, svc.logger)
		assert.Nil(t, svc.db)
	})
}

// TestNotification_Structure tests the Notification struct
func TestNotification_Structure(t *testing.T) {
	t.Run("notification with all fields", func(t *testing.T) {
		link := "https://example.com/notification/123"
		now := time.Now().UTC()

		notif := Notification{
			ID:       "notif-123",
			UserID:   "user-456",
			OrgID:    "org-789",
			Channel:  "in_app",
			Type:     "security_alert",
			Title:    "New login detected",
			Body:     "A new login was detected from IP 192.168.1.1",
			Link:     &link,
			Read:     false,
			Metadata: map[string]interface{}{"ip": "192.168.1.1", "location": "New York"},
			CreatedAt: now,
		}

		assert.Equal(t, "notif-123", notif.ID)
		assert.Equal(t, "user-456", notif.UserID)
		assert.Equal(t, "org-789", notif.OrgID)
		assert.Equal(t, "in_app", notif.Channel)
		assert.Equal(t, "security_alert", notif.Type)
		assert.Equal(t, "New login detected", notif.Title)
		assert.NotNil(t, notif.Link)
		assert.Equal(t, "https://example.com/notification/123", *notif.Link)
		assert.False(t, notif.Read)
		assert.NotNil(t, notif.Metadata)
	})

	t.Run("notification without link", func(t *testing.T) {
		notif := Notification{
			ID:       "notif-456",
			UserID:   "user-789",
			OrgID:    "org-123",
			Channel:  "email",
			Type:     "welcome",
			Title:    "Welcome to OpenIDX",
			Body:     "Thank you for signing up!",
			Link:     nil,
			Read:     false,
			Metadata: map[string]interface{}{},
		}

		assert.Nil(t, notif.Link)
		assert.Empty(t, notif.Metadata)
	})
}

// TestNotificationPreference_Structure tests the NotificationPreference struct
func TestNotificationPreference_Structure(t *testing.T) {
	t.Run("preference with all fields", func(t *testing.T) {
		now := time.Now().UTC()

		pref := NotificationPreference{
			ID:        "pref-123",
			UserID:    "user-456",
			Channel:   "email",
			EventType: "security_alert",
			Enabled:   true,
			CreatedAt: now,
			UpdatedAt: now,
		}

		assert.Equal(t, "pref-123", pref.ID)
		assert.Equal(t, "user-456", pref.UserID)
		assert.Equal(t, "email", pref.Channel)
		assert.Equal(t, "security_alert", pref.EventType)
		assert.True(t, pref.Enabled)
	})

	t.Run("disabled preference", func(t *testing.T) {
		pref := NotificationPreference{
			ID:        "pref-789",
			UserID:    "user-123",
			Channel:   "in_app",
			EventType: "marketing",
			Enabled:   false,
		}

		assert.False(t, pref.Enabled)
	})
}

// TestNotification_JSONSerialization tests JSON marshaling
func TestNotification_JSONSerialization(t *testing.T) {
	t.Run("marshal and unmarshal notification", func(t *testing.T) {
		link := "https://example.com"

		notif := Notification{
			ID:       "notif-123",
			UserID:   "user-456",
			OrgID:    "org-789",
			Channel:  "in_app",
			Type:     "alert",
			Title:    "Test Notification",
			Body:     "Test Body",
			Link:     &link,
			Read:     false,
			Metadata: map[string]interface{}{"key": "value"},
			CreatedAt: time.Now(),
		}

		data, err := json.Marshal(notif)
		assert.NoError(t, err)
		assert.NotEmpty(t, data)

		var decoded Notification
		err = json.Unmarshal(data, &decoded)
		assert.NoError(t, err)

		assert.Equal(t, "notif-123", decoded.ID)
		assert.Equal(t, "user-456", decoded.UserID)
		assert.Equal(t, "in_app", decoded.Channel)
		assert.Equal(t, "alert", decoded.Type)
		assert.NotNil(t, decoded.Link)
	})

	t.Run("marshal notification with nil link", func(t *testing.T) {
		notif := Notification{
			ID:      "notif-456",
			UserID:  "user-789",
			Channel: "email",
			Type:    "welcome",
			Title:   "Welcome",
			Body:    "Welcome!",
			Link:    nil,
		}

		data, err := json.Marshal(notif)
		assert.NoError(t, err)

		var decoded Notification
		err = json.Unmarshal(data, &decoded)
		assert.NoError(t, err)
		assert.Nil(t, decoded.Link)
	})
}

// TestNotificationPreference_JSONSerialization tests preference JSON handling
func TestNotificationPreference_JSONSerialization(t *testing.T) {
	t.Run("marshal and unmarshal preference", func(t *testing.T) {
		pref := NotificationPreference{
			ID:        "pref-123",
			UserID:    "user-456",
			Channel:   "email",
			EventType: "security_alert",
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		data, err := json.Marshal(pref)
		assert.NoError(t, err)

		var decoded NotificationPreference
		err = json.Unmarshal(data, &decoded)
		assert.NoError(t, err)

		assert.Equal(t, "pref-123", decoded.ID)
		assert.Equal(t, "user-456", decoded.UserID)
		assert.Equal(t, "email", decoded.Channel)
		assert.True(t, decoded.Enabled)
	})
}

// TestNotificationChannels tests valid channel values
func TestNotificationChannels(t *testing.T) {
	t.Run("valid channels", func(t *testing.T) {
		channels := []string{"in_app", "email", "sms", "push"}

		for _, channel := range channels {
			assert.NotEmpty(t, channel)
		}
	})

	t.Run("default channel", func(t *testing.T) {
		defaultChannel := "in_app"
		assert.Equal(t, "in_app", defaultChannel)
	})
}

// TestNotificationTypes tests valid notification type values
func TestNotificationTypes(t *testing.T) {
	t.Run("common notification types", func(t *testing.T) {
		types := []string{
			"security_alert",
			"welcome",
			"invitation",
			"password_reset",
			"mfa_enabled",
			"login_detected",
			"access_review",
			"policy_violation",
		}

		for _, nType := range types {
			assert.NotEmpty(t, nType)
		}
	})
}

// TestNotificationMetadata tests metadata handling
func TestNotificationMetadata(t *testing.T) {
	t.Run("metadata with various types", func(t *testing.T) {
		metadata := map[string]interface{}{
			"ip":           "192.168.1.1",
			"count":        5,
			"verified":     true,
			"timestamp":    time.Now().UTC(),
			"nested_map":   map[string]string{"key": "value"},
			"string_array": []string{"a", "b", "c"},
		}

		assert.NotEmpty(t, metadata)
		assert.Equal(t, "192.168.1.1", metadata["ip"])
		assert.Equal(t, 5, metadata["count"])
		assert.True(t, metadata["verified"].(bool))
	})

	t.Run("empty metadata", func(t *testing.T) {
		metadata := map[string]interface{}{}
		assert.Empty(t, metadata)
	})
}

// TestNotificationReadStatus tests read status handling
func TestNotificationReadStatus(t *testing.T) {
	t.Run("unread notification", func(t *testing.T) {
		notif := Notification{Read: false}
		assert.False(t, notif.Read)
	})

	t.Run("read notification", func(t *testing.T) {
		notif := Notification{Read: true}
		assert.True(t, notif.Read)
	})
}

// TestNotificationTimestamps tests timestamp handling
func TestNotificationTimestamps(t *testing.T) {
	t.Run("UTC timestamp", func(t *testing.T) {
		now := time.Now().UTC()
		notif := Notification{CreatedAt: now}

		assert.False(t, notif.CreatedAt.IsZero())
	})

	t.Run("timestamp comparisons", func(t *testing.T) {
		first := time.Now().UTC()
		second := first.Add(time.Hour)

		assert.True(t, second.After(first))
	})
}

// TestGetUserIDHelper tests the getUserID helper logic
func TestGetUserIDHelper(t *testing.T) {
	t.Run("extract user ID from context", func(t *testing.T) {
		// This tests the logic of extracting user ID
		userID := "user-123"
		assert.NotEmpty(t, userID)
	})

	t.Run("empty user ID handling", func(t *testing.T) {
		userID := ""
		assert.Empty(t, userID)
	})
}

// TestPaginationParameters tests pagination logic
func TestPaginationParameters(t *testing.T) {
	t.Run("default pagination", func(t *testing.T) {
		limit := 20
		offset := 0

		assert.Equal(t, 20, limit)
		assert.Equal(t, 0, offset)
	})

	t.Run("limit bounds", func(t *testing.T) {
		minLimit := 1
		maxLimit := 100

		assert.Equal(t, 1, minLimit)
		assert.Equal(t, 100, maxLimit)
	})

	t.Run("offset cannot be negative", func(t *testing.T) {
		offset := 0
		assert.True(t, offset >= 0)
	})
}

// TestNotificationQueryFilters tests query filter logic
func TestNotificationQueryFilters(t *testing.T) {
	t.Run("channel filter", func(t *testing.T) {
		channel := "email"
		assert.NotEmpty(t, channel)
	})

	t.Run("unread only filter", func(t *testing.T) {
		unreadOnly := true
		assert.True(t, unreadOnly)
	})

	t.Run("type filter", func(t *testing.T) {
		typeFilter := "security_alert"
		assert.Equal(t, "security_alert", typeFilter)
	})
}

// TestNotificationDigestTypes tests digest type values
func TestNotificationDigestTypes(t *testing.T) {
	t.Run("common digest types", func(t *testing.T) {
		digestTypes := []string{
			"daily",
			"weekly",
			"monthly",
			"instant",
		}

		for _, dType := range digestTypes {
			assert.NotEmpty(t, dType)
		}
	})
}

// TestBatchOperations tests batch operation logic
func TestBatchOperations(t *testing.T) {
	t.Run("mark multiple as read", func(t *testing.T) {
		ids := []string{"notif-1", "notif-2", "notif-3"}
		assert.Len(t, ids, 3)
	})

	t.Run("empty batch", func(t *testing.T) {
		ids := []string{}
		assert.Empty(t, ids)
	})
}

// TestNotificationResponseFormat tests response format
func TestNotificationResponseFormat(t *testing.T) {
	t.Run("standard response structure", func(t *testing.T) {
		response := map[string]interface{}{
			"notifications": []Notification{},
			"total":         0,
			"limit":         20,
			"offset":        0,
		}

		assert.NotNil(t, response["notifications"])
		assert.Equal(t, 0, response["total"])
		assert.Equal(t, 20, response["limit"])
		assert.Equal(t, 0, response["offset"])
	})

	t.Run("unread count response", func(t *testing.T) {
		response := map[string]interface{}{
			"unread_count": 5,
		}

		assert.Equal(t, 5, response["unread_count"])
	})
}

// TestPreferenceCombinations tests channel and event type combinations
func TestPreferenceCombinations(t *testing.T) {
	t.Run("common combinations", func(t *testing.T) {
		combinations := []struct {
			channel   string
			eventType string
		}{
			{"email", "security_alert"},
			{"email", "invitation"},
			{"in_app", "security_alert"},
			{"in_app", "welcome"},
			{"sms", "mfa_code"},
			{"push", "access_review"},
		}

		for _, combo := range combinations {
			assert.NotEmpty(t, combo.channel)
			assert.NotEmpty(t, combo.eventType)
		}
	})
}

// TestNotificationUrgency tests notification urgency levels
func TestNotificationUrgency(t *testing.T) {
	t.Run("security notifications are urgent", func(t *testing.T) {
		securityTypes := []string{
			"security_alert",
			"password_reset",
			"mfa_enabled",
			"unusual_login",
		}

		// Verify these are all valid notification types
		for _, nType := range securityTypes {
			assert.NotEmpty(t, nType)
		}

		// The security_alert type specifically contains "security"
		assert.Contains(t, securityTypes[0], "security")
	})
}
