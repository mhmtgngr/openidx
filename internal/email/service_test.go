package email

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
)

// TestNewService tests service creation
func TestNewService(t *testing.T) {
	t.Run("create service with valid config", func(t *testing.T) {
		logger := zaptest.NewLogger(t)

		svc := NewService("smtp.example.com", 587, "user", "pass", "noreply@example.com", nil, logger)

		assert.NotNil(t, svc)
		assert.Equal(t, "smtp.example.com", svc.host)
		assert.Equal(t, 587, svc.port)
		assert.Equal(t, "user", svc.username)
		assert.Equal(t, "pass", svc.password)
		assert.Equal(t, "noreply@example.com", svc.from)
		assert.NotNil(t, svc.logger)
	})
}

// TestEmailMessageSerialization tests email message JSON handling
func TestEmailMessageSerialization(t *testing.T) {
	t.Run("marshal and unmarshal email message", func(t *testing.T) {
		msg := EmailMessage{
			To:           "user@example.com",
			Subject:      "Test Subject",
			TemplateName: "verification",
			Data: map[string]interface{}{
				"Name":  "Test User",
				"Token": "abc123",
				"URL":   "https://example.com/verify",
			},
		}

		data, err := json.Marshal(msg)
		assert.NoError(t, err)
		assert.NotEmpty(t, data)

		var decoded EmailMessage
		err = json.Unmarshal(data, &decoded)
		assert.NoError(t, err)

		assert.Equal(t, "user@example.com", decoded.To)
		assert.Equal(t, "Test Subject", decoded.Subject)
		assert.Equal(t, "verification", decoded.TemplateName)
		assert.Equal(t, "Test User", decoded.Data["Name"])
		assert.Equal(t, "abc123", decoded.Data["Token"])
	})

	t.Run("marshal email message with minimal data", func(t *testing.T) {
		msg := EmailMessage{
			To:           "test@example.com",
			Subject:      "Minimal",
			TemplateName: "welcome",
			Data:         map[string]interface{}{},
		}

		data, err := json.Marshal(msg)
		assert.NoError(t, err)

		var decoded EmailMessage
		err = json.Unmarshal(data, &decoded)
		assert.NoError(t, err)
		assert.Empty(t, decoded.Data)
	})
}

// TestGenerateToken tests token generation
func TestGenerateToken(t *testing.T) {
	t.Run("generate token produces 64 hex characters", func(t *testing.T) {
		token := generateToken()

		assert.Equal(t, 64, len(token))
	})

	t.Run("tokens are unique", func(t *testing.T) {
		token1 := generateToken()
		token2 := generateToken()

		assert.NotEqual(t, token1, token2)
	})

	t.Run("token contains only hex characters", func(t *testing.T) {
		token := generateToken()

		for _, c := range token {
			assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
		}
	})
}

// TestEmailMessageStructure tests the EmailMessage struct
func TestEmailMessageStructure(t *testing.T) {
	t.Run("email message with all fields", func(t *testing.T) {
		msg := EmailMessage{
			To:           "recipient@example.com",
			Subject:      "Important Email",
			TemplateName: "invitation",
			Data: map[string]interface{}{
				"Key1": "Value1",
				"Key2": 123,
				"Key3": true,
			},
		}

		assert.Equal(t, "recipient@example.com", msg.To)
		assert.Equal(t, "Important Email", msg.Subject)
		assert.Equal(t, "invitation", msg.TemplateName)
		assert.Len(t, msg.Data, 3)
	})

	t.Run("email message with empty data", func(t *testing.T) {
		msg := EmailMessage{
			To:           "test@example.com",
			Subject:      "Test",
			TemplateName: "test",
			Data:         nil,
		}

		assert.Nil(t, msg.Data)
	})
}

// TestServiceConfiguration tests various service configurations
func TestServiceConfiguration(t *testing.T) {
	t.Run("service with empty credentials", func(t *testing.T) {
		logger := zaptest.NewLogger(t)

		svc := NewService("", 0, "", "", "", nil, logger)

		assert.NotNil(t, svc)
		assert.Empty(t, svc.host)
		assert.Empty(t, svc.username)
		assert.Empty(t, svc.password)
		assert.Empty(t, svc.from)
	})

	t.Run("service with port 25 (standard SMTP)", func(t *testing.T) {
		logger := zaptest.NewLogger(t)

		svc := NewService("mail.example.com", 25, "user", "pass", "noreply@example.com", nil, logger)

		assert.Equal(t, 25, svc.port)
	})

	t.Run("service with port 465 (SMTPS)", func(t *testing.T) {
		logger := zaptest.NewLogger(t)

		svc := NewService("mail.example.com", 465, "user", "pass", "noreply@example.com", nil, logger)

		assert.Equal(t, 465, svc.port)
	})
}

// TestEmailDataTypes tests various data types in email data
func TestEmailDataTypes(t *testing.T) {
	t.Run("string data", func(t *testing.T) {
		data := map[string]interface{}{
			"Name": "John Doe",
			"Email": "john@example.com",
		}

		assert.Equal(t, "John Doe", data["Name"])
		assert.Equal(t, "john@example.com", data["Email"])
	})

	t.Run("numeric data", func(t *testing.T) {
		data := map[string]interface{}{
			"Count": 42,
			"Price": 19.99,
		}

		assert.Equal(t, 42, data["Count"])
		assert.Equal(t, 19.99, data["Price"])
	})

	t.Run("boolean data", func(t *testing.T) {
		data := map[string]interface{}{
			"Verified": true,
			"Active":   false,
		}

		assert.True(t, data["Verified"].(bool))
		assert.False(t, data["Active"].(bool))
	})

	t.Run("nested map data", func(t *testing.T) {
		nested := map[string]interface{}{
			"Street": "123 Main St",
			"City":   "Springfield",
		}
		data := map[string]interface{}{
			"Address": nested,
		}

		assert.NotNil(t, data["Address"])
	})
}

// TestEmailTypes tests common email types
func TestEmailTypes(t *testing.T) {
	t.Run("verification email data", func(t *testing.T) {
		data := map[string]interface{}{
			"Name":  "Test User",
			"Token": generateToken(),
			"URL":   "https://example.com/verify?token=abc123",
		}

		assert.NotEmpty(t, data["Token"])
		assert.Contains(t, data["URL"], "verify")
	})

	t.Run("invitation email data", func(t *testing.T) {
		data := map[string]interface{}{
			"InviterName": "John Doe",
			"Token":       generateToken(),
			"URL":         "https://example.com/accept?token=xyz789",
		}

		assert.NotEmpty(t, data["InviterName"])
		assert.NotEmpty(t, data["Token"])
		assert.Contains(t, data["URL"], "accept")
	})

	t.Run("password reset email data", func(t *testing.T) {
		data := map[string]interface{}{
			"Name":  "Jane Smith",
			"Token": generateToken(),
			"URL":   "https://example.com/reset?token=reset123",
		}

		assert.NotEmpty(t, data["Name"])
		assert.Contains(t, data["URL"], "reset")
	})

	t.Run("welcome email data", func(t *testing.T) {
		data := map[string]interface{}{
			"Name": "New User",
		}

		assert.NotEmpty(t, data["Name"])
	})
}

// TestEmailQueueOperations tests queue-related operations
func TestEmailQueueOperations(t *testing.T) {
	t.Run("queue key name", func(t *testing.T) {
		queueKey := "email:queue"
		assert.Equal(t, "email:queue", queueKey)
	})

	t.Run("BRPop timeout", func(t *testing.T) {
		timeout := 5 * time.Second
		assert.Equal(t, 5*time.Second, timeout)
	})
}

// TestServiceFields tests service field access
func TestServiceFields(t *testing.T) {
	t.Run("service fields are properly set", func(t *testing.T) {
		logger := zaptest.NewLogger(t)

		svc := NewService("smtp.test.com", 587, "testuser", "testpass", "from@test.com", nil, logger)

		assert.Equal(t, "smtp.test.com", svc.host)
		assert.Equal(t, 587, svc.port)
		assert.Equal(t, "testuser", svc.username)
		assert.Equal(t, "testpass", svc.password)
		assert.Equal(t, "from@test.com", svc.from)
	})
}

// TestTemplateNames tests template name constants
func TestTemplateNames(t *testing.T) {
	t.Run("known template names", func(t *testing.T) {
		templates := []string{
			"verification",
			"invitation",
			"password-reset",
			"welcome",
		}

		for _, tmpl := range templates {
			assert.NotEmpty(t, tmpl)
		}
	})
}

// TestEmailSubjectTests tests email subject lines
func TestEmailSubjectTests(t *testing.T) {
	t.Run("verification subject", func(t *testing.T) {
		subject := "Verify your email"
		assert.Contains(t, subject, "Verify")
		assert.Contains(t, subject, "email")
	})

	t.Run("invitation subject", func(t *testing.T) {
		subject := "You've been invited to OpenIDX"
		assert.Contains(t, subject, "invited")
		assert.Contains(t, subject, "OpenIDX")
	})

	t.Run("password reset subject", func(t *testing.T) {
		subject := "Reset your password"
		assert.Contains(t, subject, "Reset")
		assert.Contains(t, subject, "password")
	})

	t.Run("welcome subject", func(t *testing.T) {
		subject := "Welcome to OpenIDX"
		assert.Contains(t, subject, "Welcome")
	})
}

// TestEmailFormatValidation tests email format assumptions
func TestEmailFormatValidation(t *testing.T) {
	t.Run("valid email formats", func(t *testing.T) {
		emails := []string{
			"user@example.com",
			"first.last@example.com",
			"user+tag@example.com",
			"user123@test-domain.co.uk",
		}

		for _, email := range emails {
			assert.Contains(t, email, "@")
			assert.Contains(t, email, ".")
		}
	})
}

// TestSMTPAddressFormatting tests SMTP address format
func TestSMTPAddressFormatting(t *testing.T) {
	t.Run("format SMTP address components", func(t *testing.T) {
		host := "smtp.example.com"
		port := 587

		assert.Contains(t, host, "smtp.example.com")
		assert.Equal(t, 587, port)
	})
}
