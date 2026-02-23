// Package mfa provides Multi-Factor Authentication functionality for OpenIDX
package mfa

import (
	"context"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Provider defines the interface for sending OTP codes
type Provider interface {
	// SendEmail sends an OTP code via email
	SendEmail(ctx context.Context, to, subject, body string) error

	// SendSMS sends an OTP code via SMS
	SendSMS(ctx context.Context, to, message string) error
}

// SMTPConfig holds configuration for SMTP email sending
type SMTPConfig struct {
	Host     string // SMTP server hostname
	Port     int    // SMTP server port
	Username string // SMTP username
	Password string // SMTP password
	From     string // From email address
}

// TwilioConfig holds configuration for Twilio SMS
type TwilioConfig struct {
	AccountSID string // Twilio Account SID
	AuthToken  string // Twilio Auth Token
	FromNumber string // Twilio phone number
}

// SMTPProvider sends OTP codes via email using SMTP
type SMTPProvider struct {
	config SMTPConfig
	logger *zap.Logger
	client *smtp.Client
}

// NewSMTPProvider creates a new SMTP email provider
func NewSMTPProvider(config SMTPConfig, logger *zap.Logger) *SMTPProvider {
	return &SMTPProvider{
		config: config,
		logger: logger,
	}
}

// SendEmail sends an email via SMTP
func (p *SMTPProvider) SendEmail(ctx context.Context, to, subject, body string) error {
	// Build the email message
	from := p.config.From
	if from == "" {
		from = p.config.Username
	}

	// Format: From: <email>\nTo: <email>\nSubject: <subject>\n\n<body>
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-version: 1.0;\r\nContent-Type: text/plain; charset=\"UTF-8\";\r\n\r\n%s",
		from, to, subject, body)

	// Connect to SMTP server
	addr := fmt.Sprintf("%s:%d", p.config.Host, p.config.Port)

	// Create a timeout context for the connection
	sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// For TLS connections, we need to handle it differently
	// For now, using basic SMTP with STARTTLS if available
	var err error
	done := make(chan error, 1)

	go func() {
		// Connect to the server
		var auth smtp.Auth
		if p.config.Username != "" && p.config.Password != "" {
			auth = smtp.PlainAuth("", p.config.Username, p.config.Password, p.config.Host)
		}

		err = smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
		done <- err
	}()

	select {
	case <-sendCtx.Done():
		p.logger.Error("SMTP send timeout",
			zap.String("to", to),
			zap.Error(sendCtx.Err()),
		)
		return fmt.Errorf("send timeout: %w", sendCtx.Err())
	case err := <-done:
		if err != nil {
			p.logger.Error("Failed to send email via SMTP",
				zap.String("to", to),
				zap.Error(err),
			)
			return fmt.Errorf("failed to send email: %w", err)
		}
	}

	p.logger.Info("Email sent successfully",
		zap.String("to", to),
		zap.String("subject", subject),
	)

	return nil
}

// SendSMS is not implemented for SMTP provider
func (p *SMTPProvider) SendSMS(ctx context.Context, to, message string) error {
	return fmt.Errorf("SMS not supported by SMTP provider")
}

// TwilioProvider sends OTP codes via SMS using Twilio's REST API
type TwilioProvider struct {
	config TwilioConfig
	logger *zap.Logger
	client *http.Client
}

// NewTwilioProvider creates a new Twilio SMS provider
func NewTwilioProvider(config TwilioConfig, logger *zap.Logger) *TwilioProvider {
	return &TwilioProvider{
		config: config,
		logger: logger,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SendEmail is not implemented for Twilio provider
func (p *TwilioProvider) SendEmail(ctx context.Context, to, subject, body string) error {
	return fmt.Errorf("email not supported by Twilio provider")
}

// SendSMS sends an SMS via Twilio
func (p *TwilioProvider) SendSMS(ctx context.Context, to, message string) error {
	// Twilio API endpoint
	url := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", p.config.AccountSID)

	// Build form data
	data := fmt.Sprintf("To=%s&From=%s&Body=%s",
		to, p.config.FromNumber, message)

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(data))
	if err != nil {
		p.logger.Error("Failed to create Twilio request",
			zap.Error(err),
		)
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.SetBasicAuth(p.config.AccountSID, p.config.AuthToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request
	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.Error("Failed to send Twilio SMS",
			zap.String("to", to),
			zap.Error(err),
		)
		return fmt.Errorf("failed to send SMS: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		p.logger.Error("Twilio API returned error",
			zap.String("to", to),
			zap.Int("status", resp.StatusCode),
		)
		return fmt.Errorf("Twilio API error: status %d", resp.StatusCode)
	}

	p.logger.Info("SMS sent successfully via Twilio",
		zap.String("to", to),
	)

	return nil
}

// LogProvider logs OTP codes to stdout (for development/testing only)
type LogProvider struct {
	logger      *zap.Logger
	enablePrint bool // If true, also print to stdout
}

// NewLogProvider creates a new log provider for development/testing
func NewLogProvider(logger *zap.Logger, enablePrint bool) *LogProvider {
	return &LogProvider{
		logger:      logger,
		enablePrint: enablePrint,
	}
}

// SendEmail logs the email to console instead of sending
func (p *LogProvider) SendEmail(ctx context.Context, to, subject, body string) error {
	msg := fmt.Sprintf("[LOG PROVIDER - EMAIL] To: %s | Subject: %s | Body: %s",
		to, subject, strings.ReplaceAll(body, "\n", " "))

	p.logger.Info(msg)

	if p.enablePrint {
		fmt.Println(msg)
	}

	return nil
}

// SendSMS logs the SMS to console instead of sending
func (p *LogProvider) SendSMS(ctx context.Context, to, message string) error {
	msg := fmt.Sprintf("[LOG PROVIDER - SMS] To: %s | Message: %s", to, message)

	p.logger.Info(msg)

	if p.enablePrint {
		fmt.Println(msg)
	}

	return nil
}

// MockProvider is a test provider that stores sent messages for inspection
type MockProvider struct {
	Emails []SentMessage
	SMSs   []SentMessage
	logger *zap.Logger
}

// SentMessage represents a sent message for testing
type SentMessage struct {
	To      string
	Subject string // Only for emails
	Body    string
	SentAt  time.Time
}

// NewMockProvider creates a new mock provider for testing
func NewMockProvider(logger *zap.Logger) *MockProvider {
	return &MockProvider{
		Emails: make([]SentMessage, 0),
		SMSs:   make([]SentMessage, 0),
		logger: logger,
	}
}

// SendEmail stores the email for testing
func (p *MockProvider) SendEmail(ctx context.Context, to, subject, body string) error {
	p.Emails = append(p.Emails, SentMessage{
		To:      to,
		Subject: subject,
		Body:    body,
		SentAt:  time.Now(),
	})

	p.logger.Debug("Mock: Email sent",
		zap.String("to", to),
		zap.String("subject", subject),
	)

	return nil
}

// SendSMS stores the SMS for testing
func (p *MockProvider) SendSMS(ctx context.Context, to, message string) error {
	p.SMSs = append(p.SMSs, SentMessage{
		To:     to,
		Body:   message,
		SentAt: time.Now(),
	})

	p.logger.Debug("Mock: SMS sent",
		zap.String("to", to),
	)

	return nil
}

// Clear clears all stored messages
func (p *MockProvider) Clear() {
	p.Emails = make([]SentMessage, 0)
	p.SMSs = make([]SentMessage, 0)
}

// GetLastEmail returns the last sent email
func (p *MockProvider) GetLastEmail() *SentMessage {
	if len(p.Emails) == 0 {
		return nil
	}
	return &p.Emails[len(p.Emails)-1]
}

// GetLastSMS returns the last sent SMS
func (p *MockProvider) GetLastSMS() *SentMessage {
	if len(p.SMSs) == 0 {
		return nil
	}
	return &p.SMSs[len(p.SMSs)-1]
}

// GetEmailsTo returns all emails sent to a specific recipient
func (p *MockProvider) GetEmailsTo(to string) []SentMessage {
	result := make([]SentMessage, 0)
	for _, email := range p.Emails {
		if email.To == to {
			result = append(result, email)
		}
	}
	return result
}

// GetSMSTo returns all SMS sent to a specific recipient
func (p *MockProvider) GetSMSTo(to string) []SentMessage {
	result := make([]SentMessage, 0)
	for _, sms := range p.SMSs {
		if sms.To == to {
			result = append(result, sms)
		}
	}
	return result
}

// WebhookProvider sends OTP codes via a custom webhook
type WebhookProvider struct {
	url     string
	apiKey  string
	logger  *zap.Logger
	client  *http.Client
}

// NewWebhookProvider creates a new webhook provider
func NewWebhookProvider(url, apiKey string, logger *zap.Logger) *WebhookProvider {
	return &WebhookProvider{
		url:    url,
		apiKey: apiKey,
		logger: logger,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SendEmail sends an email via webhook
func (p *WebhookProvider) SendEmail(ctx context.Context, to, subject, body string) error {
	// This would make a webhook call to send email
	// Implementation depends on the webhook API specification
	p.logger.Info("Webhook: Would send email",
		zap.String("to", to),
		zap.String("subject", subject),
	)
	return fmt.Errorf("webhook email sending not implemented")
}

// SendSMS sends an SMS via webhook
func (p *WebhookProvider) SendSMS(ctx context.Context, to, message string) error {
	// This would make a webhook call to send SMS
	// Implementation depends on the webhook API specification
	p.logger.Info("Webhook: Would send SMS",
		zap.String("to", to),
	)
	return fmt.Errorf("webhook SMS sending not implemented")
}

// MultiProvider sends via multiple providers with fallback
type MultiProvider struct {
	primary   Provider
	secondary Provider
	logger    *zap.Logger
}

// NewMultiProvider creates a new multi-provider with fallback
func NewMultiProvider(primary, secondary Provider, logger *zap.Logger) *MultiProvider {
	return &MultiProvider{
		primary:   primary,
		secondary: secondary,
		logger:    logger,
	}
}

// SendEmail tries primary provider, falls back to secondary on failure
func (p *MultiProvider) SendEmail(ctx context.Context, to, subject, body string) error {
	err := p.primary.SendEmail(ctx, to, subject, body)
	if err != nil {
		p.logger.Warn("Primary email provider failed, trying secondary",
			zap.Error(err),
		)
		return p.secondary.SendEmail(ctx, to, subject, body)
	}
	return nil
}

// SendSMS tries primary provider, falls back to secondary on failure
func (p *MultiProvider) SendSMS(ctx context.Context, to, message string) error {
	err := p.primary.SendSMS(ctx, to, message)
	if err != nil {
		p.logger.Warn("Primary SMS provider failed, trying secondary",
			zap.Error(err),
		)
		return p.secondary.SendSMS(ctx, to, message)
	}
	return nil
}
