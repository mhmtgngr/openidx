// Package sms provides SMS messaging functionality with support for multiple providers
package sms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Provider defines the interface for SMS providers
type Provider interface {
	SendOTP(ctx context.Context, phoneNumber, code string) error
	SendMessage(ctx context.Context, phoneNumber, message string) error
	Name() string
}

// Config holds SMS service configuration
type Config struct {
	Provider      string `mapstructure:"provider"`       // twilio, aws_sns, netgsm, ileti_merkezi, verimor, turkcell, vodafone, turk_telekom, mutlucell, webhook, mock
	TwilioSID     string `mapstructure:"twilio_sid"`     // Twilio Account SID
	TwilioToken   string `mapstructure:"twilio_token"`   // Twilio Auth Token
	TwilioFrom    string `mapstructure:"twilio_from"`    // Twilio From Number
	AWSRegion     string `mapstructure:"aws_region"`     // AWS Region for SNS
	AWSAccessKey  string `mapstructure:"aws_access_key"` // AWS Access Key
	AWSSecretKey  string `mapstructure:"aws_secret_key"` // AWS Secret Key
	MessagePrefix string `mapstructure:"message_prefix"` // Prefix for OTP messages
	Enabled       bool   `mapstructure:"enabled"`        // Enable/disable SMS sending

	// Turkish SMS gateway providers
	NetGSMUserCode string `mapstructure:"netgsm_usercode"`  // NetGSM user code
	NetGSMPassword string `mapstructure:"netgsm_password"`  // NetGSM password
	NetGSMHeader   string `mapstructure:"netgsm_header"`    // NetGSM sender header

	IletiMerkeziKey    string `mapstructure:"iletimerkezi_key"`    // İleti Merkezi API key
	IletiMerkeziSecret string `mapstructure:"iletimerkezi_secret"` // İleti Merkezi API secret
	IletiMerkeziSender string `mapstructure:"iletimerkezi_sender"` // İleti Merkezi sender name

	VerimorUsername   string `mapstructure:"verimor_username"`    // Verimor username (phone number)
	VerimorPassword   string `mapstructure:"verimor_password"`    // Verimor password
	VerimorSourceAddr string `mapstructure:"verimor_source_addr"` // Verimor sender ID

	TurkcellUsername string `mapstructure:"turkcell_username"` // Turkcell Mesajüssü username
	TurkcellPassword string `mapstructure:"turkcell_password"` // Turkcell Mesajüssü password
	TurkcellSender   string `mapstructure:"turkcell_sender"`   // Turkcell sender name

	VodafoneAPIKey   string `mapstructure:"vodafone_api_key"`   // Vodafone API key
	VodafoneSecret   string `mapstructure:"vodafone_secret"`    // Vodafone API secret
	VodafoneSender   string `mapstructure:"vodafone_sender"`    // Vodafone sender address

	TurkTelekomAPIKey string `mapstructure:"turktelekom_api_key"` // Türk Telekom API key
	TurkTelekomSecret string `mapstructure:"turktelekom_secret"`  // Türk Telekom API secret
	TurkTelekomSender string `mapstructure:"turktelekom_sender"`  // Türk Telekom sender name

	MutlucellUsername string `mapstructure:"mutlucell_username"` // Mutlucell username
	MutlucellPassword string `mapstructure:"mutlucell_password"` // Mutlucell password
	MutlucellAPIKey   string `mapstructure:"mutlucell_api_key"`  // Mutlucell API key
	MutlucellSender   string `mapstructure:"mutlucell_sender"`   // Mutlucell sender name

	// Webhook provider
	WebhookURL    string `mapstructure:"webhook_url"`     // Custom webhook URL for SMS delivery
	WebhookAPIKey string `mapstructure:"webhook_api_key"` // API key for webhook authentication
}

// DefaultConfig returns the default SMS configuration
func DefaultConfig() Config {
	return Config{
		Provider:      "mock",
		MessagePrefix: "OpenIDX",
		Enabled:       false,
	}
}

// Service manages SMS sending via configurable providers
type Service struct {
	provider Provider
	config   Config
	logger   *zap.Logger
}

// NewService creates a new SMS service based on configuration
func NewService(cfg Config, logger *zap.Logger) (*Service, error) {
	var provider Provider
	var err error

	switch cfg.Provider {
	case "twilio":
		provider, err = NewTwilioProvider(cfg.TwilioSID, cfg.TwilioToken, cfg.TwilioFrom, logger)
	case "aws_sns":
		provider, err = NewAWSSNSProvider(cfg.AWSRegion, cfg.AWSAccessKey, cfg.AWSSecretKey, logger)
	case "webhook":
		provider, err = NewWebhookProvider(cfg.WebhookURL, cfg.WebhookAPIKey, logger)
	// Turkish SMS providers
	case "netgsm":
		provider, err = NewNetGSMProvider(cfg.NetGSMUserCode, cfg.NetGSMPassword, cfg.NetGSMHeader, logger)
	case "ileti_merkezi":
		provider, err = NewIletiMerkeziProvider(cfg.IletiMerkeziKey, cfg.IletiMerkeziSecret, cfg.IletiMerkeziSender, logger)
	case "verimor":
		provider, err = NewVerimorProvider(cfg.VerimorUsername, cfg.VerimorPassword, cfg.VerimorSourceAddr, logger)
	case "turkcell":
		provider, err = NewTurkcellProvider(cfg.TurkcellUsername, cfg.TurkcellPassword, cfg.TurkcellSender, logger)
	case "vodafone":
		provider, err = NewVodafoneProvider(cfg.VodafoneAPIKey, cfg.VodafoneSecret, cfg.VodafoneSender, logger)
	case "turk_telekom":
		provider, err = NewTurkTelekomProvider(cfg.TurkTelekomAPIKey, cfg.TurkTelekomSecret, cfg.TurkTelekomSender, logger)
	case "mutlucell":
		provider, err = NewMutlucellProvider(cfg.MutlucellUsername, cfg.MutlucellPassword, cfg.MutlucellAPIKey, cfg.MutlucellSender, logger)
	case "mock":
		provider = NewMockProvider(logger)
	default:
		logger.Warn("Unknown SMS provider, falling back to mock", zap.String("provider", cfg.Provider))
		provider = NewMockProvider(logger)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create SMS provider: %w", err)
	}

	return &Service{
		provider: provider,
		config:   cfg,
		logger:   logger,
	}, nil
}

// SendOTP sends a one-time password to the specified phone number
func (s *Service) SendOTP(ctx context.Context, phoneNumber, code string) error {
	if !s.config.Enabled {
		s.logger.Info("SMS sending disabled, skipping OTP",
			zap.String("phone", maskPhone(phoneNumber)),
			zap.String("provider", s.provider.Name()))
		return nil
	}

	message := fmt.Sprintf("%s: Your verification code is %s. It expires in 5 minutes.", s.config.MessagePrefix, code)
	return s.provider.SendMessage(ctx, phoneNumber, message)
}

// SendMessage sends a custom message to the specified phone number
func (s *Service) SendMessage(ctx context.Context, phoneNumber, message string) error {
	if !s.config.Enabled {
		s.logger.Info("SMS sending disabled, skipping message",
			zap.String("phone", maskPhone(phoneNumber)),
			zap.String("provider", s.provider.Name()))
		return nil
	}

	return s.provider.SendMessage(ctx, phoneNumber, message)
}

// --- Twilio Provider ---

// TwilioProvider implements SMS sending via Twilio
type TwilioProvider struct {
	accountSID string
	authToken  string
	fromNumber string
	client     *http.Client
	logger     *zap.Logger
}

// NewTwilioProvider creates a new Twilio SMS provider
func NewTwilioProvider(accountSID, authToken, fromNumber string, logger *zap.Logger) (*TwilioProvider, error) {
	if accountSID == "" || authToken == "" || fromNumber == "" {
		return nil, fmt.Errorf("twilio credentials required: account_sid, auth_token, from_number")
	}

	return &TwilioProvider{
		accountSID: accountSID,
		authToken:  authToken,
		fromNumber: fromNumber,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}, nil
}

func (t *TwilioProvider) Name() string {
	return "twilio"
}

func (t *TwilioProvider) SendOTP(ctx context.Context, phoneNumber, code string) error {
	message := fmt.Sprintf("Your OpenIDX verification code is: %s", code)
	return t.SendMessage(ctx, phoneNumber, message)
}

func (t *TwilioProvider) SendMessage(ctx context.Context, phoneNumber, message string) error {
	endpoint := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", t.accountSID)

	data := url.Values{}
	data.Set("To", phoneNumber)
	data.Set("From", t.fromNumber)
	data.Set("Body", message)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(t.accountSID, t.authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("twilio request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		t.logger.Error("Twilio API error",
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(body)))
		return fmt.Errorf("twilio returned status %d: %s", resp.StatusCode, string(body))
	}

	t.logger.Info("SMS sent via Twilio",
		zap.String("to", maskPhone(phoneNumber)),
		zap.Int("status", resp.StatusCode))

	return nil
}

// --- AWS SNS Provider ---

// AWSSNSProvider implements SMS sending via AWS SNS
type AWSSNSProvider struct {
	region    string
	accessKey string
	secretKey string
	client    *http.Client
	logger    *zap.Logger
}

// NewAWSSNSProvider creates a new AWS SNS SMS provider
func NewAWSSNSProvider(region, accessKey, secretKey string, logger *zap.Logger) (*AWSSNSProvider, error) {
	if region == "" {
		region = "us-east-1"
	}

	return &AWSSNSProvider{
		region:    region,
		accessKey: accessKey,
		secretKey: secretKey,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}, nil
}

func (a *AWSSNSProvider) Name() string {
	return "aws_sns"
}

func (a *AWSSNSProvider) SendOTP(ctx context.Context, phoneNumber, code string) error {
	message := fmt.Sprintf("Your OpenIDX verification code is: %s", code)
	return a.SendMessage(ctx, phoneNumber, message)
}

func (a *AWSSNSProvider) SendMessage(ctx context.Context, phoneNumber, message string) error {
	// Simplified SNS implementation - in production use AWS SDK
	endpoint := fmt.Sprintf("https://sns.%s.amazonaws.com/", a.region)

	params := url.Values{}
	params.Set("Action", "Publish")
	params.Set("PhoneNumber", phoneNumber)
	params.Set("Message", message)
	params.Set("Version", "2010-03-31")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Note: In production, use proper AWS SigV4 signing

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("SNS request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		a.logger.Error("AWS SNS API error",
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(body)))
		return fmt.Errorf("SNS returned status %d", resp.StatusCode)
	}

	a.logger.Info("SMS sent via AWS SNS",
		zap.String("to", maskPhone(phoneNumber)),
		zap.Int("status", resp.StatusCode))

	return nil
}

// --- Mock Provider (for development/testing) ---

// MockProvider implements a mock SMS provider that logs messages
type MockProvider struct {
	logger   *zap.Logger
	messages []MockMessage
}

// MockMessage represents a sent message in the mock provider
type MockMessage struct {
	To        string    `json:"to"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// NewMockProvider creates a new mock SMS provider
func NewMockProvider(logger *zap.Logger) *MockProvider {
	return &MockProvider{
		logger:   logger,
		messages: make([]MockMessage, 0),
	}
}

func (m *MockProvider) Name() string {
	return "mock"
}

func (m *MockProvider) SendOTP(ctx context.Context, phoneNumber, code string) error {
	message := fmt.Sprintf("Your verification code is: %s", code)
	return m.SendMessage(ctx, phoneNumber, message)
}

func (m *MockProvider) SendMessage(ctx context.Context, phoneNumber, message string) error {
	msg := MockMessage{
		To:        phoneNumber,
		Message:   message,
		Timestamp: time.Now(),
	}
	m.messages = append(m.messages, msg)

	msgJSON, _ := json.Marshal(msg)
	m.logger.Info("Mock SMS sent (not actually delivered)",
		zap.String("to", maskPhone(phoneNumber)),
		zap.String("message_preview", truncate(message, 50)),
		zap.ByteString("full_message", msgJSON))

	return nil
}

// GetMessages returns all messages sent through the mock provider (for testing)
func (m *MockProvider) GetMessages() []MockMessage {
	return m.messages
}

// ClearMessages clears all stored messages (for testing)
func (m *MockProvider) ClearMessages() {
	m.messages = make([]MockMessage, 0)
}

// --- Webhook Provider (for custom integrations) ---

// WebhookProvider sends SMS via a webhook endpoint
type WebhookProvider struct {
	webhookURL string
	apiKey     string
	client     *http.Client
	logger     *zap.Logger
}

// NewWebhookProvider creates a new webhook-based SMS provider
func NewWebhookProvider(webhookURL, apiKey string, logger *zap.Logger) (*WebhookProvider, error) {
	if webhookURL == "" {
		return nil, fmt.Errorf("webhook URL required")
	}

	return &WebhookProvider{
		webhookURL: webhookURL,
		apiKey:     apiKey,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}, nil
}

func (w *WebhookProvider) Name() string {
	return "webhook"
}

func (w *WebhookProvider) SendOTP(ctx context.Context, phoneNumber, code string) error {
	message := fmt.Sprintf("Your verification code is: %s", code)
	return w.SendMessage(ctx, phoneNumber, message)
}

func (w *WebhookProvider) SendMessage(ctx context.Context, phoneNumber, message string) error {
	payload := map[string]string{
		"to":      phoneNumber,
		"message": message,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.webhookURL, bytes.NewReader(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if w.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+w.apiKey)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		w.logger.Error("Webhook SMS error",
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(body)))
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	w.logger.Info("SMS sent via webhook",
		zap.String("to", maskPhone(phoneNumber)),
		zap.Int("status", resp.StatusCode))

	return nil
}

// --- Utility Functions ---

func maskPhone(phone string) string {
	if len(phone) <= 4 {
		return "****"
	}
	return "***" + phone[len(phone)-4:]
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
