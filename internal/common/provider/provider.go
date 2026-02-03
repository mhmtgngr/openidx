// Package provider defines interfaces for pluggable service providers.
// This enables swapping implementations (e.g., Twilio vs AWS SNS for SMS)
// without changing business logic.
package provider

import (
	"context"
	"time"
)

// ProviderType identifies the category of provider
type ProviderType string

const (
	ProviderTypeMFA     ProviderType = "mfa"
	ProviderTypeSMS     ProviderType = "sms"
	ProviderTypeEmail   ProviderType = "email"
	ProviderTypeStorage ProviderType = "storage"
	ProviderTypePush    ProviderType = "push"
)

// HealthStatus represents provider health
type HealthStatus struct {
	Healthy     bool              `json:"healthy"`
	Latency     time.Duration     `json:"latency_ms"`
	Message     string            `json:"message,omitempty"`
	LastChecked time.Time         `json:"last_checked"`
	Details     map[string]string `json:"details,omitempty"`
}

// Provider is the base interface for all providers
type Provider interface {
	// Name returns the provider identifier
	Name() string

	// Type returns the provider category
	Type() ProviderType

	// Configure configures the provider
	Configure(config map[string]interface{}) error

	// Health checks provider health
	Health(ctx context.Context) HealthStatus
}

// ============================================================================
// MFA Provider
// ============================================================================

// MFAMethod identifies the MFA method
type MFAMethod string

const (
	MFAMethodTOTP      MFAMethod = "totp"
	MFAMethodWebAuthn  MFAMethod = "webauthn"
	MFAMethodSMS       MFAMethod = "sms"
	MFAMethodEmail     MFAMethod = "email"
	MFAMethodPush      MFAMethod = "push"
	MFAMethodHardware  MFAMethod = "hardware"
	MFAMethodBackup    MFAMethod = "backup"
	MFAMethodBiometric MFAMethod = "biometric"
	MFAMethodPhoneCall MFAMethod = "phone_call"
)

// MFAChallenge represents an MFA challenge
type MFAChallenge struct {
	ID        string                 `json:"id"`
	Method    MFAMethod              `json:"method"`
	UserID    string                 `json:"user_id"`
	CreatedAt time.Time              `json:"created_at"`
	ExpiresAt time.Time              `json:"expires_at"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// MFAProvider interface for MFA implementations
type MFAProvider interface {
	Provider

	// Method returns the MFA method this provider handles
	Method() MFAMethod

	// Enroll starts the enrollment process
	Enroll(ctx context.Context, userID string, options map[string]interface{}) (*MFAEnrollment, error)

	// CompleteEnrollment completes enrollment
	CompleteEnrollment(ctx context.Context, userID string, response string) error

	// Challenge creates a new MFA challenge
	Challenge(ctx context.Context, userID string) (*MFAChallenge, error)

	// Verify verifies an MFA response
	Verify(ctx context.Context, challenge *MFAChallenge, response string) (bool, error)

	// Revoke revokes MFA for a user
	Revoke(ctx context.Context, userID string) error

	// IsEnrolled checks if user has this MFA method enrolled
	IsEnrolled(ctx context.Context, userID string) (bool, error)
}

// MFAEnrollment represents MFA enrollment data
type MFAEnrollment struct {
	Method     MFAMethod              `json:"method"`
	Secret     string                 `json:"secret,omitempty"`
	QRCode     string                 `json:"qr_code,omitempty"`
	RecoveryCodes []string            `json:"recovery_codes,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
}

// ============================================================================
// SMS Provider
// ============================================================================

// SMSMessage represents an SMS message
type SMSMessage struct {
	To      string `json:"to"`
	From    string `json:"from,omitempty"`
	Body    string `json:"body"`
	Unicode bool   `json:"unicode,omitempty"`
}

// SMSResult represents the result of sending an SMS
type SMSResult struct {
	MessageID string `json:"message_id"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}

// SMSProvider interface for SMS implementations
type SMSProvider interface {
	Provider

	// Send sends an SMS message
	Send(ctx context.Context, msg SMSMessage) (*SMSResult, error)

	// SendOTP sends an OTP code
	SendOTP(ctx context.Context, phoneNumber, code string) (*SMSResult, error)

	// GetStatus gets the delivery status of a message
	GetStatus(ctx context.Context, messageID string) (string, error)
}

// ============================================================================
// Email Provider
// ============================================================================

// EmailMessage represents an email message
type EmailMessage struct {
	To          []string          `json:"to"`
	CC          []string          `json:"cc,omitempty"`
	BCC         []string          `json:"bcc,omitempty"`
	From        string            `json:"from"`
	ReplyTo     string            `json:"reply_to,omitempty"`
	Subject     string            `json:"subject"`
	TextBody    string            `json:"text_body,omitempty"`
	HTMLBody    string            `json:"html_body,omitempty"`
	Attachments []EmailAttachment `json:"attachments,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
}

// EmailAttachment represents an email attachment
type EmailAttachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Content     []byte `json:"content"`
	Inline      bool   `json:"inline,omitempty"`
	ContentID   string `json:"content_id,omitempty"`
}

// EmailResult represents the result of sending an email
type EmailResult struct {
	MessageID string `json:"message_id"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}

// EmailProvider interface for email implementations
type EmailProvider interface {
	Provider

	// Send sends an email
	Send(ctx context.Context, msg EmailMessage) (*EmailResult, error)

	// SendTemplate sends a templated email
	SendTemplate(ctx context.Context, templateID string, to []string, data map[string]interface{}) (*EmailResult, error)

	// GetStatus gets the delivery status of an email
	GetStatus(ctx context.Context, messageID string) (string, error)
}

// ============================================================================
// Push Notification Provider
// ============================================================================

// PushMessage represents a push notification
type PushMessage struct {
	DeviceToken string                 `json:"device_token"`
	Title       string                 `json:"title"`
	Body        string                 `json:"body"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Badge       int                    `json:"badge,omitempty"`
	Sound       string                 `json:"sound,omitempty"`
	TTL         int                    `json:"ttl,omitempty"`
	Priority    string                 `json:"priority,omitempty"`
}

// PushResult represents the result of sending a push notification
type PushResult struct {
	MessageID string `json:"message_id"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}

// PushProvider interface for push notification implementations
type PushProvider interface {
	Provider

	// Send sends a push notification
	Send(ctx context.Context, msg PushMessage) (*PushResult, error)

	// SendToUser sends to all user's devices
	SendToUser(ctx context.Context, userID string, msg PushMessage) ([]PushResult, error)

	// RegisterDevice registers a device for push notifications
	RegisterDevice(ctx context.Context, userID, deviceToken, platform string) error

	// UnregisterDevice removes a device
	UnregisterDevice(ctx context.Context, deviceToken string) error
}

// ============================================================================
// Storage Provider
// ============================================================================

// StorageObject represents a stored object
type StorageObject struct {
	Key         string            `json:"key"`
	ContentType string            `json:"content_type"`
	Size        int64             `json:"size"`
	ETag        string            `json:"etag,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	LastModified time.Time        `json:"last_modified"`
}

// StorageProvider interface for storage implementations
type StorageProvider interface {
	Provider

	// Put stores an object
	Put(ctx context.Context, key string, data []byte, contentType string) error

	// Get retrieves an object
	Get(ctx context.Context, key string) ([]byte, error)

	// Delete deletes an object
	Delete(ctx context.Context, key string) error

	// Exists checks if an object exists
	Exists(ctx context.Context, key string) (bool, error)

	// List lists objects with prefix
	List(ctx context.Context, prefix string, maxKeys int) ([]StorageObject, error)

	// GetSignedURL returns a pre-signed URL for temporary access
	GetSignedURL(ctx context.Context, key string, expiry time.Duration) (string, error)
}

// ============================================================================
// Directory Provider (LDAP, AD, etc.)
// ============================================================================

// DirectoryUser represents a user from a directory
type DirectoryUser struct {
	DN          string            `json:"dn"`
	Username    string            `json:"username"`
	Email       string            `json:"email"`
	FirstName   string            `json:"first_name"`
	LastName    string            `json:"last_name"`
	DisplayName string            `json:"display_name"`
	Groups      []string          `json:"groups"`
	Attributes  map[string]string `json:"attributes"`
	Enabled     bool              `json:"enabled"`
}

// DirectoryGroup represents a group from a directory
type DirectoryGroup struct {
	DN          string   `json:"dn"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Members     []string `json:"members"`
}

// DirectoryProvider interface for directory implementations
type DirectoryProvider interface {
	Provider

	// Authenticate authenticates a user
	Authenticate(ctx context.Context, username, password string) (*DirectoryUser, error)

	// GetUser gets a user by username
	GetUser(ctx context.Context, username string) (*DirectoryUser, error)

	// SearchUsers searches for users
	SearchUsers(ctx context.Context, filter string, limit int) ([]DirectoryUser, error)

	// GetGroups gets groups for a user
	GetGroups(ctx context.Context, username string) ([]DirectoryGroup, error)

	// SyncUsers syncs users from directory
	SyncUsers(ctx context.Context) ([]DirectoryUser, error)
}

// ============================================================================
// Provider Registry
// ============================================================================

// Registry manages providers
type Registry struct {
	providers map[ProviderType]map[string]Provider
}

// NewRegistry creates a new provider registry
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[ProviderType]map[string]Provider),
	}
}

// Register registers a provider
func (r *Registry) Register(p Provider) {
	pt := p.Type()
	if r.providers[pt] == nil {
		r.providers[pt] = make(map[string]Provider)
	}
	r.providers[pt][p.Name()] = p
}

// Get gets a provider by type and name
func (r *Registry) Get(pt ProviderType, name string) Provider {
	if r.providers[pt] == nil {
		return nil
	}
	return r.providers[pt][name]
}

// GetByType gets all providers of a type
func (r *Registry) GetByType(pt ProviderType) []Provider {
	if r.providers[pt] == nil {
		return nil
	}
	result := make([]Provider, 0, len(r.providers[pt]))
	for _, p := range r.providers[pt] {
		result = append(result, p)
	}
	return result
}

// GetMFA gets an MFA provider
func (r *Registry) GetMFA(name string) MFAProvider {
	p := r.Get(ProviderTypeMFA, name)
	if p == nil {
		return nil
	}
	return p.(MFAProvider)
}

// GetSMS gets an SMS provider
func (r *Registry) GetSMS(name string) SMSProvider {
	p := r.Get(ProviderTypeSMS, name)
	if p == nil {
		return nil
	}
	return p.(SMSProvider)
}

// GetEmail gets an email provider
func (r *Registry) GetEmail(name string) EmailProvider {
	p := r.Get(ProviderTypeEmail, name)
	if p == nil {
		return nil
	}
	return p.(EmailProvider)
}

// Health checks health of all providers
func (r *Registry) Health(ctx context.Context) map[string]HealthStatus {
	result := make(map[string]HealthStatus)
	for pt, providers := range r.providers {
		for name, p := range providers {
			key := string(pt) + ":" + name
			result[key] = p.Health(ctx)
		}
	}
	return result
}

// Global provider registry
var globalRegistry = NewRegistry()

// Register registers to global registry
func Register(p Provider) {
	globalRegistry.Register(p)
}

// Get gets from global registry
func Get(pt ProviderType, name string) Provider {
	return globalRegistry.Get(pt, name)
}

// GetMFA gets MFA provider from global registry
func GetMFA(name string) MFAProvider {
	return globalRegistry.GetMFA(name)
}

// GetSMS gets SMS provider from global registry
func GetSMS(name string) SMSProvider {
	return globalRegistry.GetSMS(name)
}

// GetEmail gets email provider from global registry
func GetEmail(name string) EmailProvider {
	return globalRegistry.GetEmail(name)
}

// Global returns the global registry
func Global() *Registry {
	return globalRegistry
}
