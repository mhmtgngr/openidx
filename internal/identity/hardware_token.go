// Package identity - Hardware Token (YubiKey OATH-HOTP) Support
package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// HardwareToken represents a physical security token
type HardwareToken struct {
	ID              string     `json:"id"`
	SerialNumber    string     `json:"serial_number"`
	Name            string     `json:"name"`
	TokenType       string     `json:"token_type"` // yubikey, oath-hotp, oath-totp
	SecretKey       string     `json:"-"`          // Never expose
	Counter         int64      `json:"counter,omitempty"`
	Manufacturer    string     `json:"manufacturer,omitempty"`
	Model           string     `json:"model,omitempty"`
	FirmwareVersion string     `json:"firmware_version,omitempty"`
	Status          string     `json:"status"` // available, assigned, revoked, lost
	AssignedTo      *string    `json:"assigned_to,omitempty"`
	AssignedAt      *time.Time `json:"assigned_at,omitempty"`
	AssignedBy      *string    `json:"assigned_by,omitempty"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	UseCount        int        `json:"use_count"`
	CreatedAt       time.Time  `json:"created_at"`
	Notes           string     `json:"notes,omitempty"`
}

// HardwareTokenEvent represents an event in token lifecycle
type HardwareTokenEvent struct {
	ID        string                 `json:"id"`
	TokenID   string                 `json:"token_id"`
	UserID    *string                `json:"user_id,omitempty"`
	EventType string                 `json:"event_type"`
	IPAddress string                 `json:"ip_address,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// CreateHardwareTokenRequest for registering a new token
type CreateHardwareTokenRequest struct {
	SerialNumber    string `json:"serial_number"`
	Name            string `json:"name"`
	TokenType       string `json:"token_type"`
	SecretKey       string `json:"secret_key,omitempty"` // Base32 encoded, auto-generate if empty
	Manufacturer    string `json:"manufacturer,omitempty"`
	Model           string `json:"model,omitempty"`
	FirmwareVersion string `json:"firmware_version,omitempty"`
	Notes           string `json:"notes,omitempty"`
}

// CreateHardwareToken registers a new hardware token in inventory
func (s *Service) CreateHardwareToken(ctx context.Context, req *CreateHardwareTokenRequest, createdBy string) (*HardwareToken, error) {
	if req.SerialNumber == "" {
		return nil, errors.New("serial number is required")
	}

	tokenType := req.TokenType
	if tokenType == "" {
		tokenType = "oath-hotp"
	}

	// Generate secret if not provided
	secretKey := req.SecretKey
	if secretKey == "" {
		secret := make([]byte, 20)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("failed to generate secret: %w", err)
		}
		secretKey = base32.StdEncoding.EncodeToString(secret)
	}

	// Encrypt the secret before storing
	encryptedSecret := s.encryptSecret(secretKey)

	id := uuid.New().String()
	query := `
		INSERT INTO hardware_tokens (
			id, serial_number, name, token_type, secret_key, counter,
			manufacturer, model, firmware_version, status, notes, created_at
		) VALUES ($1, $2, $3, $4, $5, 0, $6, $7, $8, 'available', $9, NOW())
		RETURNING created_at
	`

	var createdAt time.Time
	err := s.db.Pool.QueryRow(ctx, query,
		id, req.SerialNumber, req.Name, tokenType, encryptedSecret,
		req.Manufacturer, req.Model, req.FirmwareVersion, req.Notes,
	).Scan(&createdAt)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			return nil, errors.New("token with this serial number already exists")
		}
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	// Log event
	s.logTokenEvent(ctx, id, nil, "created", "", "", map[string]interface{}{
		"created_by": createdBy,
	})

	return &HardwareToken{
		ID:              id,
		SerialNumber:    req.SerialNumber,
		Name:            req.Name,
		TokenType:       tokenType,
		Manufacturer:    req.Manufacturer,
		Model:           req.Model,
		FirmwareVersion: req.FirmwareVersion,
		Status:          "available",
		UseCount:        0,
		CreatedAt:       createdAt,
		Notes:           req.Notes,
	}, nil
}

// ListHardwareTokens returns all hardware tokens with optional filtering
func (s *Service) ListHardwareTokens(ctx context.Context, status string, assignedTo string) ([]HardwareToken, error) {
	query := `
		SELECT id, serial_number, name, token_type, manufacturer, model,
			firmware_version, status, assigned_to, assigned_at, assigned_by,
			last_used_at, use_count, created_at, notes
		FROM hardware_tokens
		WHERE ($1 = '' OR status = $1)
		  AND ($2 = '' OR assigned_to::text = $2)
		ORDER BY created_at DESC
	`

	rows, err := s.db.Pool.Query(ctx, query, status, assignedTo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []HardwareToken
	for rows.Next() {
		var t HardwareToken
		err := rows.Scan(
			&t.ID, &t.SerialNumber, &t.Name, &t.TokenType, &t.Manufacturer, &t.Model,
			&t.FirmwareVersion, &t.Status, &t.AssignedTo, &t.AssignedAt, &t.AssignedBy,
			&t.LastUsedAt, &t.UseCount, &t.CreatedAt, &t.Notes,
		)
		if err != nil {
			continue
		}
		tokens = append(tokens, t)
	}

	return tokens, nil
}

// GetHardwareToken returns a specific token
func (s *Service) GetHardwareToken(ctx context.Context, tokenID string) (*HardwareToken, error) {
	query := `
		SELECT id, serial_number, name, token_type, manufacturer, model,
			firmware_version, status, assigned_to, assigned_at, assigned_by,
			last_used_at, use_count, created_at, notes
		FROM hardware_tokens
		WHERE id = $1
	`

	var t HardwareToken
	err := s.db.Pool.QueryRow(ctx, query, tokenID).Scan(
		&t.ID, &t.SerialNumber, &t.Name, &t.TokenType, &t.Manufacturer, &t.Model,
		&t.FirmwareVersion, &t.Status, &t.AssignedTo, &t.AssignedAt, &t.AssignedBy,
		&t.LastUsedAt, &t.UseCount, &t.CreatedAt, &t.Notes,
	)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

// AssignHardwareToken assigns a token to a user
func (s *Service) AssignHardwareToken(ctx context.Context, tokenID, userID, assignedBy string) error {
	// Check token is available
	var status string
	err := s.db.Pool.QueryRow(ctx, "SELECT status FROM hardware_tokens WHERE id = $1", tokenID).Scan(&status)
	if err != nil {
		return errors.New("token not found")
	}
	if status != "available" {
		return fmt.Errorf("token is not available (status: %s)", status)
	}

	// Assign token
	query := `
		UPDATE hardware_tokens
		SET status = 'assigned', assigned_to = $1, assigned_at = NOW(), assigned_by = $2
		WHERE id = $3
	`
	_, err = s.db.Pool.Exec(ctx, query, userID, assignedBy, tokenID)
	if err != nil {
		return err
	}

	// Log event
	s.logTokenEvent(ctx, tokenID, &userID, "assigned", "", "", map[string]interface{}{
		"assigned_by": assignedBy,
	})

	return nil
}

// UnassignHardwareToken removes token assignment from user
func (s *Service) UnassignHardwareToken(ctx context.Context, tokenID, unassignedBy string) error {
	var userID *string
	err := s.db.Pool.QueryRow(ctx, "SELECT assigned_to FROM hardware_tokens WHERE id = $1", tokenID).Scan(&userID)
	if err != nil {
		return errors.New("token not found")
	}

	query := `
		UPDATE hardware_tokens
		SET status = 'available', assigned_to = NULL, assigned_at = NULL, assigned_by = NULL
		WHERE id = $1
	`
	_, err = s.db.Pool.Exec(ctx, query, tokenID)
	if err != nil {
		return err
	}

	// Log event
	s.logTokenEvent(ctx, tokenID, userID, "unassigned", "", "", map[string]interface{}{
		"unassigned_by": unassignedBy,
	})

	return nil
}

// RevokeHardwareToken marks token as revoked (cannot be used)
func (s *Service) RevokeHardwareToken(ctx context.Context, tokenID, revokedBy, reason string) error {
	query := `UPDATE hardware_tokens SET status = 'revoked' WHERE id = $1`
	_, err := s.db.Pool.Exec(ctx, query, tokenID)
	if err != nil {
		return err
	}

	s.logTokenEvent(ctx, tokenID, nil, "revoked", "", "", map[string]interface{}{
		"revoked_by": revokedBy,
		"reason":     reason,
	})

	return nil
}

// ReportTokenLost marks token as lost
func (s *Service) ReportTokenLost(ctx context.Context, tokenID, reportedBy string) error {
	query := `UPDATE hardware_tokens SET status = 'lost' WHERE id = $1`
	_, err := s.db.Pool.Exec(ctx, query, tokenID)
	if err != nil {
		return err
	}

	s.logTokenEvent(ctx, tokenID, nil, "lost_reported", "", "", map[string]interface{}{
		"reported_by": reportedBy,
	})

	return nil
}

// VerifyHardwareToken validates an OTP from a hardware token
func (s *Service) VerifyHardwareToken(ctx context.Context, userID, otp string, ipAddress, userAgent string) (bool, error) {
	// Get user's assigned token
	query := `
		SELECT id, token_type, secret_key, counter
		FROM hardware_tokens
		WHERE assigned_to = $1 AND status = 'assigned'
	`

	var tokenID, tokenType, encryptedSecret string
	var counter int64
	err := s.db.Pool.QueryRow(ctx, query, userID).Scan(&tokenID, &tokenType, &encryptedSecret, &counter)
	if err != nil {
		return false, errors.New("no hardware token assigned to user")
	}

	// Decrypt secret
	secretKey := s.decryptSecret(encryptedSecret)
	secret, err := base32.StdEncoding.DecodeString(strings.ToUpper(secretKey))
	if err != nil {
		return false, errors.New("invalid token secret")
	}

	// Verify OTP based on token type
	var valid bool
	var newCounter int64

	switch tokenType {
	case "oath-hotp", "yubikey":
		valid, newCounter = s.verifyHOTP(secret, counter, otp)
	case "oath-totp":
		valid = s.verifyTOTP(secret, otp)
		newCounter = counter
	default:
		return false, fmt.Errorf("unsupported token type: %s", tokenType)
	}

	if valid {
		// Update counter and last used
		updateQuery := `
			UPDATE hardware_tokens
			SET counter = $1, last_used_at = NOW(), use_count = use_count + 1
			WHERE id = $2
		`
		s.db.Pool.Exec(ctx, updateQuery, newCounter, tokenID)

		s.logTokenEvent(ctx, tokenID, &userID, "used", ipAddress, userAgent, nil)
		return true, nil
	}

	s.logTokenEvent(ctx, tokenID, &userID, "failed", ipAddress, userAgent, map[string]interface{}{
		"reason": "invalid_otp",
	})

	return false, nil
}

// verifyHOTP validates HOTP code with look-ahead window
func (s *Service) verifyHOTP(secret []byte, counter int64, otp string) (bool, int64) {
	lookAhead := int64(10) // Allow counter drift of 10

	for i := int64(0); i <= lookAhead; i++ {
		expected := generateHOTP(secret, counter+i)
		if expected == otp {
			return true, counter + i + 1 // Return next counter
		}
	}

	return false, counter
}

// verifyTOTP validates TOTP code
func (s *Service) verifyTOTP(secret []byte, otp string) bool {
	now := time.Now().Unix()
	timeStep := int64(30)

	// Check current and adjacent time steps
	for i := int64(-1); i <= 1; i++ {
		counter := (now / timeStep) + i
		expected := generateHOTP(secret, counter)
		if expected == otp {
			return true
		}
	}

	return false
}

// generateHOTP generates an HOTP code
func generateHOTP(secret []byte, counter int64) string {
	// Convert counter to bytes
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	// HMAC-SHA1
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf)
	hash := mac.Sum(nil)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0x0f
	code := int32(hash[offset]&0x7f)<<24 |
		int32(hash[offset+1])<<16 |
		int32(hash[offset+2])<<8 |
		int32(hash[offset+3])

	// 6-digit code
	return fmt.Sprintf("%06d", code%1000000)
}

// GetUserHardwareToken returns the token assigned to a user
func (s *Service) GetUserHardwareToken(ctx context.Context, userID string) (*HardwareToken, error) {
	query := `
		SELECT id, serial_number, name, token_type, manufacturer, model,
			firmware_version, status, assigned_to, assigned_at, assigned_by,
			last_used_at, use_count, created_at, notes
		FROM hardware_tokens
		WHERE assigned_to = $1 AND status = 'assigned'
	`

	var t HardwareToken
	err := s.db.Pool.QueryRow(ctx, query, userID).Scan(
		&t.ID, &t.SerialNumber, &t.Name, &t.TokenType, &t.Manufacturer, &t.Model,
		&t.FirmwareVersion, &t.Status, &t.AssignedTo, &t.AssignedAt, &t.AssignedBy,
		&t.LastUsedAt, &t.UseCount, &t.CreatedAt, &t.Notes,
	)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

// GetTokenEvents returns events for a token
func (s *Service) GetTokenEvents(ctx context.Context, tokenID string, limit int) ([]HardwareTokenEvent, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT id, token_id, user_id, event_type, ip_address, user_agent, details, created_at
		FROM hardware_token_events
		WHERE token_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := s.db.Pool.Query(ctx, query, tokenID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []HardwareTokenEvent
	for rows.Next() {
		var e HardwareTokenEvent
		err := rows.Scan(&e.ID, &e.TokenID, &e.UserID, &e.EventType, &e.IPAddress, &e.UserAgent, &e.Details, &e.CreatedAt)
		if err != nil {
			continue
		}
		events = append(events, e)
	}

	return events, nil
}

// logTokenEvent records a token event
func (s *Service) logTokenEvent(ctx context.Context, tokenID string, userID *string, eventType, ipAddress, userAgent string, details map[string]interface{}) {
	query := `
		INSERT INTO hardware_token_events (id, token_id, user_id, event_type, ip_address, user_agent, details, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
	`
	s.db.Pool.Exec(ctx, query, uuid.New().String(), tokenID, userID, eventType, ipAddress, userAgent, details)
}

// encryptSecret encrypts a secret key (simplified - use proper encryption in production)
func (s *Service) encryptSecret(secret string) string {
	// In production, use AES-256-GCM with a proper key management system
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:]) + ":" + secret
}

// decryptSecret decrypts a secret key
func (s *Service) decryptSecret(encrypted string) string {
	parts := strings.SplitN(encrypted, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return encrypted
}
