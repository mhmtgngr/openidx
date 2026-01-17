// Package identity - Push Notification MFA implementation
package identity

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PushMFADevice represents a registered push notification device
type PushMFADevice struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	DeviceToken string     `json:"-"` // Never expose token in JSON
	Platform    string     `json:"platform"` // ios, android, web
	DeviceName  string     `json:"device_name"`
	DeviceModel string     `json:"device_model,omitempty"`
	OSVersion   string     `json:"os_version,omitempty"`
	AppVersion  string     `json:"app_version,omitempty"`
	Enabled     bool       `json:"enabled"`
	Trusted     bool       `json:"trusted"`
	LastIP      string     `json:"last_ip,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// PushMFAChallenge represents a push notification challenge
type PushMFAChallenge struct {
	ID            string                 `json:"id"`
	UserID        string                 `json:"user_id"`
	DeviceID      string                 `json:"device_id"`
	ChallengeCode string                 `json:"challenge_code"` // Number matching code
	Status        string                 `json:"status"`         // pending, approved, denied, expired
	SessionInfo   map[string]interface{} `json:"session_info,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	ExpiresAt     time.Time              `json:"expires_at"`
	RespondedAt   *time.Time             `json:"responded_at,omitempty"`
	IPAddress     string                 `json:"ip_address,omitempty"`
	UserAgent     string                 `json:"user_agent,omitempty"`
	Location      string                 `json:"location,omitempty"`
}

// PushMFAEnrollment represents enrollment request
type PushMFAEnrollment struct {
	DeviceToken string `json:"device_token"`
	Platform    string `json:"platform"`
	DeviceName  string `json:"device_name"`
	DeviceModel string `json:"device_model,omitempty"`
	OSVersion   string `json:"os_version,omitempty"`
	AppVersion  string `json:"app_version,omitempty"`
}

// PushMFAChallengeRequest represents challenge creation request
type PushMFAChallengeRequest struct {
	UserID    string `json:"user_id"`
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Location  string `json:"location,omitempty"`
}

// PushMFAChallengeResponse represents challenge response from user
type PushMFAChallengeResponse struct {
	ChallengeID   string `json:"challenge_id"`
	ChallengeCode string `json:"challenge_code"` // User must enter the number they see
	Approved      bool   `json:"approved"`
}

// RegisterPushMFADevice registers a new push notification device
func (s *Service) RegisterPushMFADevice(ctx context.Context, userID string, enrollment *PushMFAEnrollment, ipAddress string) (*PushMFADevice, error) {
	// Validate platform
	if enrollment.Platform != "ios" && enrollment.Platform != "android" && enrollment.Platform != "web" {
		return nil, fmt.Errorf("invalid platform: must be ios, android, or web")
	}

	// Check if device already exists
	existingDevice, err := s.getPushDeviceByToken(ctx, enrollment.DeviceToken)
	if err == nil && existingDevice != nil {
		// Update existing device
		existingDevice.DeviceName = enrollment.DeviceName
		existingDevice.DeviceModel = enrollment.DeviceModel
		existingDevice.OSVersion = enrollment.OSVersion
		existingDevice.AppVersion = enrollment.AppVersion
		existingDevice.Enabled = true
		existingDevice.LastIP = ipAddress

		if err := s.updatePushDevice(ctx, existingDevice); err != nil {
			return nil, fmt.Errorf("failed to update device: %w", err)
		}

		s.logger.Info("Push MFA device updated",
			zap.String("user_id", userID),
			zap.String("device_id", existingDevice.ID),
			zap.String("platform", enrollment.Platform))

		return existingDevice, nil
	}

	// Create new device
	device := &PushMFADevice{
		ID:          uuid.New().String(),
		UserID:      userID,
		DeviceToken: enrollment.DeviceToken,
		Platform:    enrollment.Platform,
		DeviceName:  enrollment.DeviceName,
		DeviceModel: enrollment.DeviceModel,
		OSVersion:   enrollment.OSVersion,
		AppVersion:  enrollment.AppVersion,
		Enabled:     true,
		Trusted:     false, // Require trust establishment
		LastIP:      ipAddress,
		CreatedAt:   time.Now(),
	}

	if err := s.storePushDevice(ctx, device); err != nil {
		return nil, fmt.Errorf("failed to store device: %w", err)
	}

	s.logger.Info("Push MFA device registered",
		zap.String("user_id", userID),
		zap.String("device_id", device.ID),
		zap.String("platform", enrollment.Platform))

	return device, nil
}

// CreatePushMFAChallenge creates a new push notification challenge
func (s *Service) CreatePushMFAChallenge(ctx context.Context, request *PushMFAChallengeRequest) (*PushMFAChallenge, error) {
	// Get user's active devices
	devices, err := s.GetPushMFADevices(ctx, request.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}

	if len(devices) == 0 {
		return nil, fmt.Errorf("no push MFA devices registered")
	}

	// Find first enabled device (in production, allow user to choose or send to all)
	var targetDevice *PushMFADevice
	for _, d := range devices {
		if d.Enabled {
			targetDevice = &d
			break
		}
	}

	if targetDevice == nil {
		return nil, fmt.Errorf("no enabled push MFA devices found")
	}

	// Generate random number matching code (2 digits)
	codeNum, err := rand.Int(rand.Reader, big.NewInt(90))
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge code: %w", err)
	}
	challengeCode := fmt.Sprintf("%02d", codeNum.Int64()+10) // Ensures 2 digits (10-99)

	// Create challenge
	challenge := &PushMFAChallenge{
		ID:            uuid.New().String(),
		UserID:        request.UserID,
		DeviceID:      targetDevice.ID,
		ChallengeCode: challengeCode,
		Status:        "pending",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Duration(s.cfg.PushMFA.ChallengeTimeout) * time.Second),
		IPAddress:     request.IPAddress,
		UserAgent:     request.UserAgent,
		Location:      request.Location,
	}

	// Store challenge
	if err := s.storePushChallenge(ctx, challenge); err != nil {
		return nil, fmt.Errorf("failed to store challenge: %w", err)
	}

	// Send push notification
	if err := s.sendPushNotification(ctx, targetDevice, challenge); err != nil {
		s.logger.Error("Failed to send push notification",
			zap.String("challenge_id", challenge.ID),
			zap.Error(err))
		// Don't fail the challenge creation, just log the error
	}

	s.logger.Info("Push MFA challenge created",
		zap.String("user_id", request.UserID),
		zap.String("challenge_id", challenge.ID),
		zap.String("device_id", targetDevice.ID))

	return challenge, nil
}

// VerifyPushMFAChallenge verifies a push MFA challenge response
func (s *Service) VerifyPushMFAChallenge(ctx context.Context, response *PushMFAChallengeResponse) (bool, error) {
	// Get challenge
	challenge, err := s.getPushChallenge(ctx, response.ChallengeID)
	if err != nil {
		return false, fmt.Errorf("challenge not found: %w", err)
	}

	// Check if already responded
	if challenge.Status != "pending" {
		return false, fmt.Errorf("challenge already responded: %s", challenge.Status)
	}

	// Check expiry
	if time.Now().After(challenge.ExpiresAt) {
		challenge.Status = "expired"
		s.updatePushChallenge(ctx, challenge)
		return false, fmt.Errorf("challenge expired")
	}

	// Verify challenge code (number matching)
	if response.ChallengeCode != challenge.ChallengeCode {
		s.logger.Warn("Push MFA challenge code mismatch",
			zap.String("challenge_id", challenge.ID),
			zap.String("expected", challenge.ChallengeCode),
			zap.String("received", response.ChallengeCode))
		return false, fmt.Errorf("invalid challenge code")
	}

	// Update challenge status
	now := time.Now()
	challenge.RespondedAt = &now
	if response.Approved {
		challenge.Status = "approved"
	} else {
		challenge.Status = "denied"
	}

	if err := s.updatePushChallenge(ctx, challenge); err != nil {
		s.logger.Error("Failed to update challenge", zap.Error(err))
	}

	// Update device last used time
	s.updatePushDeviceLastUsed(ctx, challenge.DeviceID)

	s.logger.Info("Push MFA challenge verified",
		zap.String("challenge_id", challenge.ID),
		zap.String("status", challenge.Status),
		zap.Bool("approved", response.Approved))

	return response.Approved, nil
}

// GetPushMFAChallenge retrieves a challenge by ID
func (s *Service) GetPushMFAChallenge(ctx context.Context, challengeID string) (*PushMFAChallenge, error) {
	return s.getPushChallenge(ctx, challengeID)
}

// GetPushMFADevices returns all push MFA devices for a user
func (s *Service) GetPushMFADevices(ctx context.Context, userID string) ([]PushMFADevice, error) {
	query := `
		SELECT id, user_id, device_token, platform, device_name, device_model,
		       os_version, app_version, enabled, trusted, last_ip,
		       created_at, last_used_at, expires_at
		FROM mfa_push_devices
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	rows, err := s.db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []PushMFADevice
	for rows.Next() {
		var device PushMFADevice
		err := rows.Scan(
			&device.ID,
			&device.UserID,
			&device.DeviceToken,
			&device.Platform,
			&device.DeviceName,
			&device.DeviceModel,
			&device.OSVersion,
			&device.AppVersion,
			&device.Enabled,
			&device.Trusted,
			&device.LastIP,
			&device.CreatedAt,
			&device.LastUsedAt,
			&device.ExpiresAt,
		)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}

	return devices, nil
}

// DeletePushMFADevice removes a push MFA device
func (s *Service) DeletePushMFADevice(ctx context.Context, userID, deviceID string) error {
	query := `DELETE FROM mfa_push_devices WHERE user_id = $1 AND id = $2`
	result, err := s.db.Pool.Exec(ctx, query, userID, deviceID)
	if err != nil {
		return fmt.Errorf("failed to delete device: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("device not found")
	}

	s.logger.Info("Push MFA device deleted",
		zap.String("user_id", userID),
		zap.String("device_id", deviceID))

	return nil
}

// Helper functions

func (s *Service) getPushDeviceByToken(ctx context.Context, token string) (*PushMFADevice, error) {
	query := `
		SELECT id, user_id, device_token, platform, device_name, device_model,
		       os_version, app_version, enabled, trusted, last_ip,
		       created_at, last_used_at, expires_at
		FROM mfa_push_devices
		WHERE device_token = $1
	`

	var device PushMFADevice
	err := s.db.Pool.QueryRow(ctx, query, token).Scan(
		&device.ID,
		&device.UserID,
		&device.DeviceToken,
		&device.Platform,
		&device.DeviceName,
		&device.DeviceModel,
		&device.OSVersion,
		&device.AppVersion,
		&device.Enabled,
		&device.Trusted,
		&device.LastIP,
		&device.CreatedAt,
		&device.LastUsedAt,
		&device.ExpiresAt,
	)

	if err != nil {
		return nil, err
	}

	return &device, nil
}

func (s *Service) storePushDevice(ctx context.Context, device *PushMFADevice) error {
	query := `
		INSERT INTO mfa_push_devices
		(id, user_id, device_token, platform, device_name, device_model,
		 os_version, app_version, enabled, trusted, last_ip, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := s.db.Pool.Exec(ctx, query,
		device.ID,
		device.UserID,
		device.DeviceToken,
		device.Platform,
		device.DeviceName,
		device.DeviceModel,
		device.OSVersion,
		device.AppVersion,
		device.Enabled,
		device.Trusted,
		device.LastIP,
		device.CreatedAt,
	)

	return err
}

func (s *Service) updatePushDevice(ctx context.Context, device *PushMFADevice) error {
	query := `
		UPDATE mfa_push_devices
		SET device_name = $1, device_model = $2, os_version = $3,
		    app_version = $4, enabled = $5, last_ip = $6
		WHERE id = $7
	`

	_, err := s.db.Pool.Exec(ctx, query,
		device.DeviceName,
		device.DeviceModel,
		device.OSVersion,
		device.AppVersion,
		device.Enabled,
		device.LastIP,
		device.ID,
	)

	return err
}

func (s *Service) updatePushDeviceLastUsed(ctx context.Context, deviceID string) error {
	query := `UPDATE mfa_push_devices SET last_used_at = $1 WHERE id = $2`
	_, err := s.db.Pool.Exec(ctx, query, time.Now(), deviceID)
	return err
}

func (s *Service) storePushChallenge(ctx context.Context, challenge *PushMFAChallenge) error {
	sessionInfoJSON, _ := json.Marshal(challenge.SessionInfo)

	query := `
		INSERT INTO mfa_push_challenges
		(id, user_id, device_id, challenge_code, status, session_info,
		 created_at, expires_at, ip_address, user_agent, location)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err := s.db.Pool.Exec(ctx, query,
		challenge.ID,
		challenge.UserID,
		challenge.DeviceID,
		challenge.ChallengeCode,
		challenge.Status,
		sessionInfoJSON,
		challenge.CreatedAt,
		challenge.ExpiresAt,
		challenge.IPAddress,
		challenge.UserAgent,
		challenge.Location,
	)

	return err
}

func (s *Service) getPushChallenge(ctx context.Context, challengeID string) (*PushMFAChallenge, error) {
	query := `
		SELECT id, user_id, device_id, challenge_code, status, session_info,
		       created_at, expires_at, responded_at, ip_address, user_agent, location
		FROM mfa_push_challenges
		WHERE id = $1
	`

	var challenge PushMFAChallenge
	var sessionInfoJSON []byte

	err := s.db.Pool.QueryRow(ctx, query, challengeID).Scan(
		&challenge.ID,
		&challenge.UserID,
		&challenge.DeviceID,
		&challenge.ChallengeCode,
		&challenge.Status,
		&sessionInfoJSON,
		&challenge.CreatedAt,
		&challenge.ExpiresAt,
		&challenge.RespondedAt,
		&challenge.IPAddress,
		&challenge.UserAgent,
		&challenge.Location,
	)

	if err != nil {
		return nil, err
	}

	if len(sessionInfoJSON) > 0 {
		json.Unmarshal(sessionInfoJSON, &challenge.SessionInfo)
	}

	return &challenge, nil
}

func (s *Service) updatePushChallenge(ctx context.Context, challenge *PushMFAChallenge) error {
	query := `
		UPDATE mfa_push_challenges
		SET status = $1, responded_at = $2
		WHERE id = $3
	`

	_, err := s.db.Pool.Exec(ctx, query,
		challenge.Status,
		challenge.RespondedAt,
		challenge.ID,
	)

	return err
}

func (s *Service) sendPushNotification(ctx context.Context, device *PushMFADevice, challenge *PushMFAChallenge) error {
	// Auto-approve in development mode (for testing without actual push service)
	if s.cfg.PushMFA.AutoApprove {
		s.logger.Info("Auto-approving push challenge (development mode)",
			zap.String("challenge_id", challenge.ID))
		return nil
	}

	// Build notification payload
	payload := map[string]interface{}{
		"challenge_id":   challenge.ID,
		"challenge_code": challenge.ChallengeCode,
		"ip_address":     challenge.IPAddress,
		"location":       challenge.Location,
		"user_agent":     challenge.UserAgent,
		"expires_at":     challenge.ExpiresAt.Unix(),
	}

	// Send based on platform
	switch device.Platform {
	case "android", "web":
		return s.sendFCMNotification(ctx, device.DeviceToken, payload)
	case "ios":
		return s.sendAPNSNotification(ctx, device.DeviceToken, payload)
	default:
		return fmt.Errorf("unsupported platform: %s", device.Platform)
	}
}

func (s *Service) sendFCMNotification(ctx context.Context, token string, payload map[string]interface{}) error {
	// TODO: Implement Firebase Cloud Messaging
	// This would use the Firebase Admin SDK or HTTP API
	s.logger.Info("Sending FCM notification",
		zap.String("token_prefix", token[:min(10, len(token))]),
		zap.Any("payload", payload))

	// Placeholder for actual FCM implementation
	// In production, this would send actual push notifications via FCM
	return nil
}

func (s *Service) sendAPNSNotification(ctx context.Context, token string, payload map[string]interface{}) error {
	// TODO: Implement Apple Push Notification Service
	// This would use the APNs HTTP/2 API
	s.logger.Info("Sending APNS notification",
		zap.String("token_prefix", token[:min(10, len(token))]),
		zap.Any("payload", payload))

	// Placeholder for actual APNS implementation
	// In production, this would send actual push notifications via APNs
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
