// Package mfa provides WebAuthn/FIDO2 passwordless authentication for OpenIDX
package mfa

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// WebAuthnService handles WebAuthn/FIDO2 registration and authentication ceremonies
type WebAuthnService struct {
	webAuthn *webauthn.WebAuthn
	store    WebAuthnStore
	logger   *zap.Logger
	config   *WebAuthnConfig
}

// WebAuthnConfig holds WebAuthn configuration
type WebAuthnConfig struct {
	RPDisplayName string   // Display name for the relying party
	RPID          string   // Relying party ID (typically the domain)
	RPOrigins     []string // Allowed origins for WebAuthn (e.g., https://example.com)
	Timeout       int      // Timeout in milliseconds for ceremonies
	UserVerification string // User verification requirement ("required", "preferred", "discouraged")
	AuthenticatorSelection webauthn.AuthenticatorSelection
}

// DefaultWebAuthnConfig returns default WebAuthn configuration
func DefaultWebAuthnConfig(rpID string, origins []string) *WebAuthnConfig {
	return &WebAuthnConfig{
		RPDisplayName: "OpenIDX",
		RPID:          rpID,
		RPOrigins:     origins,
		Timeout:       60000, // 60 seconds
		UserVerification: "preferred",
		AuthenticatorSelection: webauthn.AuthenticatorSelection{
			RequireResidentKey: protocol.ResidentKeyNotRequired(),
			UserVerification:   protocol.VerificationPreferred,
			AuthenticatorAttachment: protocol.AuthenticatorAttachmentUnspecified,
		},
	}
}

// NewWebAuthnService creates a new WebAuthn service
func NewWebAuthnService(
	config *WebAuthnConfig,
	store WebAuthnStore,
	logger *zap.Logger,
) (*WebAuthnService, error) {
	if config == nil {
		return nil, fmt.Errorf("webauthn config cannot be nil")
	}

	// Create WebAuthn instance
	wconfig := &webauthn.Config{
		RPDisplayName:         config.RPDisplayName,
		RPID:                  config.RPID,
		RPOrigins:             config.RPOrigins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: config.AuthenticatorSelection,
	}

	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn instance: %w", err)
	}

	return &WebAuthnService{
		webAuthn: webAuthn,
		store:    store,
		logger:   logger,
		config:   config,
	}, nil
}

// webauthnUser adapts a user credential to the webauthn.User interface
type webauthnUser struct {
	*WebAuthnCredential
}

// WebAuthnUserID is the interface for user lookups
type WebAuthnUserID interface {
	GetUUID() uuid.UUID
}

// WebAuthnCredential represents a stored WebAuthn credential
type WebAuthnCredential struct {
	ID              uuid.UUID   `json:"id"`
	CredentialID    string      `json:"credential_id"`    // Base64URL-encoded credential ID
	PublicKey       []byte      `json:"public_key"`       // Marshal'd public key
	AttestationType string      `json:"attestation_type"` // Attestation type (e.g., "none", "packed")
	AAGUID          []byte      `json:"aaguid"`           // Authenticator AAGUID
	SignCount       uint32      `json:"sign_count"`       // Signature counter
	Transports      []string    `json:"transports"`       // Transport types (usb, nfc, ble, internal)
	UserID          uuid.UUID   `json:"user_id"`          // User ID
	UserHandle      []byte      `json:"user_handle"`      // User handle for WebAuthn
	FriendlyName    string      `json:"friendly_name"`    // User-friendly name for the credential
	BackupEligible  bool        `json:"backup_eligible"`  // Whether the credential is backup eligible
	BackupState     bool        `json:"backup_state"`     // Whether the credential is backed up
	CreatedAt       time.Time   `json:"created_at"`
	LastUsedAt      *time.Time  `json:"last_used_at"`
}

// CredentialCreationOptions is the response for BeginRegistration
type CredentialCreationOptions struct {
	PublicKey *protocol.CredentialCreation `json:"publicKey"`
	Status    string                       `json:"status"`
	Message   string                       `json:"message"`
}

// CredentialAssertionOptions is the response for BeginLogin
type CredentialAssertionOptions struct {
	PublicKey *protocol.CredentialAssertion `json:"publicKey"`
	Status    string                        `json:"status"`
	Message   string                        `json:"message"`
}

// RegistrationBeginRequest initiates WebAuthn registration
type RegistrationBeginRequest struct {
	UserID      uuid.UUID `json:"user_id" binding:"required"`
	Username    string    `json:"username" binding:"required"`
	DisplayName string    `json:"display_name"`
	FriendlyName string   `json:"friendly_name"` // Optional name for the credential
}

// RegistrationFinishRequest completes WebAuthn registration
type RegistrationFinishRequest struct {
	UserID    uuid.UUID              `json:"user_id" binding:"required"`
	Response  protocol.CredentialCreationResponse `json:"response"`
	SessionID string                 `json:"session_id"`
}

// LoginBeginRequest initiates WebAuthn login
type LoginBeginRequest struct {
	UserID uuid.UUID `json:"user_id" binding:"required"`
}

// LoginFinishRequest completes WebAuthn login
type LoginFinishRequest struct {
	UserID    uuid.UUID              `json:"user_id" binding:"required"`
	Response  protocol.CredentialAssertionResponse `json:"response"`
}

// BeginRegistration starts the WebAuthn registration ceremony
// Generates a challenge and credential creation options for the client
func (s *WebAuthnService) BeginRegistration(
	ctx context.Context,
	userID uuid.UUID,
	username string,
	displayName string,
	friendlyName string,
) (*CredentialCreationOptions, error) {
	s.logger.Info("Beginning WebAuthn registration",
		zap.String("user_id", userID.String()),
		zap.String("username", username),
	)

	// Get existing credentials for this user
	existingCredentials, err := s.store.ListCredentials(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get existing credentials",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to get existing credentials: %w", err)
	}

	// Create webauthn.User from existing credentials
	user := &webauthnUser{
		WebAuthnCredential: &WebAuthnCredential{
			UserID:     userID,
			UserHandle: userID[:], // Use UUID bytes as user handle
		},
	}

	// Set display name and username
	userDisplayName := displayName
	if userDisplayName == "" {
		userDisplayName = username
	}

	// Convert existing credentials to webauthn.Credential
	credentials := make([]webauthn.Credential, len(existingCredentials))
	for i, cred := range existingCredentials {
		credentialID, err := base64.RawURLEncoding.DecodeString(cred.CredentialID)
		if err != nil {
			s.logger.Error("Failed to decode credential ID",
				zap.String("credential_id", cred.CredentialID),
				zap.Error(err),
			)
			continue
		}

		// Convert transports
		var transports []protocol.AuthenticatorTransport
		for _, t := range cred.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}

		credentials[i] = webauthn.Credential{
			ID:              credentialID,
			PublicKey:       cred.PublicKey,
			AttestationType: cred.AttestationType,
			Authenticator: webauthn.Authenticator{
				AAGUID:       cred.AAGUID,
				SignCount:    cred.SignCount,
				CloneWarning: false,
			},
			Transport: transports,
		}
	}

	// Create registration options
	options := []webauthn.RegistrationOption{
		webauthn.WithAuthenticatorSelection(s.config.AuthenticatorSelection),
		webauthn.WithUserVerification(protocol.UserVerificationPreference(s.config.UserVerification)),
		webauthn.WithExclusions(credentials),
	}

	// Begin registration
	creation, sessionData, err := s.webAuthn.BeginRegistration(
		&webAuthnUserData{
			id:          userID[:],
			displayName: userDisplayName,
			name:        username,
			credentials: credentials,
		},
		options...,
	)
	if err != nil {
		s.logger.Error("Failed to begin registration",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to begin registration: %w", err)
	}

	// Store session data for later verification
	// Use a unique session key
	sessionKey := fmt.Sprintf("webauthn:registration:%s:%s", userID.String(), sessionData.Challenge.String())
	if err := s.store.StoreSession(ctx, sessionKey, sessionData, time.Duration(s.config.Timeout)*time.Millisecond); err != nil {
		s.logger.Error("Failed to store session data",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to store session data: %w", err)
	}

	// Store the friendly name for use in finish registration
	if friendlyName != "" {
		friendlyNameKey := fmt.Sprintf("webauthn:friendly:%s:%s", userID.String(), sessionData.Challenge.String())
		_ = s.store.StoreSession(ctx, friendlyNameKey, []byte(friendlyName), time.Duration(s.config.Timeout)*time.Millisecond)
	}

	s.logger.Info("WebAuthn registration begun",
		zap.String("user_id", userID.String()),
		zap.String("challenge", sessionData.Challenge.String()),
	)

	return &CredentialCreationOptions{
		PublicKey: creation,
		Status:    "ok",
		Message:   "Registration initiated",
	}, nil
}

// FinishRegistration completes the WebAuthn registration ceremony
// Verifies attestation and stores the credential
func (s *WebAuthnService) FinishRegistration(
	ctx context.Context,
	userID uuid.UUID,
	response *protocol.CredentialCreationResponse,
) (*WebAuthnCredential, error) {
	s.logger.Info("Finishing WebAuthn registration",
		zap.String("user_id", userID.String()),
	)

	// Get the challenge from response
	challenge := response.Response.CollectedClientData.Challenge

	// Retrieve session data
	sessionKey := fmt.Sprintf("webauthn:registration:%s:%s", userID.String(), challenge)
	sessionDataBytes, err := s.store.GetSession(ctx, sessionKey)
	if err != nil {
		s.logger.Error("Failed to get session data",
			zap.String("user_id", userID.String()),
			zap.String("challenge", challenge),
			zap.Error(err),
		)
		return nil, fmt.Errorf("session not found or expired: %w", err)
	}

	// Unmarshal session data
	var sessionData webauthn.SessionData
	if err := json.Unmarshal(sessionDataBytes, &sessionData); err != nil {
		s.logger.Error("Failed to unmarshal session data",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("invalid session data: %w", err)
	}

	// Get the user
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		s.logger.Error("User not found",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Get friendly name if provided
	friendlyNameKey := fmt.Sprintf("webauthn:friendly:%s:%s", userID.String(), challenge)
	friendlyNameBytes, _ := s.store.GetSession(ctx, friendlyNameKey)
	friendlyName := "Passkey"
	if friendlyNameBytes != nil {
		friendlyName = string(friendlyNameBytes)
	}

	// Create a credential object for the webauthn library
	credential, err := s.webAuthn.FinishRegistration(
		&webAuthnUserData{
			id:          user.UserID[:],
			displayName: user.DisplayName,
			name:        user.Username,
			credentials: nil, // We don't need existing creds for registration
		},
		sessionData,
		response,
	)
	if err != nil {
		s.logger.Error("Failed to finish registration",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to verify attestation: %w", err)
	}

	// Encode credential ID as base64URL
	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)

	// Extract transports
	var transports []string
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}

	// Create the credential record
	newCredential := &WebAuthnCredential{
		ID:              uuid.New(),
		CredentialID:    credentialID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
		Transports:      transports,
		UserID:          userID,
		UserHandle:      userID[:],
		FriendlyName:    friendlyName,
		BackupEligible:  response.Response.AuthenticatorData.Flags.HasBackupEligible(),
		BackupState:     response.Response.AuthenticatorData.Flags.HasBackupState(),
		CreatedAt:       time.Now(),
	}

	// Store the credential
	if err := s.store.CreateCredential(ctx, newCredential); err != nil {
		s.logger.Error("Failed to store credential",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to store credential: %w", err)
	}

	// Clean up session data
	_ = s.store.DeleteSession(ctx, sessionKey)
	_ = s.store.DeleteSession(ctx, friendlyNameKey)

	s.logger.Info("WebAuthn registration completed",
		zap.String("user_id", userID.String()),
		zap.String("credential_id", credentialID),
		zap.Uint32("sign_count", credential.Authenticator.SignCount),
	)

	return newCredential, nil
}

// BeginLogin starts the WebAuthn login ceremony
// Generates a challenge and assertion options for the client
func (s *WebAuthnService) BeginLogin(
	ctx context.Context,
	userID uuid.UUID,
) (*CredentialAssertionOptions, error) {
	s.logger.Info("Beginning WebAuthn login",
		zap.String("user_id", userID.String()),
	)

	// Get user
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		s.logger.Error("User not found",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Get credentials for this user
	credentials, err := s.store.ListCredentials(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get credentials",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("no credentials found for user")
	}

	// Convert credentials to webauthn.Credential
	webAuthnCredentials := make([]webauthn.Credential, len(credentials))
	for i, cred := range credentials {
		credentialID, err := base64.RawURLEncoding.DecodeString(cred.CredentialID)
		if err != nil {
			s.logger.Error("Failed to decode credential ID",
				zap.String("credential_id", cred.CredentialID),
				zap.Error(err),
			)
			continue
		}

		var transports []protocol.AuthenticatorTransport
		for _, t := range cred.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}

		webAuthnCredentials[i] = webauthn.Credential{
			ID:              credentialID,
			PublicKey:       cred.PublicKey,
			AttestationType: cred.AttestationType,
			Authenticator: webauthn.Authenticator{
				AAGUID:       cred.AAGUID,
				SignCount:    cred.SignCount,
				CloneWarning: false,
			},
			Transport: transports,
		}
	}

	// Create login options
	options := []webauthn.LoginOption{
		webauthn.WithUserVerification(protocol.UserVerificationPreference(s.config.UserVerification)),
	}

	// Begin login
	assertion, sessionData, err := s.webAuthn.BeginLogin(
		&webAuthnUserData{
			id:          user.UserID[:],
			displayName: user.DisplayName,
			name:        user.Username,
			credentials: webAuthnCredentials,
		},
		options...,
	)
	if err != nil {
		s.logger.Error("Failed to begin login",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to begin login: %w", err)
	}

	// Store session data
	sessionKey := fmt.Sprintf("webauthn:login:%s:%s", userID.String(), sessionData.Challenge.String())
	if err := s.store.StoreSession(ctx, sessionKey, sessionData, time.Duration(s.config.Timeout)*time.Millisecond); err != nil {
		s.logger.Error("Failed to store session data",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to store session data: %w", err)
	}

	s.logger.Info("WebAuthn login begun",
		zap.String("user_id", userID.String()),
		zap.String("challenge", sessionData.Challenge.String()),
	)

	return &CredentialAssertionOptions{
		PublicKey: assertion,
		Status:    "ok",
		Message:   "Login initiated",
	}, nil
}

// FinishLogin completes the WebAuthn login ceremony
// Verifies the assertion and checks the sign count
func (s *WebAuthnService) FinishLogin(
	ctx context.Context,
	userID uuid.UUID,
	response *protocol.CredentialAssertionResponse,
) (*WebAuthnCredential, error) {
	s.logger.Info("Finishing WebAuthn login",
		zap.String("user_id", userID.String()),
	)

	// Get the challenge from response
	challenge := response.Response.CollectedClientData.Challenge

	// Retrieve session data
	sessionKey := fmt.Sprintf("webauthn:login:%s:%s", userID.String(), challenge)
	sessionDataBytes, err := s.store.GetSession(ctx, sessionKey)
	if err != nil {
		s.logger.Error("Failed to get session data",
			zap.String("user_id", userID.String()),
			zap.String("challenge", challenge),
			zap.Error(err),
		)
		return nil, fmt.Errorf("session not found or expired: %w", err)
	}

	// Unmarshal session data
	var sessionData webauthn.SessionData
	if err := json.Unmarshal(sessionDataBytes, &sessionData); err != nil {
		s.logger.Error("Failed to unmarshal session data",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("invalid session data: %w", err)
	}

	// Get user and credentials
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		s.logger.Error("User not found",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("user not found: %w", err)
	}

	credentials, err := s.store.ListCredentials(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get credentials",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	// Find the credential being used
	var usedCred *WebAuthnCredential
	webAuthnCredentials := make([]webauthn.Credential, len(credentials))
	for i, cred := range credentials {
		credentialID, err := base64.RawURLEncoding.DecodeString(cred.CredentialID)
		if err != nil {
			continue
		}

		var transports []protocol.AuthenticatorTransport
		for _, t := range cred.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}

		webAuthnCredentials[i] = webauthn.Credential{
			ID:              credentialID,
			PublicKey:       cred.PublicKey,
			AttestationType: cred.AttestationType,
			Authenticator: webauthn.Authenticator{
				AAGUID:       cred.AAGUID,
				SignCount:    cred.SignCount,
				CloneWarning: false,
			},
			Transport: transports,
		}

		// Check if this is the credential being used
		responseID := base64.RawURLEncoding.EncodeToString(response.Response.AuthenticatorData.AttData.CredentialID)
		if responseID == cred.CredentialID {
			usedCred = cred
		}
	}

	if usedCred == nil {
		s.logger.Error("Credential not found",
			zap.String("user_id", userID.String()),
		)
		return nil, fmt.Errorf("credential not found")
	}

	// Finish login (verify assertion)
	credential, err := s.webAuthn.FinishLogin(
		&webAuthnUserData{
			id:          user.UserID[:],
			displayName: user.DisplayName,
			name:        user.Username,
			credentials: webAuthnCredentials,
		},
		sessionData,
		response,
	)
	if err != nil {
		s.logger.Error("Failed to finish login",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to verify assertion: %w", err)
	}

	// Check sign count for cloning
	// A cloned authenticator would have a sign count less than or equal to the stored value
	if credential.Authenticator.SignCount > 0 && credential.Authenticator.SignCount <= usedCred.SignCount {
		// Sign count didn't increase - possible cloned authenticator!
		s.logger.Warn("Potential cloned authenticator detected",
			zap.String("user_id", userID.String()),
			zap.String("credential_id", usedCred.CredentialID),
			zap.Uint32("stored_count", usedCred.SignCount),
			zap.Uint32("new_count", credential.Authenticator.SignCount),
		)
		return nil, fmt.Errorf("potential cloned authenticator detected")
	}

	// Update the credential with new sign count and last used time
	now := time.Now()
	usedCred.SignCount = credential.Authenticator.SignCount
	usedCred.LastUsedAt = &now

	if err := s.store.UpdateCredential(ctx, usedCred); err != nil {
		s.logger.Error("Failed to update credential",
			zap.String("user_id", userID.String()),
			zap.String("credential_id", usedCred.CredentialID),
			zap.Error(err),
		)
		// Don't fail authentication if we can't update the credential
	}

	// Clean up session data
	_ = s.store.DeleteSession(ctx, sessionKey)

	s.logger.Info("WebAuthn login completed",
		zap.String("user_id", userID.String()),
		zap.String("credential_id", usedCred.CredentialID),
		zap.Uint32("sign_count", credential.Authenticator.SignCount),
	)

	return usedCred, nil
}

// webAuthnUserData implements webauthn.User interface
type webAuthnUserData struct {
	id          []byte
	displayName string
	name        string
	credentials []webauthn.Credential
}

// WebAuthnID returns the user's WebAuthn ID
func (u *webAuthnUserData) WebAuthnID() []byte {
	return u.id
}

// WebAuthnName returns the user's username
func (u *webAuthnUserData) WebAuthnName() string {
	return u.name
}

// WebAuthnDisplayName returns the user's display name
func (u *webAuthnUserData) WebAuthnDisplayName() string {
	return u.displayName
}

// WebAuthnCredentials returns the user's credentials
func (u *webAuthnUserData) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

// WebAuthnIcon returns the user's icon (optional)
func (u *webAuthnUserData) WebAuthnIcon() string {
	return ""
}

// User represents a user for WebAuthn operations
type User struct {
	UserID      uuid.UUID `json:"user_id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
}

// ParseRPID extracts the RPID from a URL
func ParseRPID(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil {
		return "", fmt.Errorf("invalid origin: %w", err)
	}
	return u.Hostname(), nil
}

// AuthenticatorInfo provides information about an authenticator
type AuthenticatorInfo struct {
	AAGUID       string `json:"aaguid"`
	Name         string `json:"name,omitempty"`
	IsPasskey    bool   `json:"is_passkey"`
}

// GetAuthenticatorInfo returns information about an authenticator based on its AAGUID
func GetAuthenticatorInfo(aaguid []byte) AuthenticatorInfo {
	aaguidStr := formatAAGUID(aaguid)

	// Check if it's a passkey (AAGUID indicates passkey)
	// Passkeys from major platforms have specific AAGUIDs
	isPasskey := isPasskeyAAGUID(aaguid)

	return AuthenticatorInfo{
		AAGUID:    aaguidStr,
		Name:      getAuthenticatorName(aaguid),
		IsPasskey: isPasskey,
	}
}

// formatAAGUID formats an AAGUID as a string with dashes
func formatAAGUID(aaguid []byte) string {
	if len(aaguid) != 16 {
		return ""
	}
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		aaguid[0], aaguid[1], aaguid[2], aaguid[3],
		aaguid[4], aaguid[5],
		aaguid[6], aaguid[7],
		aaguid[8], aaguid[9],
		aaguid[10], aaguid[11], aaguid[12], aaguid[13], aaguid[14], aaguid[15])
}

// isPasskeyAAGUID checks if the AAGUID indicates a passkey
func isPasskeyAAGUID(aaguid []byte) bool {
	if len(aaguid) != 16 {
		return false
	}

	// Check for zero AAGUID (often used for passkeys)
	for _, b := range aaguid {
		if b != 0 {
			return false
		}
	}
	return true
}

// getAuthenticatorName returns a human-readable name for the authenticator
func getAuthenticatorName(aaguid []byte) string {
	if len(aaguid) != 16 {
		return "Unknown Authenticator"
	}

	// Zero AAGUID typically indicates a passkey
	allZero := true
	for _, b := range aaguid {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "Passkey"
	}

	return "Security Key"
}
