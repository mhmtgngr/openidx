// Package identity - Hardware Token (YubiKey OATH-HOTP) Support
package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
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

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
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
	encryptedSecret, err := s.encryptSecret(secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt token secret: %w", err)
	}

	// org_id is stamped here rather than derived from a user later, because an
	// inventory row exists before anyone holds it: `status = 'available'`,
	// assigned_to NULL. There is no user to derive from at any point until
	// somebody is issued the token, so the tenant has to come from whoever
	// registered it.
	id := uuid.New().String()
	query := `
		INSERT INTO hardware_tokens (
			id, org_id, serial_number, name, token_type, secret_key, counter,
			manufacturer, model, firmware_version, status, notes, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $8, $9, 'available', $10, NOW())
		RETURNING created_at
	`

	var createdAt time.Time
	err = s.db.Pool.QueryRow(ctx, query,
		id, org.ID, req.SerialNumber, req.Name, tokenType, encryptedSecret,
		req.Manufacturer, req.Model, req.FirmwareVersion, req.Notes,
	).Scan(&createdAt)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			// Since v145 the serial is unique per organization, so this now
			// means "you already registered it", never "somebody else did".
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
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// Before v145 this query had no tenant predicate at all: the two filters
	// are both optional, so the console's unfiltered inventory page listed
	// every hardware token in the install — serial, model and assignee —
	// to any tenant's administrator.
	query := `
		SELECT id, serial_number, name, token_type, manufacturer, model,
			firmware_version, status, assigned_to, assigned_at, assigned_by,
			last_used_at, use_count, created_at, notes
		FROM hardware_tokens
		WHERE org_id = $1
		  AND ($2 = '' OR status = $2)
		  AND ($3 = '' OR assigned_to::text = $3)
		ORDER BY created_at DESC
	`

	rows, err := s.db.Pool.Query(ctx, query, org.ID, status, assignedTo)
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
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, serial_number, name, token_type, manufacturer, model,
			firmware_version, status, assigned_to, assigned_at, assigned_by,
			last_used_at, use_count, created_at, notes
		FROM hardware_tokens
		WHERE id = $1 AND org_id = $2
	`

	var t HardwareToken
	err = s.db.Pool.QueryRow(ctx, query, tokenID, org.ID).Scan(
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
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// BOTH ends need checking, and before v145 neither was. The token id was
	// bare, so an administrator of one tenant could pick a token sitting
	// available in another tenant's inventory; the user id was bare too, so
	// they could equally bind their OWN token to a user in somebody else's
	// tenant. Either direction hands a working second factor across a tenant
	// boundary, which is why this is a check on the user and not only a
	// predicate on the update.
	var status string
	err = s.db.Pool.QueryRow(ctx,
		"SELECT status FROM hardware_tokens WHERE id = $1 AND org_id = $2", tokenID, org.ID).Scan(&status)
	if err != nil {
		return errors.New("token not found")
	}
	if status != "available" {
		return fmt.Errorf("token is not available (status: %s)", status)
	}

	var exists bool
	if err := s.db.Pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND org_id = $2)", userID, org.ID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return errors.New("user not found")
	}

	// Assign token
	query := `
		UPDATE hardware_tokens
		SET status = 'assigned', assigned_to = $1, assigned_at = NOW(), assigned_by = $2
		WHERE id = $3 AND org_id = $4
	`
	_, err = s.db.Pool.Exec(ctx, query, userID, assignedBy, tokenID, org.ID)
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
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	var userID *string
	err = s.db.Pool.QueryRow(ctx,
		"SELECT assigned_to FROM hardware_tokens WHERE id = $1 AND org_id = $2", tokenID, org.ID).Scan(&userID)
	if err != nil {
		return errors.New("token not found")
	}

	query := `
		UPDATE hardware_tokens
		SET status = 'available', assigned_to = NULL, assigned_at = NULL, assigned_by = NULL
		WHERE id = $1 AND org_id = $2
	`
	_, err = s.db.Pool.Exec(ctx, query, tokenID, org.ID)
	if err != nil {
		return err
	}

	// Log event
	s.logTokenEvent(ctx, tokenID, userID, "unassigned", "", "", map[string]interface{}{
		"unassigned_by": unassignedBy,
	})

	return nil
}

// ErrHardwareTokenNotFound is returned when an operation names a token that
// does not exist. It exists because an UPDATE that matches no row succeeds:
// revoking a token that is not there used to return nil and write a "revoked"
// event for it, so an administrator acting on a stale id — or a typo'd one —
// was told the credential was dead while it went on working.
var ErrHardwareTokenNotFound = errors.New("hardware token not found")

// RevokeHardwareToken marks token as revoked (cannot be used)
func (s *Service) RevokeHardwareToken(ctx context.Context, tokenID, revokedBy, reason string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	tag, err := s.db.Pool.Exec(ctx,
		`UPDATE hardware_tokens SET status = 'revoked' WHERE id = $1 AND org_id = $2`, tokenID, org.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrHardwareTokenNotFound
	}

	s.logTokenEvent(ctx, tokenID, nil, "revoked", "", "", map[string]interface{}{
		"revoked_by": revokedBy,
		"reason":     reason,
	})

	return nil
}

// ReportTokenLost marks token as lost
func (s *Service) ReportTokenLost(ctx context.Context, tokenID, reportedBy string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	tag, err := s.db.Pool.Exec(ctx,
		`UPDATE hardware_tokens SET status = 'lost' WHERE id = $1 AND org_id = $2`, tokenID, org.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrHardwareTokenNotFound
	}

	s.logTokenEvent(ctx, tokenID, nil, "lost_reported", "", "", map[string]interface{}{
		"reported_by": reportedBy,
	})

	return nil
}

// VerifyHardwareToken validates an OTP from a hardware token
func (s *Service) VerifyHardwareToken(ctx context.Context, userID, otp string, ipAddress, userAgent string) (bool, error) {
	// Verification runs with the RLS belt lifted, and the whole function shares
	// one bypassed context — including the counter advance and the event write
	// that follow.
	//
	// WHY BYPASS. This is a second-factor check on the sign-in path, reached
	// from the oauth service's step-up as well as from the identity API, and
	// those callers do not all carry a resolved organization yet. Under FORCE
	// RLS an unset app.org_id returns zero rows, which this function reports as
	// "no hardware token assigned to user" — a factor that silently stops
	// existing, on exactly the path where that is least noticeable. The same
	// shape already bit VerifyBypassCode once (see its comment about "conn
	// busy").
	//
	// WHY THAT IS SAFE. The tenant is not being trusted to the connection here;
	// it is in the predicate. `assigned_to = $1` is the authenticated user, and
	// the org term ties the row to that user's own organization, so a token
	// belonging to any other tenant cannot match even with the belt lifted.
	//orgscope:ignore second-factor verification on a path that may not have resolved an org; scoped by the user's own org_id below
	query := `
		SELECT id, token_type, secret_key, counter, locked_until
		FROM hardware_tokens
		WHERE assigned_to = $1 AND status = 'assigned'
		  AND org_id = (SELECT org_id FROM users WHERE id = $1)
	`

	ctx = orgctx.WithBypassRLS(ctx)

	var tokenID, tokenType, encryptedSecret string
	var counter int64
	var lockedUntil *time.Time
	err := s.db.Pool.QueryRow(ctx, query, userID).Scan(&tokenID, &tokenType, &encryptedSecret, &counter, &lockedUntil)
	if err != nil {
		return false, errors.New("no hardware token assigned to user")
	}

	// Refuse while locked, before the code is examined at all — the same order
	// VerifyTOTP uses, and for the same reason: a verifier that checks the code
	// first and only then notices the lock still leaks whether the guess was
	// right.
	if lockedUntil != nil && time.Now().Before(*lockedUntil) {
		s.logTokenEvent(ctx, tokenID, &userID, "failed", ipAddress, userAgent, map[string]interface{}{
			"reason": "locked_out",
		})
		return false, ErrHardwareTokenLockedOut
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
		// Advancing the counter is what makes an HOTP single-use, so this write
		// is part of the verification, not bookkeeping after it. Its error used
		// to be discarded: a failed UPDATE left the counter where it was and the
		// same code kept working, for as long as the write kept failing, with
		// nothing said. Refuse instead — a code that cannot be spent has not
		// been verified.
		if _, err := s.db.Pool.Exec(ctx,
			//orgscope:ignore token id already resolved under the caller's org predicate; ctx is the bypassed verification context
			`
			UPDATE hardware_tokens
			SET counter = $1, last_used_at = NOW(), use_count = use_count + 1,
			    failed_attempts = 0, last_failed_at = NULL, locked_until = NULL
			WHERE id = $2
		`, newCounter, tokenID); err != nil {
			s.logger.Error("Hardware token accepted but its counter could not be advanced; refusing",
				zap.String("token_id", tokenID), zap.Error(err))
			return false, fmt.Errorf("could not spend hardware token code: %w", err)
		}

		s.logTokenEvent(ctx, tokenID, &userID, "used", ipAddress, userAgent, nil)
		return true, nil
	}

	s.recordFailedHardwareToken(ctx, tokenID)
	s.logTokenEvent(ctx, tokenID, &userID, "failed", ipAddress, userAgent, map[string]interface{}{
		"reason": "invalid_otp",
	})

	return false, nil
}

// Hardware-token verification throttling.
//
// The same exposure mfa_totp's throttle closes, and a wider one: verifyHOTP
// walks a look-ahead of ten counters and verifyTOTP accepts a +/- 1 step
// window, so roughly eleven of a million six-digit values are live at any
// instant. Unthrottled, an attacker expects a hit in the tens of thousands of
// requests. The constants are mfa_totp's, deliberately — one answer to "how
// many tries do I get" across both factors is easier to reason about than two.
const (
	hardwareTokenMaxAttempts     = totpMaxAttempts
	hardwareTokenLockoutDuration = totpLockoutDuration
)

// ErrHardwareTokenLockedOut is returned when the token is locked after repeated
// failures, distinguishable from a wrong code so the caller can say "wait"
// rather than "try again" — and carrying nothing about the submitted code.
var ErrHardwareTokenLockedOut = errors.New("too many failed hardware token attempts; try again later")

// recordFailedHardwareToken counts a failed verification and locks the token at
// the threshold.
//
// The increment happens in the database, as recordFailedTOTP's does: reading
// the count into Go, adding one and writing it back loses increments under
// exactly the concurrency an attacker generates, so the cap binds later than it
// claims — or never. The error is logged and swallowed because the caller has
// already decided the code was wrong; failing the request instead would tell
// the attacker their guess was interesting.
// The id is the one VerifyHardwareToken just read under its org predicate, and
// its context is already bypassed, so no tenant term is repeated here.
func (s *Service) recordFailedHardwareToken(ctx context.Context, tokenID string) {
	//orgscope:ignore token id already resolved under the caller's org predicate; ctx is the bypassed verification context
	if _, err := s.db.Pool.Exec(ctx, `
		UPDATE hardware_tokens
		SET failed_attempts = failed_attempts + 1,
		    last_failed_at  = NOW(),
		    locked_until = CASE
		        WHEN failed_attempts + 1 >= $2 THEN NOW() + $3::interval
		        ELSE locked_until
		    END
		WHERE id = $1
	`, tokenID, hardwareTokenMaxAttempts, hardwareTokenLockoutDuration.String()); err != nil {
		s.logger.Error("Failed to record hardware token failure; throttling may not be enforced",
			zap.String("token_id", tokenID), zap.Error(err))
	}
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
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, serial_number, name, token_type, manufacturer, model,
			firmware_version, status, assigned_to, assigned_at, assigned_by,
			last_used_at, use_count, created_at, notes
		FROM hardware_tokens
		WHERE assigned_to = $1 AND status = 'assigned' AND org_id = $2
	`

	var t HardwareToken
	err = s.db.Pool.QueryRow(ctx, query, userID, org.ID).Scan(
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

	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	query := `
		SELECT id, token_id, user_id, event_type, ip_address, user_agent, details, created_at
		FROM hardware_token_events
		WHERE token_id = $1 AND org_id = $2
		ORDER BY created_at DESC
		LIMIT $3
	`

	rows, err := s.db.Pool.Query(ctx, query, tokenID, org.ID, limit)
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
	// The event takes its tenant from the token it is about, not from the
	// connection: this is called from the bypassed verification path as well as
	// from the org-scoped admin handlers, and the token is the one thing every
	// caller has. orgctx.AuditOrgID is the floor — a record of a hardware-token
	// event filed under the primary organization is recoverable; one refused by
	// the belt's WITH CHECK and dropped is not, and that is the failure mode
	// this whole programme has already met once.
	fallback, resolved := orgctx.AuditOrgID(ctx)
	query := `
		INSERT INTO hardware_token_events (id, org_id, token_id, user_id, event_type, ip_address, user_agent, details, created_at)
		VALUES ($1,
		        COALESCE((SELECT org_id FROM hardware_tokens WHERE id = $2),
		                 (SELECT org_id FROM users WHERE id = $3),
		                 $8::uuid),
		        $2, $3, $4, $5, $6, $7, NOW())
	`
	if _, err := s.db.Pool.Exec(orgctx.WithBypassRLS(ctx), query,
		uuid.New().String(), tokenID, userID, eventType, ipAddress, userAgent, details, fallback); err != nil {
		s.logger.Error("failed to write hardware token event",
			zap.String("event_type", eventType), zap.String("token_id", tokenID),
			zap.Bool("org_resolved", resolved), zap.Error(err))
	}
}

// encryptSecret encrypts a hardware-token secret (e.g. a TOTP/HOTP seed) for storage at rest using
// the service's AES-256-GCM cipher (secretcrypt). Returns an "encv1:"-prefixed ciphertext; with no
// KEK configured (dev) the Noop cipher passes the value through, matching the idpCipher behavior.
func (s *Service) encryptSecret(secret string) (string, error) {
	return s.idpCipher.Encrypt(secret)
}

// decryptSecret decrypts a hardware-token secret. It reads both the current AES-GCM format and the
// legacy "<64-hex sha256>:<secret>" format written before encryption was added (those rows upgrade to
// AES-GCM on the next write).
func (s *Service) decryptSecret(stored string) string {
	if secretcrypt.IsEncrypted(stored) {
		if v, err := s.idpCipher.Decrypt(stored); err == nil {
			return v
		}
		return ""
	}
	// Legacy: "<64-hex sha256>:<secret>" — the hash prefix was security-theater; return the secret.
	if i := strings.IndexByte(stored, ':'); i == 64 && isHex(stored[:i]) {
		return stored[i+1:]
	}
	return stored
}

// isHex reports whether s is all hex digits.
func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
