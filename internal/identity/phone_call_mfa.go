// Package identity - Phone Call Verification MFA
package identity

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// maxPhoneCallAttempts is how many guesses one spoken code is worth. The
// counter it is compared against is incremented and read in a single statement,
// so this is a ceiling on guesses actually made, not on guesses the process
// happened to observe.
const maxPhoneCallAttempts = 3

// PhoneCallEnrollment represents a phone call MFA enrollment
type PhoneCallEnrollment struct {
	ID            string     `json:"id"`
	UserID        string     `json:"user_id"`
	PhoneNumber   string     `json:"phone_number"`
	CountryCode   string     `json:"country_code"`
	Verified      bool       `json:"verified"`
	Enabled       bool       `json:"enabled"`
	VoiceLanguage string     `json:"voice_language"`
	CreatedAt     time.Time  `json:"created_at"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
}

// PhoneCallChallenge represents an active phone call verification
type PhoneCallChallenge struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	PhoneNumber string     `json:"phone_number"`
	CallType    string     `json:"call_type"` // outbound, callback
	CallSID     string     `json:"call_sid,omitempty"`
	Status      string     `json:"status"` // pending, calling, answered, completed, failed
	Attempts    int        `json:"attempts"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`
}

// PhoneCallProvider interface for voice call services
type PhoneCallProvider interface {
	InitiateCall(phoneNumber, code, language string) (callSID string, err error)
	GetCallStatus(callSID string) (status string, err error)
}

// EnrollPhoneCall starts phone call MFA enrollment
func (s *Service) EnrollPhoneCall(ctx context.Context, userID, phoneNumber, countryCode string) (*PhoneCallChallenge, error) {
	// Format phone number
	fullNumber := countryCode + phoneNumber

	// Check if already enrolled
	var existing string
	err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		"SELECT id FROM mfa_phone_call WHERE user_id = $1 AND org_id = (SELECT org_id FROM users WHERE id = $1)", userID,
	).Scan(&existing)
	if err == nil {
		// Update existing enrollment
		_, err = s.db.Pool.Exec(orgctx.WithBypassRLS(ctx),
			`UPDATE mfa_phone_call
			SET phone_number = $1, country_code = $2, verified = false
			WHERE user_id = $3 AND org_id = (SELECT org_id FROM users WHERE id = $3)`,
			phoneNumber, countryCode, userID,
		)
		if err != nil {
			return nil, err
		}
	} else {
		// Create new enrollment
		_, err = s.db.Pool.Exec(orgctx.WithBypassRLS(ctx),
			`INSERT INTO mfa_phone_call (id, org_id, user_id, phone_number, country_code, verified, enabled, voice_language, created_at)
			VALUES ($1, (SELECT org_id FROM users WHERE id = $2), $2, $3, $4, false, true, 'en-US', NOW())`,
			uuid.New().String(), userID, phoneNumber, countryCode,
		)
		if err != nil {
			return nil, err
		}
	}

	// Create verification challenge
	return s.CreatePhoneCallChallenge(ctx, userID, fullNumber, "outbound")
}

// ErrPhoneCallMFANotConfigured is returned when the phone-call factor is
// exercised on an installation with no call provider wired.
var ErrPhoneCallMFANotConfigured = fmt.Errorf("phone-call MFA is not configured on this installation")

// CreatePhoneCallChallenge creates a phone call challenge and initiates the call
func (s *Service) CreatePhoneCallChallenge(ctx context.Context, userID, phoneNumber, callType string) (*PhoneCallChallenge, error) {
	// Refuse up front when no call provider is wired (SetPhoneCallProvider).
	// This path used to store the challenge, skip the call, and report
	// success — the user waits for a call that never comes and the factor
	// can never verify. A control that displays must be true.
	if s.phoneCallProvider == nil {
		return nil, ErrPhoneCallMFANotConfigured
	}

	// Generate 6-digit code
	code, err := generateSecureCode(6)
	if err != nil {
		return nil, err
	}

	// Hash the code
	codeHash, err := bcrypt.GenerateFromPassword([]byte(code), bcryptCost)
	if err != nil {
		return nil, err
	}

	challengeID := uuid.New().String()
	expiresAt := time.Now().Add(5 * time.Minute)

	// Store challenge
	_, err = s.db.Pool.Exec(ctx,
		// org_id is derived from the challenge's own user: the column is nullable
		// on this table, so a challenge raised without one used to sit in nobody's
		// scope at all.
		`INSERT INTO phone_call_challenges
		(id, org_id, user_id, phone_number, code_hash, call_type, status, attempts, created_at, expires_at)
		VALUES ($1, (SELECT org_id FROM users WHERE id = $2), $2, $3, $4, $5, 'pending', 0, NOW(), $6)`,
		challengeID, userID, phoneNumber, string(codeHash), callType, expiresAt,
	)
	if err != nil {
		return nil, err
	}

	// Initiate the call. The provider was verified non-nil above, so a
	// stored challenge always corresponds to a call that was attempted.
	callSID, err := s.phoneCallProvider.InitiateCall(phoneNumber, code, "en-US")
	if err != nil {
		// Update status to failed
		//silentwrite:ok the caller is given the error below either way; a challenge left 'pending'
		// here holds a code that was never spoken to anybody and expires on its own in five minutes.
		s.db.Pool.Exec(ctx,
			`UPDATE phone_call_challenges SET status = 'failed'
			  WHERE id = $1 AND org_id = (SELECT org_id FROM users WHERE id = $2)`,
			challengeID, userID,
		)
		return nil, fmt.Errorf("failed to initiate call: %w", err)
	}

	// Update with call SID
	//silentwrite:ok call_sid is written and read nowhere in the product -- it is a provider-side
	// correlation id for support -- and 'pending' verifies exactly as 'calling' does below.
	s.db.Pool.Exec(ctx,
		`UPDATE phone_call_challenges SET call_sid = $1, status = 'calling'
		  WHERE id = $2 AND org_id = (SELECT org_id FROM users WHERE id = $3)`,
		callSID, challengeID, userID,
	)

	return &PhoneCallChallenge{
		ID:          challengeID,
		UserID:      userID,
		PhoneNumber: maskPhoneNumber(phoneNumber),
		CallType:    callType,
		CallSID:     callSID,
		Status:      "calling",
		Attempts:    0,
		CreatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
	}, nil
}

// VerifyPhoneCallChallenge verifies the code from a phone call
func (s *Service) VerifyPhoneCallChallenge(ctx context.Context, userID, code string) error {
	// Get active challenge
	var challengeID, codeHash string
	var expiresAt time.Time

	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, code_hash, expires_at FROM phone_call_challenges
		WHERE user_id = $1 AND org_id = (SELECT org_id FROM users WHERE id = $1)
		  AND status IN ('pending', 'calling', 'answered')
		ORDER BY created_at DESC LIMIT 1`,
		userID,
	).Scan(&challengeID, &codeHash, &expiresAt)
	if err != nil {
		return errors.New("no active phone call challenge found")
	}

	// Check expiration
	if time.Now().After(expiresAt) {
		//silentwrite:ok the refusal is the return below, decided from expires_at on every attempt;
		// the row only records what the timestamp already says and never widens what is accepted.
		s.db.Pool.Exec(ctx, `UPDATE phone_call_challenges SET status = 'expired'
			WHERE id = $1 AND org_id = (SELECT org_id FROM users WHERE id = $2)`, challengeID, userID)
		return errors.New("challenge expired")
	}

	// Count the attempt, and read the count back from the same statement.
	//
	// THIS IS the brute-force limit on a six-digit code. It was a read of
	// `attempts`, a comparison, and a separate increment whose error was
	// discarded -- so an increment that failed left the counter where it was
	// and the cap never arrived, and two verifications racing each other both
	// read the same count before either wrote. One conditional UPDATE closes
	// both: the row is locked for the increment, and the value returned is the
	// number of attempts including this one. A guess that cannot be counted is
	// not allowed to be a free one.
	var attempts int
	if err := s.db.Pool.QueryRow(ctx,
		`UPDATE phone_call_challenges SET attempts = attempts + 1
		  WHERE id = $1 AND org_id = (SELECT org_id FROM users WHERE id = $2)
		  RETURNING attempts`,
		challengeID, userID,
	).Scan(&attempts); err != nil {
		s.logger.Error("could not count a phone-call verification attempt; refusing it",
			zap.Error(err))
		return errors.New("could not record the verification attempt")
	}

	// Check max attempts
	if attempts > maxPhoneCallAttempts {
		//silentwrite:ok the cap is enforced from the attempts column above, which keeps climbing on
		// every further guess, so this status is a label on a challenge already refused for good.
		s.db.Pool.Exec(ctx, `UPDATE phone_call_challenges SET status = 'failed'
			WHERE id = $1 AND org_id = (SELECT org_id FROM users WHERE id = $2)`, challengeID, userID)
		return errors.New("maximum attempts exceeded")
	}

	// Verify code
	if err := bcrypt.CompareHashAndPassword([]byte(codeHash), []byte(code)); err != nil {
		return errors.New("invalid verification code")
	}

	// Spend the challenge and verify the enrolment together.
	//
	// The first write is what stops the same challenge being presented twice
	// with the same code. The second is what makes the factor usable at all --
	// InitiatePhoneCall reads `verified = true` to find a number to ring. Both
	// discarded their errors, so a failure on the first left the code live for
	// the rest of its window, and a failure on the second told the person their
	// phone was verified and left them a factor that would never work again.
	//
	// One transaction: either the challenge is spent and the enrolment is
	// usable, or neither happened and the same challenge can be tried again.
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("verify phone-call challenge: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once committed

	tag, err := tx.Exec(ctx,
		`UPDATE phone_call_challenges SET status = 'completed', verified_at = NOW()
		  WHERE id = $1 AND org_id = (SELECT org_id FROM users WHERE id = $2)
		    AND status IN ('pending', 'calling', 'answered')`,
		challengeID, userID,
	)
	if err != nil {
		s.logger.Error("could not spend a phone-call challenge; refusing the verification", zap.Error(err))
		return fmt.Errorf("mark phone-call challenge completed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Another verification spent it between the increment and here.
		return errors.New("no active phone call challenge found")
	}

	// Mark enrollment as verified
	if _, err := tx.Exec(orgctx.WithBypassRLS(ctx),
		"UPDATE mfa_phone_call SET verified = true, last_used_at = NOW() WHERE user_id = $1 AND org_id = (SELECT org_id FROM users WHERE id = $1)",
		userID,
	); err != nil {
		s.logger.Error("could not mark the phone-call enrolment verified; refusing the verification",
			zap.Error(err))
		return fmt.Errorf("mark phone-call enrolment verified: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("verify phone-call challenge: %w", err)
	}
	return nil
}

// GetPhoneCallEnrollment returns the phone call enrollment for a user
func (s *Service) GetPhoneCallEnrollment(ctx context.Context, userID string) (*PhoneCallEnrollment, error) {
	query := `
		SELECT id, user_id, phone_number, country_code, verified, enabled, voice_language, created_at, last_used_at
		FROM mfa_phone_call
		WHERE user_id = $1 AND org_id = (SELECT org_id FROM users WHERE id = $1)
	`

	var e PhoneCallEnrollment
	err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx), query, userID).Scan(
		&e.ID, &e.UserID, &e.PhoneNumber, &e.CountryCode, &e.Verified, &e.Enabled,
		&e.VoiceLanguage, &e.CreatedAt, &e.LastUsedAt,
	)
	if err != nil {
		return nil, err
	}

	// Mask phone number
	e.PhoneNumber = maskPhoneNumber(e.CountryCode + e.PhoneNumber)

	return &e, nil
}

// DeletePhoneCallEnrollment removes phone call MFA
func (s *Service) DeletePhoneCallEnrollment(ctx context.Context, userID string) error {
	_, err := s.db.Pool.Exec(orgctx.WithBypassRLS(ctx),
		"DELETE FROM mfa_phone_call WHERE user_id = $1 AND org_id = (SELECT org_id FROM users WHERE id = $1)", userID)
	return err
}

// RequestCallback initiates a callback verification (user calls system)
func (s *Service) RequestCallback(ctx context.Context, userID string) (*PhoneCallChallenge, error) {
	// Get user's enrolled phone
	var phoneNumber, countryCode string
	err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		"SELECT phone_number, country_code FROM mfa_phone_call WHERE user_id = $1 AND verified = true AND org_id = (SELECT org_id FROM users WHERE id = $1)",
		userID,
	).Scan(&phoneNumber, &countryCode)
	if err != nil {
		return nil, errors.New("no verified phone number found")
	}

	return s.CreatePhoneCallChallenge(ctx, userID, countryCode+phoneNumber, "callback")
}

// generateSecureCode generates a cryptographically secure numeric code
func generateSecureCode(length int) (string, error) {
	const digits = "0123456789"
	code := make([]byte, length)

	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		code[i] = digits[n.Int64()]
	}

	return string(code), nil
}

// maskPhoneNumber masks a phone number for display
func maskPhoneNumber(phone string) string {
	if len(phone) < 4 {
		return "****"
	}
	return phone[:len(phone)-4] + "****"
}

// TwilioPhoneCallProvider implements PhoneCallProvider for Twilio
type TwilioPhoneCallProvider struct {
	AccountSID string
	AuthToken  string
	FromNumber string
}

// InitiateCall makes a phone call via Twilio.
//
// NOT IMPLEMENTED: the Twilio API integration was never written (the TwiML
// draft lived in a comment here). It used to return a fabricated call SID
// and GetCallStatus always said "completed", so anyone wiring this provider
// would ship a factor that looks healthy and never rings a phone. It now
// fails loudly until a real integration exists.
func (t *TwilioPhoneCallProvider) InitiateCall(phoneNumber, code, language string) (string, error) {
	return "", fmt.Errorf("TwilioPhoneCallProvider is not implemented: no call is placed; wire a real PhoneCallProvider")
}

// GetCallStatus gets the status of a Twilio call.
func (t *TwilioPhoneCallProvider) GetCallStatus(callSID string) (string, error) {
	return "", fmt.Errorf("TwilioPhoneCallProvider is not implemented")
}
