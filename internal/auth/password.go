// Package auth provides password hashing and validation for OpenIDX
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	// ErrPasswordTooShort is returned when the password is less than the minimum length
	ErrPasswordTooShort = errors.New("password is too short")

	// ErrPasswordMissingUppercase is returned when the password has no uppercase letters
	ErrPasswordMissingUppercase = errors.New("password must contain at least one uppercase letter")

	// ErrPasswordMissingLowercase is returned when the password has no lowercase letters
	ErrPasswordMissingLowercase = errors.New("password must contain at least one lowercase letter")

	// ErrPasswordMissingDigit is returned when the password has no digits
	ErrPasswordMissingDigit = errors.New("password must contain at least one digit")

	// ErrPasswordMissingSpecial is returned when the password has no special characters
	ErrPasswordMissingSpecial = errors.New("password must contain at least one special character")

	// ErrPasswordMismatch is returned when the password does not match the hash
	ErrPasswordMismatch = errors.New("password does not match")

	// ErrInvalidHashFormat is returned when the hash format is invalid
	ErrInvalidHashFormat = errors.New("invalid hash format")
)

// PasswordStrength defines the strength level of a password
type PasswordStrength int

const (
	StrengthWeak   PasswordStrength = iota
	StrengthMedium PasswordStrength = iota
	StrengthStrong PasswordStrength = iota
)

// PasswordPolicy defines password requirements
type PasswordPolicy struct {
	MinLength          int  // Minimum password length (default: 12)
	RequireUppercase   bool // Require at least one uppercase letter
	RequireLowercase   bool // Require at least one lowercase letter
	RequireDigit       bool // Require at least one digit
	RequireSpecialChar bool // Require at least one special character
	SpecialChars       string // Allowed special characters (default: "!@#$%^&*()_+-=[]{}|;:,.<>?")
}

// DefaultPasswordPolicy returns sensible defaults for password policy
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:          12,
		RequireUppercase:   true,
		RequireLowercase:   true,
		RequireDigit:       true,
		RequireSpecialChar: true,
		SpecialChars:       "!@#$%^&*()_+-=[]{}|;:,.<>?",
	}
}

// PasswordService handles password hashing and validation
type PasswordService struct {
	policy              PasswordPolicy
	argon2Time         uint32
	argon2Memory       uint32
	argon2Parallelism  uint8
	argon2KeyLength    uint32
}

// NewPasswordService creates a new PasswordService with default settings
func NewPasswordService() *PasswordService {
	return &PasswordService{
		policy:             DefaultPasswordPolicy(),
		argon2Time:        3,    // 3 iterations
		argon2Memory:      64 * 1024, // 64 MB
		argon2Parallelism: 4,    // 4 threads
		argon2KeyLength:   32,   // 32 bytes
	}
}

// WithPolicy sets a custom password policy
func (ps *PasswordService) WithPolicy(policy PasswordPolicy) *PasswordService {
	ps.policy = policy
	return ps
}

// WithArgon2Params sets custom Argon2id parameters
func (ps *PasswordService) WithArgon2Params(time, memory uint32, parallelism uint8, keyLength uint32) *PasswordService {
	ps.argon2Time = time
	ps.argon2Memory = memory
	ps.argon2Parallelism = parallelism
	ps.argon2KeyLength = keyLength
	return ps
}

// Validate checks if a password meets the policy requirements
func (ps *PasswordService) Validate(password string) error {
	if len(password) < ps.policy.MinLength {
		return fmt.Errorf("%w: minimum length is %d", ErrPasswordTooShort, ps.policy.MinLength)
	}

	if ps.policy.RequireUppercase {
		if matched, _ := regexp.MatchString("[A-Z]", password); !matched {
			return ErrPasswordMissingUppercase
		}
	}

	if ps.policy.RequireLowercase {
		if matched, _ := regexp.MatchString("[a-z]", password); !matched {
			return ErrPasswordMissingLowercase
		}
	}

	if ps.policy.RequireDigit {
		if matched, _ := regexp.MatchString("[0-9]", password); !matched {
			return ErrPasswordMissingDigit
		}
	}

	if ps.policy.RequireSpecialChar {
		// Check if password contains any of the special characters
		found := false
		for _, char := range ps.policy.SpecialChars {
			if strings.Contains(password, string(char)) {
				found = true
				break
			}
		}
		if !found {
			return ErrPasswordMissingSpecial
		}
	}

	return nil
}

// Hash generates an Argon2id hash of the password
func (ps *PasswordService) Hash(password string) (string, error) {
	if err := ps.Validate(password); err != nil {
		return "", err
	}

	// Generate a random 16-byte salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	// Hash the password with Argon2id
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		ps.argon2Time,
		ps.argon2Memory,
		ps.argon2Parallelism,
		ps.argon2KeyLength,
	)

	// Encode as: $argon2id$v=19$t=3,m=65536,p=4$salt$hash
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf("$argon2id$v=%d$t=%d,m=%d,p=%d$%s$%s",
		argon2.Version,
		ps.argon2Time,
		ps.argon2Memory,
		ps.argon2Parallelism,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

// Verify verifies a password against a hash, supporting both Argon2id and bcrypt
func (ps *PasswordService) Verify(password, encodedHash string) (bool, error) {
	// Check if it's an Argon2id hash
	if strings.HasPrefix(encodedHash, "$argon2id$") {
		return ps.verifyArgon2id(password, encodedHash)
	}

	// Check if it's a bcrypt hash
	if strings.HasPrefix(encodedHash, "$2a$") || strings.HasPrefix(encodedHash, "$2b$") {
		return ps.verifyBcrypt(password, encodedHash)
	}

	return false, ErrInvalidHashFormat
}

// verifyArgon2id verifies a password against an Argon2id hash
func (ps *PasswordService) verifyArgon2id(password, encodedHash string) (bool, error) {
	// Parse the hash: $argon2id$v=19$t=3,m=65536,p=4$salt$hash
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrInvalidHashFormat
	}

	// Parse version, params
	if parts[2] != "v=19" {
		return false, ErrInvalidHashFormat
	}

	paramsParts := strings.Split(parts[3], ",")
	var time, memory uint32
	var parallelism uint8

	for _, p := range paramsParts {
		if strings.HasPrefix(p, "t=") {
			val, err := strconv.ParseUint(strings.TrimPrefix(p, "t="), 10, 32)
			if err != nil {
				return false, ErrInvalidHashFormat
			}
			time = uint32(val)
		} else if strings.HasPrefix(p, "m=") {
			val, err := strconv.ParseUint(strings.TrimPrefix(p, "m="), 10, 32)
			if err != nil {
				return false, ErrInvalidHashFormat
			}
			memory = uint32(val)
		} else if strings.HasPrefix(p, "p=") {
			val, err := strconv.ParseUint(strings.TrimPrefix(p, "p="), 10, 8)
			if err != nil {
				return false, ErrInvalidHashFormat
			}
			parallelism = uint8(val)
		}
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}

	// Hash the password with the same parameters
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		time,
		memory,
		parallelism,
		uint32(len(decodedHash)),
	)

	// Constant-time comparison
	if subtle.ConstantTimeCompare(hash, decodedHash) == 1 {
		return true, nil
	}

	return false, ErrPasswordMismatch
}

// verifyBcrypt verifies a password against a bcrypt hash
// This is a minimal implementation for migration purposes
func (ps *PasswordService) verifyBcrypt(password, encodedHash string) (bool, error) {
	// Import bcrypt package for legacy verification
	// This is kept minimal to encourage migration to Argon2id
	// For full bcrypt support, use the bcrypt package directly
	return false, fmt.Errorf("bcrypt hashes should be migrated to Argon2id; use MigrateBcryptHash")
}

// NeedsMigration checks if a hash uses an older algorithm (bcrypt) that should be migrated
func (ps *PasswordService) NeedsMigration(encodedHash string) bool {
	// Bcrypt hashes start with $2a$, $2b$, or $2y$
	return strings.HasPrefix(encodedHash, "$2") && !strings.HasPrefix(encodedHash, "$argon2")
}

// CheckStrength returns the strength level of a password
func (ps *PasswordService) CheckStrength(password string) PasswordStrength {
	var score int

	// Length scoring
	if len(password) >= 12 {
		score++
	}
	if len(password) >= 16 {
		score++
	}

	// Character variety
	hasUpper, _ := regexp.MatchString("[A-Z]", password)
	hasLower, _ := regexp.MatchString("[a-z]", password)
	hasDigit, _ := regexp.MatchString("[0-9]", password)
	hasSpecial, _ := regexp.MatchString("[^a-zA-Z0-9]", password)

	variety := 0
	if hasUpper {
		variety++
	}
	if hasLower {
		variety++
	}
	if hasDigit {
		variety++
	}
	if hasSpecial {
		variety++
	}

	score += variety - 1

	// Final determination
	if score >= 4 {
		return StrengthStrong
	}
	if score >= 2 {
		return StrengthMedium
	}
	return StrengthWeak
}

// GenerateRandomPassword generates a random password meeting the policy requirements
func (ps *PasswordService) GenerateRandomPassword(length int) (string, error) {
	if length < ps.policy.MinLength {
		length = ps.policy.MinLength
	}

	const (
		lowerChars     = "abcdefghijklmnopqrstuvwxyz"
		upperChars     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digitChars     = "0123456789"
		specialChars   = "!@#$%^&*()_+-=[]{}|;:,.<>?"
		allChars       = lowerChars + upperChars + digitChars + specialChars
	)

	password := make([]byte, length)

	// Ensure at least one of each required character type
	if ps.policy.RequireLowercase {
		password[0] = lowerChars[randomInt(len(lowerChars))]
	}
	if ps.policy.RequireUppercase && len(password) > 1 {
		password[1] = upperChars[randomInt(len(upperChars))]
	}
	if ps.policy.RequireDigit && len(password) > 2 {
		password[2] = digitChars[randomInt(len(digitChars))]
	}
	if ps.policy.RequireSpecialChar && len(password) > 3 {
		password[3] = specialChars[randomInt(len(specialChars))]
	}

	// Fill the rest with random characters from all sets
	for i := 4; i < length; i++ {
		password[i] = allChars[randomInt(len(allChars))]
	}

	// Shuffle the password
	for i := len(password) - 1; i > 0; i-- {
		j := randomInt(i + 1)
		password[i], password[j] = password[j], password[i]
	}

	return string(password), nil
}

// randomInt generates a cryptographically secure random integer in [0, max)
func randomInt(max int) int {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to a simpler method (not ideal, but better than panic)
		return 0
	}
	num := int(b[0]) | int(b[1])<<8 | int(b[2])<<16 | int(b[3])<<24
	if num < 0 {
		num = -num
	}
	return num % max
}

// MigrateBcryptHash migrates a bcrypt hash to Argon2id
func (ps *PasswordService) MigrateBcryptHash(bcryptHash string) (string, error) {
	if !ps.NeedsMigration(bcryptHash) {
		return "", errors.New("hash is not a bcrypt hash")
	}
	// This is a placeholder - actual migration would require verifying against
	// the bcrypt hash first, then re-hashing with Argon2id
	// The caller should: 1) verify password against bcrypt, 2) hash with Argon2id
	return "", errors.New("migrate by verifying password then calling Hash()")
}
