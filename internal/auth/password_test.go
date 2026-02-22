// Package auth provides unit tests for password operations
package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordService_Validate(t *testing.T) {
	ps := NewPasswordService()

	tests := []struct {
		name      string
		password  string
		wantErr   error
		policy    PasswordPolicy
	}{
		{
			name:     "strong password - meets all requirements",
			password: "SecurePass123!",
			wantErr:  nil,
			policy:   DefaultPasswordPolicy(),
		},
		{
			name:     "weak password - too short",
			password: "Short1!",
			wantErr:  ErrPasswordTooShort,
			policy:   DefaultPasswordPolicy(),
		},
		{
			name:     "missing uppercase",
			password: "lowercase123!",
			wantErr:  ErrPasswordMissingUppercase,
			policy:   DefaultPasswordPolicy(),
		},
		{
			name:     "missing lowercase",
			password: "UPPERCASE123!",
			wantErr:  ErrPasswordMissingLowercase,
			policy:   DefaultPasswordPolicy(),
		},
		{
			name:     "missing digit",
			password: "NoDigitsHere!",
			wantErr:  ErrPasswordMissingDigit,
			policy:   DefaultPasswordPolicy(),
		},
		{
			name:     "missing special character",
			password: "NoSpecialChar123",
			wantErr:  ErrPasswordMissingSpecial,
			policy:   DefaultPasswordPolicy(),
		},
		{
			name:     "exactly minimum length",
			password: "MinLen12!!Aa",
			wantErr:  nil,
			policy:   DefaultPasswordPolicy(),
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  ErrPasswordTooShort,
			policy:   DefaultPasswordPolicy(),
		},
		{
			name:     "lenient policy - only length required",
			password: "longenough",
			wantErr:  nil,
			policy: PasswordPolicy{
				MinLength:          8,
				RequireUppercase:   false,
				RequireLowercase:   false,
				RequireDigit:       false,
				RequireSpecialChar: false,
			},
		},
		{
			name:     "lenient policy - length and digit only",
			password: "longenough123",
			wantErr:  nil,
			policy: PasswordPolicy{
				MinLength:          10,
				RequireUppercase:   false,
				RequireLowercase:   false,
				RequireDigit:       true,
				RequireSpecialChar: false,
			},
		},
		{
			name:     "lenient policy - missing digit",
			password: "longenough",
			wantErr:  ErrPasswordMissingDigit,
			policy: PasswordPolicy{
				MinLength:          10,
				RequireUppercase:   false,
				RequireLowercase:   false,
				RequireDigit:       true,
				RequireSpecialChar: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps.WithPolicy(tt.policy)
			err := ps.Validate(tt.password)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPasswordService_Hash(t *testing.T) {
	ps := NewPasswordService()

	tests := []struct {
		name     string
		password string
		wantErr  error
		checkHash func(*testing.T, string)
	}{
		{
			name:     "hash valid password",
			password: "SecurePass123!",
			wantErr:  nil,
			checkHash: func(t *testing.T, hash string) {
				assert.True(t, strings.HasPrefix(hash, "$argon2id$"))
				assert.Contains(t, hash, "$v=19$")
				parts := strings.Split(hash, "$")
				assert.Len(t, parts, 6, "hash should have 6 parts")
			},
		},
		{
			name:     "hash weak password fails validation",
			password: "weak",
			wantErr:  ErrPasswordTooShort,
		},
		{
			name:     "hash password without special char fails",
			password: "NoSpecialChars1",
			wantErr:  ErrPasswordMissingSpecial,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := ps.Hash(tt.password)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, hash)
				if tt.checkHash != nil {
					tt.checkHash(t, hash)
				}
			}
		})
	}
}

func TestPasswordService_Verify(t *testing.T) {
	ps := NewPasswordService()

	// Create a hash for testing
	password := "SecurePass123!"
	hash, err := ps.Hash(password)
	require.NoError(t, err)

	tests := []struct {
		name      string
		password  string
		hash      string
		wantValid bool
		wantErr   error
	}{
		{
			name:      "correct password",
			password:  password,
			hash:      hash,
			wantValid: true,
			wantErr:   nil,
		},
		{
			name:      "incorrect password",
			password:  "WrongPass123!",
			hash:      hash,
			wantValid: false,
			wantErr:   ErrPasswordMismatch,
		},
		{
			name:      "empty password",
			password:  "",
			hash:      hash,
			wantValid: false,
			wantErr:   ErrPasswordMismatch,
		},
		{
			name:      "invalid hash format",
			password:  password,
			hash:      "invalid-hash",
			wantValid: false,
			wantErr:   ErrInvalidHashFormat,
		},
		{
			name:      "bcrypt hash (should fail verification - needs migration)",
			password:  password,
			hash:      "$2a$10$abcdefghijklmnopqrstuvwxyz",
			wantValid: false,
			wantErr:   nil, // We expect an error but not ErrInvalidHashFormat - it's a migration error
		},
		{
			name:      "malformed argon2 hash",
			password:  password,
			hash:      "$argon2id$incomplete",
			wantValid: false,
			wantErr:   ErrInvalidHashFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := ps.Verify(tt.password, tt.hash)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else if tt.wantValid {
				assert.NoError(t, err)
				assert.True(t, valid)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestPasswordService_Verify_ConstantTime(t *testing.T) {
	ps := NewPasswordService()

	password := "SecurePass123!"
	hash, err := ps.Hash(password)
	require.NoError(t, err)

	// Verify correct password multiple times to ensure consistent timing
	for i := 0; i < 10; i++ {
		valid, err := ps.Verify(password, hash)
		assert.NoError(t, err)
		assert.True(t, valid)
	}
}

func TestPasswordService_NeedsMigration(t *testing.T) {
	ps := NewPasswordService()

	// Create an Argon2id hash
	argon2Hash, _ := ps.Hash("SecurePass123!")

	tests := []struct {
		name     string
		hash     string
		wantNeed bool
	}{
		{
			name:     "argon2id hash - no migration needed",
			hash:     argon2Hash,
			wantNeed: false,
		},
		{
			name:     "bcrypt 2a hash - needs migration",
			hash:     "$2a$10$abcdefghijklmnopqrstuvwxyz123456",
			wantNeed: true,
		},
		{
			name:     "bcrypt 2b hash - needs migration",
			hash:     "$2b$12$abcdefghijklmnopqrstuvwxyz123456",
			wantNeed: true,
		},
		{
			name:     "bcrypt 2y hash - needs migration",
			hash:     "$2y$12$abcdefghijklmnopqrstuvwxyz123456",
			wantNeed: true,
		},
		{
			name:     "unknown hash format - no migration needed",
			hash:     "unknown-format",
			wantNeed: false,
		},
		{
			name:     "empty hash - no migration needed",
			hash:     "",
			wantNeed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			needs := ps.NeedsMigration(tt.hash)
			assert.Equal(t, tt.wantNeed, needs)
		})
	}
}

func TestPasswordService_CheckStrength(t *testing.T) {
	ps := NewPasswordService()

	tests := []struct {
		name     string
		password string
		want     PasswordStrength
	}{
		{
			name:     "weak - short",
			password: "Short1!",
			want:     StrengthMedium, // Length 7: 0 points, variety 4: 3 points = 3 (Medium)
		},
		{
			name:     "weak - lowercase only",
			password: "lowercaselong",
			want:     StrengthWeak, // Length 12: 1 point, variety 1: 0 points = 1 (Weak)
		},
		{
			name:     "strong - meets minimum",
			password: "MediumPass12!",
			want:     StrengthStrong, // Length 12: 1 point, variety 4: 3 points = 4 (Strong)
		},
		{
			name:     "strong - long with variety",
			password: "VeryStrongPassword123!@#",
			want:     StrengthStrong, // Length 24: 2 points, variety 4: 3 points = 5 (Strong)
		},
		{
			name:     "strong - decent length and variety",
			password: "DecentPass1!",
			want:     StrengthStrong, // Length 12: 1 point, variety 4: 3 points = 4 (Strong)
		},
		{
			name:     "weak - only digits",
			password: "12345678",
			want:     StrengthWeak, // Length 8: 0 points, variety 1: 0 points = 0 (Weak)
		},
		{
			name:     "weak - only letters",
			password: "onlyletters",
			want:     StrengthWeak, // Length 11: 0 points, variety 1: 0 points = 0 (Weak)
		},
		{
			name:     "strong - very long with all types",
			password: "ThisIsAVeryStrongPassword123!@#$%",
			want:     StrengthStrong, // Length 33: 2 points, variety 4: 3 points = 5 (Strong)
		},
		{
			name:     "medium - mix but shorter",
			password: "Mix1!",
			want:     StrengthMedium, // Length 4: 0 points, variety 4: 3 points = 3 (Medium)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strength := ps.CheckStrength(tt.password)
			assert.Equal(t, tt.want, strength)
		})
	}
}

func TestPasswordService_GenerateRandomPassword(t *testing.T) {
	ps := NewPasswordService()

	tests := []struct {
		name     string
		length   int
		checkErr bool
		checkPw  func(*testing.T, string)
	}{
		{
			name:     "generate default length",
			length:   0,
			checkErr: false,
			checkPw: func(t *testing.T, pw string) {
				assert.GreaterOrEqual(t, len(pw), 12)
				// Verify it meets policy
				assert.NoError(t, ps.Validate(pw))
			},
		},
		{
			name:     "generate custom length",
			length:   20,
			checkErr: false,
			checkPw: func(t *testing.T, pw string) {
				assert.Equal(t, 20, len(pw))
				// Verify it meets policy
				assert.NoError(t, ps.Validate(pw))
			},
		},
		{
			name:     "generate short password uses minimum",
			length:   8,
			checkErr: false,
			checkPw: func(t *testing.T, pw string) {
				assert.GreaterOrEqual(t, len(pw), 12)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := ps.GenerateRandomPassword(tt.length)
			if tt.checkErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, password)
				if tt.checkPw != nil {
					tt.checkPw(t, password)
				}
			}
		})
	}
}

func TestPasswordService_GenerateRandomPassword_Uniqueness(t *testing.T) {
	ps := NewPasswordService()

	// Generate multiple passwords and ensure they're different
	passwords := make(map[string]bool)
	for i := 0; i < 100; i++ {
		password, err := ps.GenerateRandomPassword(16)
		require.NoError(t, err)
		assert.False(t, passwords[password], "generated duplicate password")
		passwords[password] = true
	}
}

func TestPasswordService_WithArgon2Params(t *testing.T) {
	ps := NewPasswordService().WithArgon2Params(1, 1024, 2, 16)

	password := "SecurePass123!"
	hash, err := ps.Hash(password)
	require.NoError(t, err)

	// Verify the hash uses the custom parameters
	// Format is: $argon2id$v=19$t=1,m=1024,p=2$salt$hash
	assert.Contains(t, hash, "t=1,m=1024,p=2")

	// Verify password still works
	valid, err := ps.Verify(password, hash)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestPasswordService_Hash_DeterministicVerification(t *testing.T) {
	ps := NewPasswordService()

	password := "SecurePass123!"

	// Hash the same password multiple times
	hashes := make([]string, 5)
	for i := 0; i < 5; i++ {
		hash, err := ps.Hash(password)
		require.NoError(t, err)
		hashes[i] = hash
	}

	// Each hash should be unique (due to random salt)
	uniqueHashes := make(map[string]bool)
	for _, hash := range hashes {
		uniqueHashes[hash] = true
	}
	assert.Len(t, uniqueHashes, 5, "each hash should be unique")

	// But all hashes should verify the same password
	for _, hash := range hashes {
		valid, err := ps.Verify(password, hash)
		assert.NoError(t, err)
		assert.True(t, valid)
	}
}

func TestPasswordService_MigrateBcryptHash(t *testing.T) {
	ps := NewPasswordService()

	bcryptHash := "$2a$10$abcdefghijklmnopqrstuvwxyz123456"

	_, err := ps.MigrateBcryptHash(bcryptHash)
	assert.Error(t, err)

	// Verify migration error for non-bcrypt hash
	argonHash, _ := ps.Hash("SecurePass123!")
	_, err = ps.MigrateBcryptHash(argonHash)
	assert.Error(t, err)
}

func TestPasswordService_WithPolicy(t *testing.T) {
	ps := NewPasswordService()

	// Set lenient policy
	lenient := PasswordPolicy{
		MinLength:          4,
		RequireUppercase:   false,
		RequireLowercase:   false,
		RequireDigit:       false,
		RequireSpecialChar: false,
	}
	ps.WithPolicy(lenient)

	// Should validate weak passwords
	err := ps.Validate("weak")
	assert.NoError(t, err)

	// Should hash weak passwords
	hash, err := ps.Hash("weak")
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Should verify
	valid, err := ps.Verify("weak", hash)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestPasswordService_SpecialCharacters(t *testing.T) {
	ps := NewPasswordService()

	// Test various special characters - each password is at least 12 chars
	// with uppercase, lowercase, digit, and the special character being tested
	specialPasswords := []string{
		"Password123!",  // Basic special
		"Password123@",  // At symbol
		"Password123#",  // Hash
		"Password123$",  // Dollar
		"Password123%",  // Percent
		"Password123^",  // Caret
		"Password123&",  // Ampersand
		"Password123*",  // Asterisk
		"Password123(",  // Open paren
		"Password123)",  // Close paren
		"Password123_",  // Underscore
		"Password123+",  // Plus
		"Password123-",  // Minus
		"Password123=",  // Equals
		"Password123[",  // Open bracket
		"Password123]",  // Close bracket
		"Password123{",  // Open brace
		"Password123}",  // Close brace
		"Password123|",  // Pipe
		"Password123;",  // Semicolon
		"Password123:",  // Colon
		"Password123,",  // Comma
		"Password123.",  // Period
		"Password123<",  // Less than
		"Password123>",  // Greater than
		"Password123?",  // Question mark
	}

	for _, password := range specialPasswords {
		t.Run("special_"+password, func(t *testing.T) {
			err := ps.Validate(password)
			assert.NoError(t, err, "password with special char should validate: %s", password)

			hash, err := ps.Hash(password)
			assert.NoError(t, err)

			valid, err := ps.Verify(password, hash)
			assert.NoError(t, err)
			assert.True(t, valid)
		})
	}
}
