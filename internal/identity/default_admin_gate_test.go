package identity

import (
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/pwhash"
)

// seededAdminHash is the exact bcrypt hash migration v10 writes for
// admin@openidx.local (internal/migrations/sql.go, seedDataUp). Pinning it
// here keeps the gate and the seed honest about being the same credential:
// if the seed ever changes password without this test noticing, the gate
// stops guarding anything.
const seededAdminHash = "$2b$12$oX..0F6dHbNip8vASE5VdOgXiBfyqRZ768PU5vArjeOMxG5MGEEdq"

func TestDefaultAdminVerdictBlocksSeededPassword(t *testing.T) {
	err := defaultAdminVerdict([]seededAdminRow{{
		ID:           seededAdminID,
		Email:        seededAdminEmail,
		Enabled:      true,
		PasswordHash: seededAdminHash,
	}}, zap.NewNop())
	if err == nil {
		t.Fatal("an enabled account with the seeded default password must refuse production startup")
	}
	if !strings.Contains(err.Error(), seededAdminEmail) {
		t.Errorf("error should name the offending account, got: %v", err)
	}
}

// TestDefaultAdminVerdictBlocksRehashOfSamePassword: "rotating" to the same
// password under the current hash scheme is not a rotation. The gate compares
// against the plaintext with the login path's verifier, so a fresh Argon2id
// hash of Admin@123 still blocks.
func TestDefaultAdminVerdictBlocksRehashOfSamePassword(t *testing.T) {
	rehashed, err := pwhash.Hash(seededAdminPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	verr := defaultAdminVerdict([]seededAdminRow{{
		ID: seededAdminID, Email: seededAdminEmail, Enabled: true, PasswordHash: rehashed,
	}}, zap.NewNop())
	if verr == nil {
		t.Fatal("a re-hash of the same default password must still block startup")
	}
}

func TestDefaultAdminVerdictPassesWhenRotated(t *testing.T) {
	rotated, err := pwhash.Hash("an-actually-rotated-password-7#")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	cases := []struct {
		name string
		rows []seededAdminRow
	}{
		{"rotated password", []seededAdminRow{{ID: seededAdminID, Email: seededAdminEmail, Enabled: true, PasswordHash: rotated}}},
		{"account deleted", nil},
		{"no password hash (federated or demo account)", []seededAdminRow{{ID: seededAdminID, Email: seededAdminEmail, Enabled: true, PasswordHash: ""}}},
		{"uninterpretable stored hash", []seededAdminRow{{ID: seededAdminID, Email: seededAdminEmail, Enabled: true, PasswordHash: "not-a-hash"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := defaultAdminVerdict(tc.rows, zap.NewNop()); err != nil {
				t.Errorf("verdict = %v, want nil", err)
			}
		})
	}
}

// TestDefaultAdminVerdictWarnsOnDisabledAccount: disabling the seeded admin is
// a legitimate remediation — the login path is already cut off — so the gate
// warns instead of refusing to boot.
func TestDefaultAdminVerdictWarnsOnDisabledAccount(t *testing.T) {
	err := defaultAdminVerdict([]seededAdminRow{{
		ID: seededAdminID, Email: seededAdminEmail, Enabled: false, PasswordHash: seededAdminHash,
	}}, zap.NewNop())
	if err != nil {
		t.Errorf("a disabled account must not block startup, got: %v", err)
	}
}
