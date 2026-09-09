package migrations

import (
	"regexp"
	"strings"
	"testing"
)

// TestMigrationV186_sessionMFAVerifiedAt pins the shape the freshness gate
// depends on, and the one judgement in the migration worth pinning: which
// sessions get a backfilled value and which must not.
func TestMigrationV186_sessionMFAVerifiedAt(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 186 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v186 not registered in allMigrations()")
	}
	if m.Name != "session_mfa_verified_at" {
		t.Errorf("v186 Name = %q, want session_mfa_verified_at", m.Name)
	}

	// Nullable and idempotent: NULL is "this session has never proved a second
	// factor", which the gate reads as stale. A NOT NULL column would need a
	// default, and any default here is a lie about when a factor was verified.
	if !regexp.MustCompile(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS mfa_verified_at TIMESTAMPTZ;`).MatchString(m.UpSQL) {
		t.Error("v186 does not add sessions.mfa_verified_at TIMESTAMPTZ idempotently")
	}
	if regexp.MustCompile(`mfa_verified_at TIMESTAMPTZ[^;]*(NOT NULL|DEFAULT)`).MatchString(m.UpSQL) {
		t.Error("v186 makes mfa_verified_at NOT NULL or gives it a DEFAULT; either invents a verification time")
	}

	// The backfill is conditional on auth_methods containing 'mfa'. A session
	// whose recorded methods include a second factor verified it when the
	// session started -- the same fact the amr claim already asserts about it,
	// so this is a reading of existing data, not an invention. An
	// unconditional backfill would hand every session on the install a
	// freshness it never earned, which is the one thing this column must never
	// say.
	if !strings.Contains(m.UpSQL, "'mfa' = ANY(auth_methods)") {
		t.Error("v186's backfill is not conditional on auth_methods containing 'mfa'")
	}
	if !regexp.MustCompile(`SET mfa_verified_at = started_at`).MatchString(m.UpSQL) {
		t.Error("v186 does not backfill from started_at; any other source is a guess")
	}
	if regexp.MustCompile(`SET mfa_verified_at = NOW\(\)`).MatchString(m.UpSQL) {
		t.Error("v186 backfills with NOW(); that would declare every existing session freshly verified " +
			"at upgrade, which is exactly the claim the column exists to be able to refute")
	}

	// The partial index serves the gate's lookup and skips the rows that have
	// no timestamp, which on a fresh upgrade is most of them.
	if !regexp.MustCompile(`CREATE INDEX IF NOT EXISTS idx_sessions_mfa_verified_at`).MatchString(m.UpSQL) {
		t.Error("v186 does not create the index the gate's lookup uses")
	}
	if !strings.Contains(m.UpSQL, "WHERE mfa_verified_at IS NOT NULL") {
		t.Error("v186's index is not partial")
	}

	// Rollback removes both, idempotently.
	for _, want := range []string{
		"DROP INDEX IF EXISTS idx_sessions_mfa_verified_at;",
		"ALTER TABLE sessions DROP COLUMN IF EXISTS mfa_verified_at;",
	} {
		if !strings.Contains(m.DownSQL, want) {
			t.Errorf("v186 rollback does not contain %q", want)
		}
	}

	// Plain statements only. The migration runner executes these directly and
	// the repository's convention (v69 onward) is no DO $$ blocks.
	if strings.Contains(m.UpSQL, "DO $$") || strings.Contains(m.DownSQL, "DO $$") {
		t.Error("v186 uses a DO $$ block; the convention here is plain statements")
	}
}
