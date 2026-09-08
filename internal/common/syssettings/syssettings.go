// Package syssettings is the one reader of the console's system settings row.
//
// WHY IT EXISTS. system_settings is a key/value table. The admin console reads
// and writes the whole settings document under the key "system" — that is what
// migration 010 seeds and what internal/admin's GetSettings/UpdateSettings
// use. Four other places in the product read settings out of the same table
// under keys nothing has ever written:
//
//	internal/oauth/session_policy.go   key = 'settings'
//	internal/identity/service.go       key = 'failed_login_lockout_threshold'
//	internal/identity/service.go       key = 'failed_login_lockout_duration'
//	internal/audit/compliance_enhanced.go  key = 'security' (x2), 'authentication'
//
// Every one of those queries returns no rows on every install that has ever
// run, and every one of them treats no-rows as "not configured" and carries on
// with a default. So:
//
//   - the console's Security tab could set an idle timeout, an absolute
//     timeout, a remember-me duration, a re-auth interval, IP binding and a
//     concurrent-session policy, and getEffectiveSessionPolicy applied the
//     compiled-in defaults regardless;
//   - "Max failed logins" and "Lockout duration" were saved and the lockout ran
//     on 5 attempts and 15 minutes whatever they said;
//   - the ISO 27001 / SOC 2 assessment deducted 40 points and reported "No
//     security policy configuration found in system_settings" on installs whose
//     security policy was fully configured — a compliance finding that was
//     simply false.
//
// Nothing failed, nothing logged, and each caller looked correct in isolation.
// A key that is never written is a table that is never read, one level finer:
// the SQL is valid, the tenant predicate is right, the handler answers 200, and
// the default that comes back is indistinguishable from a real answer.
//
// The fix is one reader with one key constant, so the next consumer cannot
// invent a sixth spelling. settings_keys_test.go holds the tree to it: any
// query naming system_settings under a key that nothing writes fails the test.
package syssettings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Key is the system_settings row the admin console reads and writes. It is
// seeded by migration 010 and upserted by internal/admin's UpdateSettings.
const Key = "system"

// Settings mirrors the document internal/admin writes under Key. Only the
// fields consumers outside internal/admin actually read are declared; the JSON
// tags must match internal/admin's structs exactly, which syssettings_test.go
// checks by reflection rather than by eye.
type Settings struct {
	Security       Security       `json:"security"`
	Authentication Authentication `json:"authentication"`
}

// Security is the console's Security tab.
type Security struct {
	PasswordPolicy PasswordPolicy `json:"password_policy"`

	SessionTimeout  int  `json:"session_timeout"`
	MaxFailedLogins int  `json:"max_failed_logins"`
	LockoutDuration int  `json:"lockout_duration"` // minutes
	RequireMFA      bool `json:"require_mfa"`

	IdleTimeout               int    `json:"idle_timeout"`         // seconds
	AbsoluteTimeout           int    `json:"absolute_timeout"`     // seconds
	RememberMeDuration        int    `json:"remember_me_duration"` // seconds
	ReauthInterval            int    `json:"reauth_interval"`      // seconds, 0 = unset
	BindSessionToIP           bool   `json:"bind_session_to_ip"`
	ForceLogoutOnPwdChange    bool   `json:"force_logout_on_password_change"`
	MaxConcurrentSessions     int    `json:"max_concurrent_sessions"`
	ConcurrentSessionStrategy string `json:"concurrent_session_strategy"`
}

// PasswordPolicy is the console's password rules.
type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireNumbers   bool `json:"require_numbers"`
	RequireSpecial   bool `json:"require_special"`
	MaxAge           int  `json:"max_age"`
	History          int  `json:"history"`
}

// Authentication is the console's Authentication tab.
type Authentication struct {
	AllowRegistration  bool     `json:"allow_registration"`
	RequireEmailVerify bool     `json:"require_email_verify"`
	MFAMethods         []string `json:"mfa_methods"`
}

// ErrNotConfigured means the settings row is absent — a genuinely fresh
// install that has never saved settings and whose seed row was removed. It is
// returned as a distinct error so a caller can tell "the operator has not
// configured this" from "the database would not answer", which is the
// distinction every one of the broken readers above collapsed.
var ErrNotConfigured = errors.New("system settings row not present")

// Querier is the read surface Load needs, satisfied by *pgxpool.Pool, a
// connection, a transaction, and by a stub in tests.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Load reads the console's settings document.
//
// system_settings is install-wide by design — it is one of the tables
// migration v034 deliberately left without org_id — so this carries no tenant
// predicate and needs none.
func Load(ctx context.Context, q Querier) (Settings, error) {
	var s Settings
	if q == nil {
		return s, ErrNotConfigured
	}
	var raw []byte
	//orgscope:ignore system_settings is install-wide configuration with no org_id column (migration v034)
	err := q.QueryRow(ctx, `SELECT value::text FROM system_settings WHERE key = $1`, Key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrNotConfigured
	}
	if err != nil {
		return s, fmt.Errorf("read system settings: %w", err)
	}
	if len(raw) == 0 {
		return s, ErrNotConfigured
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("parse system settings: %w", err)
	}
	return s, nil
}
