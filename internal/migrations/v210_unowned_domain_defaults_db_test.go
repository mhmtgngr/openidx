// Package migrations_test, not migrations, so that it can reach
// adminPoolOrSkip in least_privilege_owner_test.go.
package migrations_test

import (
	"context"
	"encoding/json"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// The values the settings shipped with, which name a domain the project does
// not own. They are the fixtures v210 has to find.
const (
	v210OldSupport  = "support@openidx.io" // domain-ok: the shipped default under test
	v210OldRPID     = "openidx.io"         // domain-ok: the shipped default under test
	v210OldRPOrigin = "https://openidx.io" // domain-ok: the shipped default under test
)

// v210 is the migration under test; beforeV210 is every migration before it,
// whichever numbers the migrations merged beside it took.
const (
	v210       = 210
	beforeV210 = v210 - 1
)

// TestV210ClearsOnlyTheShippedDomainDefaults applies v210 over the settings an
// install can hold before it: the system settings document as migration 014
// seeded it, the console settings of an organization that saved them with the
// defaults in, those of one whose administrator typed their own, and one with
// a relying party ID left at the default and an origin typed. Every stored
// copy of a shipped value is cleared, and nothing an administrator typed
// changes, nor do the rows' other fields or who changed them last. A fresh
// install seeds no such value, and rolling back puts none back.
func TestV210ClearsOnlyTheShippedDomainDefaults(t *testing.T) {
	db, _, cleanup := adminPoolOrSkip(t)
	defer cleanup()
	ctx := context.Background()
	pool := db.Pool

	for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("reset schema (%s): %v", stmt, err)
		}
	}
	m := migrations.NewMigrator(pool.Raw(), zap.NewNop())
	if err := m.MigrateTo(ctx, beforeV210); err != nil {
		t.Fatalf("migrate to %d: %v", beforeV210, err)
	}

	systemSupport := func() string {
		t.Helper()
		var v string
		if err := pool.QueryRow(ctx,
			`SELECT value #>> '{general,support_email}' FROM system_settings WHERE key = 'system'`).Scan(&v); err != nil {
			t.Fatalf("read the system settings: %v", err)
		}
		return v
	}
	if got := systemSupport(); got != "" {
		t.Fatalf("a fresh install seeds the support address %q, want none", got)
	}
	// The document as installs seeded before this change hold it.
	if _, err := pool.Exec(ctx, `
		UPDATE system_settings SET value = jsonb_set(value, '{general,support_email}', to_jsonb($1::text))
		 WHERE key = 'system'`, v210OldSupport); err != nil {
		t.Fatalf("restore the old seed: %v", err)
	}

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	newOrg := func(slug string) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx,
			`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, slug).Scan(&id); err != nil {
			t.Fatalf("seed organization %s: %v", slug, err)
		}
		return id
	}
	orgB, orgC := newOrg("v210-typed"), newOrg("v210-mixed")

	general := func(support string) string {
		b, _ := json.Marshal(map[string]any{
			"organization_name": "Org", "support_email": support,
			"default_language": "en", "default_timezone": "UTC", "session_timeout": 3600,
		})
		return string(b)
	}
	security := func(rpID, rpOrigin string) string {
		b, _ := json.Marshal(map[string]any{
			"password_policy": map[string]any{"min_length": 14},
			"mfa": map[string]any{
				"enabled": true, "required": true, "allowed_methods": []string{"webauthn"},
				"webauthn": map[string]any{
					"enabled": true, "relying_party_id": rpID, "relying_party_name": "OpenIDX",
					"relying_party_origin": rpOrigin, "user_verification": "required",
				},
			},
			"session": map[string]any{"idle_timeout_minutes": 30},
		})
		return string(b)
	}
	const savedAt = "2026-01-02T03:04:05Z"
	seed := func(org, key, value string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO admin_console_settings (org_id, key, value, updated_at, updated_by)
			VALUES ($1::uuid, $2, $3::jsonb, $4::timestamptz, 'admin-who-saved')`, org, key, value, savedAt); err != nil {
			t.Fatalf("seed %s/%s: %v", org, key, err)
		}
	}
	seed(orgA, "general", general(v210OldSupport))
	seed(orgA, "security", security(v210OldRPID, v210OldRPOrigin))
	seed(orgB, "general", general("help@corp.example"))
	seed(orgB, "security", security("login.corp.example", "https://login.corp.example"))
	seed(orgC, "security", security(v210OldRPID, "https://id.corp.example"))

	stored := func(org, key string) (map[string]any, string, string) {
		t.Helper()
		var raw []byte
		var at, by string
		if err := pool.QueryRow(ctx, `
			SELECT value, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), updated_by
			  FROM admin_console_settings WHERE org_id = $1::uuid AND key = $2`, org, key).Scan(&raw, &at, &by); err != nil {
			t.Fatalf("read %s/%s: %v", org, key, err)
		}
		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("decode %s/%s: %v", org, key, err)
		}
		return v, at, by
	}
	webauthn := func(v map[string]any) map[string]any {
		return v["mfa"].(map[string]any)["webauthn"].(map[string]any)
	}
	typedGeneral, _, _ := stored(orgB, "general")
	typedSecurity, _, _ := stored(orgB, "security")

	if err := m.MigrateTo(ctx, v210); err != nil {
		t.Fatalf("migrate to %d: %v", v210, err)
	}

	if got := systemSupport(); got != "" {
		t.Errorf("the system settings still name %q as the support address", got)
	}

	gen, at, by := stored(orgA, "general")
	if gen["support_email"] != "" {
		t.Errorf("org A's support address is still %v", gen["support_email"])
	}
	if gen["organization_name"] != "Org" || gen["session_timeout"] != float64(3600) {
		t.Errorf("clearing the address changed the rest of org A's general settings: %v", gen)
	}
	if at != savedAt || by != "admin-who-saved" {
		t.Errorf("org A's general settings now say they were changed at %s by %s; the migration is not an administrator", at, by)
	}
	sec, at, by := stored(orgA, "security")
	if wa := webauthn(sec); wa["relying_party_id"] != "" || wa["relying_party_origin"] != "" {
		t.Errorf("org A's relying party is still %v / %v", wa["relying_party_id"], wa["relying_party_origin"])
	}
	if wa := webauthn(sec); wa["enabled"] != true || wa["user_verification"] != "required" || wa["relying_party_name"] != "OpenIDX" {
		t.Errorf("clearing the relying party changed the rest of org A's WebAuthn settings: %v", wa)
	}
	if sec["password_policy"].(map[string]any)["min_length"] != float64(14) || sec["mfa"].(map[string]any)["required"] != true {
		t.Errorf("clearing the relying party changed org A's password or MFA policy: %v", sec)
	}
	if at != savedAt || by != "admin-who-saved" {
		t.Errorf("org A's security settings now say they were changed at %s by %s", at, by)
	}

	for key, before := range map[string]map[string]any{"general": typedGeneral, "security": typedSecurity} {
		after, _, _ := stored(orgB, key)
		a, _ := json.Marshal(after)
		b, _ := json.Marshal(before)
		if string(a) != string(b) {
			t.Errorf("org B typed its own %s settings and v210 changed them:\n before %s\n after  %s", key, b, a)
		}
	}

	mixed, _, _ := stored(orgC, "security")
	if wa := webauthn(mixed); wa["relying_party_id"] != "" || wa["relying_party_origin"] != "https://id.corp.example" {
		t.Errorf("org C: want the default ID cleared and the typed origin kept, got %v / %v",
			wa["relying_party_id"], wa["relying_party_origin"])
	}

	var left int
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT COUNT(*) FROM admin_console_settings WHERE strpos(value::text, $1) > 0)
		     + (SELECT COUNT(*) FROM system_settings WHERE strpos(value::text, $1) > 0)`, v210OldRPID).Scan(&left); err != nil {
		t.Fatalf("count what is left: %v", err)
	}
	if left != 0 {
		t.Errorf("%d settings rows still name the domain after v210", left)
	}

	// Down puts nothing back, and the chain applies again over it.
	if err := m.RollbackTo(ctx, beforeV210); err != nil {
		t.Fatalf("rollback to %d: %v", beforeV210, err)
	}
	if got := systemSupport(); got != "" {
		t.Errorf("rolling back put %q back as the support address", got)
	}
	if err := m.MigrateTo(ctx, -1); err != nil {
		t.Fatalf("re-apply after rollback: %v", err)
	}
}
