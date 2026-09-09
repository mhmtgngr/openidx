package migrations

import (
	"regexp"
	"strings"
	"testing"
)

// TestMigrationV187_refreshFamilyLifetime pins the shape of the cap: both
// columns, a backfill that leaves nothing NULL, the three native clients
// updated, and a rollback that puts the seeded lifetime back.
func TestMigrationV187_refreshFamilyLifetime(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 187 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v187 not registered in allMigrations()")
	}
	if m.Name != "refresh_family_lifetime" {
		t.Errorf("v187 Name = %q, want refresh_family_lifetime", m.Name)
	}

	for _, frag := range []string{
		"ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS family_started_at TIMESTAMPTZ",
		"ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS refresh_token_max_lifetime INTEGER",
		"MIN(created_at)",
		"'openidx-mobile', 'openidx-agent-android'",
		"'openidx-desktop'",
	} {
		if !strings.Contains(m.UpSQL, frag) {
			t.Errorf("v187 UpSQL missing %q", frag)
		}
	}

	// The backfill has to leave NOTHING null, or the families it missed are
	// measured from their own created_at and slide exactly like the tokens.
	// Two statements do that: the per-family MIN, then the catch-all.
	if !strings.Contains(m.UpSQL, "SET family_started_at = created_at\n WHERE family_started_at IS NULL") {
		t.Error("v187 has no catch-all backfill; a family_id-less row would stay NULL")
	}

	// The seeded values are the recorded decision, so they are pinned here
	// rather than left to whatever someone edits the SQL to later.
	for _, want := range []struct{ what, value string }{
		{"14 days per token for the mobile clients", "1209600"},
		{"90-day family cap", "7776000"},
	} {
		if !strings.Contains(m.UpSQL, want.value) {
			t.Errorf("v187 does not set %s (%s)", want.what, want.value)
		}
	}

	// An operator who already retuned the lifetime must keep their value.
	if !regexp.MustCompile(`AND refresh_token_lifetime = 2592000`).MatchString(m.UpSQL) {
		t.Error("v187 overwrites refresh_token_lifetime unconditionally; it must only " +
			"replace the seeded 2592000, or an operator's own tuning is silently reverted")
	}

	for _, frag := range []string{
		"ALTER TABLE oauth_clients DROP COLUMN IF EXISTS refresh_token_max_lifetime",
		"ALTER TABLE oauth_refresh_tokens DROP COLUMN IF EXISTS family_started_at",
		"SET refresh_token_lifetime = 2592000",
	} {
		if !strings.Contains(m.DownSQL, frag) {
			t.Errorf("v187 DownSQL missing %q", frag)
		}
	}
}

// TestEveryNativeClientHasAFamilyCap is the guard, and it derives both sides.
//
// The shipped native clients come from their own source — the same census
// TestEveryShippedClientIsSeededByAMigration uses, so a fourth native client is
// picked up the day it ships rather than the day someone remembers to add it
// here. The caps come from every migration's UpSQL.
//
// A native client is exactly the set whose refresh token sits at rest on a
// device somebody can pick up, which is what makes an uncapped family a
// standing grant rather than a session. Browser clients are deliberately not in
// this set and are deliberately not capped.
func TestEveryNativeClientHasAFamilyCap(t *testing.T) {
	shipped := []shippedClient{
		goAgentClient(t, "../../agent/internal/sso/sso.go", "DesktopClientID", "RedirectURI"),
		goAgentClient(t, "../../agent/internal/sso/sso.go", "MobileClientID", "MobileRedirectURI"),
		kotlinAgentClient(t, "../../agent-android/app/src/main/java/com/openidx/agent/enrollment/OAuthEnrollmentFlow.kt"),
	}
	capped := cappedClients(t)
	if len(capped) == 0 {
		t.Fatal("no refresh_token_max_lifetime assignment found in any migration; " +
			"the census read nothing and would pass vacuously")
	}

	for _, sc := range shipped {
		seconds, ok := capped[sc.clientID]
		if !ok {
			t.Errorf("%s ships client_id %q and no migration gives it a "+
				"refresh_token_max_lifetime. Its refresh token lives at rest on a device; "+
				"without a family cap, rotation restarts the per-token lifetime on every "+
				"use and the authorization never ends.", sc.source, sc.clientID)
			continue
		}
		if seconds <= 0 {
			t.Errorf("%s: %q is capped at %d seconds, which is not a cap",
				sc.source, sc.clientID, seconds)
		}
	}
}

// cappedClients reads every `refresh_token_max_lifetime = <n>` assignment out of
// the migrations and attributes it to the client_ids the same statement names.
// Both the UPDATE ... WHERE client_id IN (...) and the single-client form are
// recognised; anything else is not a cap this census can see, and the test above
// reports the client as uncapped rather than guessing.
func cappedClients(t *testing.T) map[string]int {
	t.Helper()
	out := map[string]int{}
	stmtRe := regexp.MustCompile(`(?s)UPDATE oauth_clients.*?refresh_token_max_lifetime = (\d+).*?client_id (?:IN \(([^)]*)\)|= ('[^']*'))`)
	idRe := regexp.MustCompile(`'([^']+)'`)
	for _, m := range allMigrations() {
		for _, stmt := range stmtRe.FindAllStringSubmatch(m.UpSQL, -1) {
			seconds := 0
			for _, ch := range stmt[1] {
				seconds = seconds*10 + int(ch-'0')
			}
			ids := stmt[2]
			if ids == "" {
				ids = stmt[3]
			}
			for _, id := range idRe.FindAllStringSubmatch(ids, -1) {
				out[id[1]] = seconds
			}
		}
	}
	return out
}
