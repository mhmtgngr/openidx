package migrations

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// TestMigrationV184_androidAgentClient pins the seed the way v84/v85 never
// were: the row must register the exact client_id, redirect and scopes the
// Kotlin agent hardcodes, be public + PKCE, and roll back cleanly.
func TestMigrationV184_androidAgentClient(t *testing.T) {
	var m *Migration
	for _, cand := range allMigrations() {
		if cand.Version == 184 {
			m = cand
			break
		}
	}
	if m == nil {
		t.Fatal("migration v184 not registered in allMigrations()")
	}
	if m.Name != "seed_android_agent_oauth_client" {
		t.Errorf("v184 Name = %q, want seed_android_agent_oauth_client", m.Name)
	}
	for _, frag := range []string{
		"'openidx-agent-android'",
		`"com.openidx.agent://oauth/redirect"`,
		`"agent.enroll"`,
		"'public'",
		"ON CONFLICT (id) DO NOTHING",
	} {
		if !strings.Contains(m.UpSQL, frag) {
			t.Errorf("v184 UpSQL missing %q", frag)
		}
	}
	// pkce_required must be true: it is the 11th value in the v84-shaped
	// INSERT, right after the scopes array.
	if !regexp.MustCompile(`\]'::jsonb,\s*true,\s*true,`).MatchString(m.UpSQL) {
		t.Error("v184 does not set pkce_required=true, allow_refresh_token=true")
	}
	if !strings.Contains(m.DownSQL, "DELETE FROM oauth_clients WHERE id = '80000000-0000-0000-0000-000000000007'") {
		t.Error("v184 DownSQL does not delete the seeded row")
	}
}

// shippedClient is what a client binary hardcodes about its OAuth registration.
// Each field is parsed out of the client's own source, never written here.
type shippedClient struct {
	source   string
	clientID string
	redirect string
	scopes   []string
}

// seededClient is what a migration registers.
type seededClient struct {
	migration int
	redirects []string
	scopes    []string
}

// TestEveryShippedClientIsSeededByAMigration is the guard that would have
// found v184's defect on the day it was written. The Android agent named a
// client_id and a scope in Kotlin, and no migration registered either, so the
// first thing every Android user tapped answered invalid_client -- and nothing
// in the repository could see it, because the client's registration lives in
// three languages (Go, Kotlin, SQL) with no census across them.
//
// This derives both sides. Shipped clients come from the source files that
// hardcode them; seeded clients come from every migration's UpSQL. A client_id
// a binary uses must be seeded; the redirect it registers must be among the
// seeded redirects; every scope it requests must be among the seeded scopes,
// because scopeAllowedForClient refuses anything else at /authorize.
func TestEveryShippedClientIsSeededByAMigration(t *testing.T) {
	shipped := []shippedClient{
		goAgentClient(t, "../../agent/internal/sso/sso.go", "DesktopClientID", "RedirectURI"),
		goAgentClient(t, "../../agent/internal/sso/sso.go", "MobileClientID", "MobileRedirectURI"),
		kotlinAgentClient(t, "../../agent-android/app/src/main/java/com/openidx/agent/enrollment/OAuthEnrollmentFlow.kt"),
	}
	seeded := seededClients(t)
	if len(seeded) == 0 {
		t.Fatal("no oauth_clients INSERT found in any migration; the census read nothing and would pass vacuously")
	}

	for _, sc := range shipped {
		reg, ok := seeded[sc.clientID]
		if !ok {
			t.Errorf("%s uses client_id %q and no migration seeds it: the authorize request "+
				"answers invalid_client on every install", sc.source, sc.clientID)
			continue
		}
		if !slices.Contains(reg.redirects, sc.redirect) {
			t.Errorf("%s registers redirect %q for %q but migration v%d seeds %v: the authorize "+
				"request answers invalid_request (redirect_uri mismatch)",
				sc.source, sc.redirect, sc.clientID, reg.migration, reg.redirects)
		}
		for _, s := range sc.scopes {
			if !slices.Contains(reg.scopes, s) {
				t.Errorf("%s requests scope %q for %q but migration v%d seeds %v: "+
					"scopeAllowedForClient refuses the request with invalid_scope",
					sc.source, s, sc.clientID, reg.migration, reg.scopes)
			}
		}
	}
}

// goAgentClient reads the string constants and the DefaultScopes slice out of
// agent/internal/sso/sso.go.
func goAgentClient(t *testing.T, path, idConst, redirectConst string) shippedClient {
	t.Helper()
	src := readSource(t, path)
	get := func(name string) string {
		re := regexp.MustCompile(`\b` + name + `\s*=\s*"([^"]+)"`)
		m := re.FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("%s: constant %s not found", path, name)
		}
		return m[1]
	}
	scopesRe := regexp.MustCompile(`DefaultScopes\s*=\s*\[\]string\{([^}]*)\}`)
	m := scopesRe.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("%s: DefaultScopes not found", path)
	}
	return shippedClient{
		source:   path + " (" + idConst + ")",
		clientID: get(idConst),
		redirect: get(redirectConst),
		scopes:   quotedStrings(m[1]),
	}
}

// kotlinAgentClient reads DEFAULT_CLIENT_ID, REDIRECT_URI and the setScopes(...)
// call out of the Android agent's OAuth flow.
func kotlinAgentClient(t *testing.T, path string) shippedClient {
	t.Helper()
	src := readSource(t, path)
	get := func(name string) string {
		re := regexp.MustCompile(`const val ` + name + `\s*=\s*"([^"]+)"`)
		m := re.FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("%s: const val %s not found", path, name)
		}
		return m[1]
	}
	scopesRe := regexp.MustCompile(`\.setScopes\(([^)]*)\)`)
	m := scopesRe.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("%s: setScopes(...) not found", path)
	}
	return shippedClient{
		source:   path,
		clientID: get("DEFAULT_CLIENT_ID"),
		redirect: get("REDIRECT_URI"),
		scopes:   quotedStrings(m[1]),
	}
}

// seededClients parses every oauth_clients INSERT across all migrations. The
// v84-shaped INSERT lists redirect_uris, grant_types, response_types, scopes as
// four consecutive '[...]'::jsonb literals after the type column; the initial
// schema's seeds use the same column order.
func seededClients(t *testing.T) map[string]seededClient {
	t.Helper()
	out := map[string]seededClient{}
	rowRe := regexp.MustCompile(`(?s)\(\s*'[0-9a-f-]{36}',\s*'([^']+)',\s*(?:NULL|'[^']*'),\s*'[^']*',\s*'[^']*',\s*'[^']*',\s*'(\[[^\]]*\])'::jsonb,\s*'\[[^\]]*\]'::jsonb,\s*'\[[^\]]*\]'::jsonb,\s*'(\[[^\]]*\])'::jsonb`)
	for _, m := range allMigrations() {
		if !strings.Contains(m.UpSQL, "INSERT INTO oauth_clients") {
			continue
		}
		for _, row := range rowRe.FindAllStringSubmatch(m.UpSQL, -1) {
			var redirects, scopes []string
			if err := json.Unmarshal([]byte(row[2]), &redirects); err != nil {
				t.Fatalf("v%d: redirect_uris for %s is not a JSON array: %v", m.Version, row[1], err)
			}
			if err := json.Unmarshal([]byte(row[3]), &scopes); err != nil {
				t.Fatalf("v%d: scopes for %s is not a JSON array: %v", m.Version, row[1], err)
			}
			out[row[1]] = seededClient{migration: m.Version, redirects: redirects, scopes: scopes}
		}
	}
	return out
}

func readSource(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v (the census reads the client's own source; if it moved, point here at the new path)", path, err)
	}
	return string(b)
}

// quotedStrings extracts every "..." literal from a Go or Kotlin argument list.
func quotedStrings(list string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(list, -1) {
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}
