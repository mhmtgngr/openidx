package admin

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestSettingsRepositoryWritesUsePrimary guards the Repository invariant shared
// across the codebase's aggregates (identity User/Group/Session, oauth
// OAuthClientStore): write methods must use the PRIMARY pool (db.Pool), never
// db.Reader(). A mutation that "optimizes" a write onto the replica would be
// caught here.
func TestSettingsRepositoryWritesUsePrimary(t *testing.T) {
	src := readSettingsRepoSource(t)
	body := settingsMethodBody(src, "PutRaw")
	if body == "" {
		t.Fatal("could not find PutRaw")
	}
	if strings.Contains(body, ".Reader(") {
		t.Error("PutRaw uses .Reader() (writes must go to the primary db.Pool)")
	}
	if !strings.Contains(body, "db.Pool.Exec") {
		t.Error("PutRaw should write via db.Pool.Exec (the primary)")
	}
}

// TestSettingsRepositoryGetUsesPrimary pins the deliberate security choice:
// system_settings carries password policy / RequireMFA / lockout, so a read
// must observe the latest write immediately (read-after-write). We therefore
// read the PRIMARY and must NOT offload to the replica, whose lag could serve a
// stale — and thus weaker — security policy. This mirrors SessionRepository.
func TestSettingsRepositoryGetUsesPrimary(t *testing.T) {
	src := readSettingsRepoSource(t)
	body := settingsMethodBody(src, "GetRaw")
	if body == "" {
		t.Fatal("could not find GetRaw")
	}
	if strings.Contains(body, ".Reader(") {
		t.Error("GetRaw must read the PRIMARY (security policy must be read-after-write, not from a lagging replica)")
	}
	if !strings.Contains(body, "db.Pool.QueryRow") {
		t.Error("GetRaw should read via db.Pool.QueryRow (the primary)")
	}
}

// TestSettingsRepositoryHasNilDBGuards ensures both methods guard a nil db,
// matching the guards added to the other aggregates (defense against a
// misconfigured constructor causing a nil-pointer panic on the request path).
func TestSettingsRepositoryHasNilDBGuards(t *testing.T) {
	src := readSettingsRepoSource(t)
	for _, m := range []string{"GetRaw", "PutRaw"} {
		body := settingsMethodBody(src, m)
		if !strings.Contains(body, "r.db == nil") || !strings.Contains(body, "r.db.Pool == nil") {
			t.Errorf("%s must guard a nil db / db.Pool before touching the pool", m)
		}
	}
}

func readSettingsRepoSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("settings_repository.go")
	if err != nil {
		t.Fatalf("read settings_repository.go: %v", err)
	}
	return string(b)
}

func settingsMethodBody(src, method string) string {
	re := regexp.MustCompile(`func \(r \*PostgresSettingsRepository\) ` + regexp.QuoteMeta(method) + `\(`)
	loc := re.FindStringIndex(src)
	if loc == nil {
		return ""
	}
	rest := src[loc[0]:]
	depth := 0
	started := false
	for i, r := range rest {
		switch r {
		case '{':
			depth++
			started = true
		case '}':
			depth--
			if started && depth == 0 {
				return rest[:i+1]
			}
		}
	}
	return rest
}
