package credentials

import (
	"strings"
	"testing"
)

// TestPgConfigFromMap_ValidDefaults checks that a fully-specified valid map
// parses correctly and that port/sslmode defaults are applied when omitted.
func TestPgConfigFromMap_ValidDefaults(t *testing.T) {
	cfg := map[string]any{
		"host":            "db.example.com",
		"dbname":          "mydb",
		"admin_secret_id": "secret-uuid-1",
		"admin_username":  "postgres",
		"target_role":     "app_user",
	}
	conf, err := pgConfigFromMap(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.host != "db.example.com" {
		t.Errorf("host: got %q, want %q", conf.host, "db.example.com")
	}
	if conf.port != 5432 {
		t.Errorf("port default: got %d, want 5432", conf.port)
	}
	if conf.dbname != "mydb" {
		t.Errorf("dbname: got %q, want %q", conf.dbname, "mydb")
	}
	if conf.sslmode != "require" {
		t.Errorf("sslmode default: got %q, want %q", conf.sslmode, "require")
	}
	if conf.adminSecretID != "secret-uuid-1" {
		t.Errorf("adminSecretID: got %q", conf.adminSecretID)
	}
	if conf.adminUsername != "postgres" {
		t.Errorf("adminUsername: got %q", conf.adminUsername)
	}
	if conf.targetRole != "app_user" {
		t.Errorf("targetRole: got %q", conf.targetRole)
	}
}

// TestPgConfigFromMap_ExplicitValues verifies that explicit port and sslmode override defaults.
func TestPgConfigFromMap_ExplicitValues(t *testing.T) {
	cfg := map[string]any{
		"host":            "10.0.0.1",
		"port":            float64(5433), // JSON numbers decode as float64
		"dbname":          "appdb",
		"sslmode":         "verify-full",
		"admin_secret_id": "sec-1",
		"admin_username":  "superuser",
		"target_role":     "webapp",
	}
	conf, err := pgConfigFromMap(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.port != 5433 {
		t.Errorf("port: got %d, want 5433", conf.port)
	}
	if conf.sslmode != "verify-full" {
		t.Errorf("sslmode: got %q, want %q", conf.sslmode, "verify-full")
	}
}

// TestPgConfigFromMap_MissingRequired verifies that each required field produces an error.
func TestPgConfigFromMap_MissingRequired(t *testing.T) {
	base := map[string]any{
		"host":            "10.0.0.1",
		"dbname":          "mydb",
		"admin_secret_id": "secret-uuid-1",
		"admin_username":  "postgres",
		"target_role":     "app_user",
	}
	required := []string{"host", "dbname", "admin_secret_id", "admin_username", "target_role"}
	for _, field := range required {
		t.Run("missing_"+field, func(t *testing.T) {
			m := make(map[string]any, len(base))
			for k, v := range base {
				m[k] = v
			}
			delete(m, field)
			_, err := pgConfigFromMap(m)
			if err == nil {
				t.Errorf("expected error when %q is missing, got nil", field)
			}
		})
	}
}

// TestBuildAdminDSN_Shape verifies the admin DSN contains expected fields.
func TestBuildAdminDSN_Shape(t *testing.T) {
	conf := pgConf{
		host:          "db.example.com",
		port:          5432,
		dbname:        "mydb",
		sslmode:       "require",
		adminUsername: "postgres",
		adminSecretID: "secret-uuid-1",
		targetRole:    "app_user",
	}
	dsn := buildAdminDSN(conf, "s3cr3t")
	for _, want := range []string{"db.example.com", "5432", "mydb", "postgres", "require", "s3cr3t"} {
		if !strings.Contains(dsn, want) {
			t.Errorf("admin DSN missing %q; got: %q", want, dsn)
		}
	}
}

// TestBuildTargetDSN_Shape verifies the target DSN contains expected fields.
func TestBuildTargetDSN_Shape(t *testing.T) {
	conf := pgConf{
		host:          "db.example.com",
		port:          5433,
		dbname:        "appdb",
		sslmode:       "verify-full",
		adminUsername: "postgres",
		adminSecretID: "sec-1",
		targetRole:    "webapp",
	}
	dsn := buildTargetDSN(conf, "newpass123")
	for _, want := range []string{"db.example.com", "5433", "appdb", "webapp", "verify-full", "newpass123"} {
		if !strings.Contains(dsn, want) {
			t.Errorf("target DSN missing %q; got: %q", want, dsn)
		}
	}
}

// TestBuildAdminDSN_SpecialChars verifies that a password with special characters
// is safely embedded in the key=value conninfo without breaking parsing.
// pgQuoteConnValue wraps the value in single quotes and backslash-escapes ' and \.
func TestBuildAdminDSN_SpecialChars(t *testing.T) {
	conf := pgConf{
		host:          "localhost",
		port:          5432,
		dbname:        "testdb",
		sslmode:       "require",
		adminUsername: "admin",
		adminSecretID: "s1",
		targetRole:    "role",
	}
	// Password with single quote, backslash, and space — all troublesome in conninfo.
	pw := `p'ass\w ord`
	dsn := buildAdminDSN(conf, pw)
	// The raw password must be in the DSN (after escaping) without the DSN
	// being broken — check that the DSN is a key=value form.
	if !strings.HasPrefix(dsn, "host=") {
		t.Errorf("expected key=value conninfo, got: %q", dsn)
	}
	// The escaped form must contain the backslash-escaped single quote.
	if !strings.Contains(dsn, `\'`) {
		t.Errorf("expected escaped single quote in DSN, got: %q", dsn)
	}
}

// TestPgQuoteConnValue verifies the conninfo value quoting rules:
//   - plain value → wrapped in single quotes
//   - single quotes inside → backslash-escaped
//   - backslashes inside → backslash-escaped
func TestPgQuoteConnValue(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"simple", "'simple'"},
		{"with space", "'with space'"},
		{"it's", `'it\'s'`},
		{`back\slash`, `'back\\slash'`},
		{`both'and\`, `'both\'and\\'`},
		{"", "''"},
	}
	for _, tc := range cases {
		got := pgQuoteConnValue(tc.input)
		if got != tc.want {
			t.Errorf("pgQuoteConnValue(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
