package testsupport

import "testing"

func TestPostgresDSNPrefersTheCanonicalName(t *testing.T) {
	t.Setenv(PostgresEnv, "")
	t.Setenv(LegacyPostgresEnv, "")
	if got := PostgresDSN(); got != "" {
		t.Fatalf("PostgresDSN() = %q with neither variable set, want empty", got)
	}

	t.Setenv(LegacyPostgresEnv, "postgres://legacy/db")
	if got := PostgresDSN(); got != "postgres://legacy/db" {
		t.Fatalf("PostgresDSN() = %q, want the deprecated alias honoured when %s is unset", got, PostgresEnv)
	}

	t.Setenv(PostgresEnv, "postgres://canonical/db")
	if got := PostgresDSN(); got != "postgres://canonical/db" {
		t.Fatalf("PostgresDSN() = %q, want %s to win over the alias", got, PostgresEnv)
	}
}

func TestScratchDatabaseWithNoServerFallsBack(t *testing.T) {
	t.Setenv(SuperuserPostgresEnv, "")
	t.Setenv(PostgresEnv, "")
	t.Setenv(LegacyPostgresEnv, "")
	if dsn, ok := ScratchDatabase(t); ok || dsn != "" {
		t.Fatalf("ScratchDatabase() = (%q, %v) with no server configured, want the container fallback", dsn, ok)
	}
}

func TestWithDatabaseKeepsEverythingButTheName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"postgres://u:p@127.0.0.1:5432/base?sslmode=disable", "postgres://u:p@127.0.0.1:5432/openidx_t_x?sslmode=disable"},
		{"postgresql://u@h/base", "postgresql://u@h/openidx_t_x"},
		{"host=h user=u dbname=base sslmode=disable", "host=h user=u sslmode=disable dbname=openidx_t_x"},
		{"host=h user=u", "host=h user=u dbname=openidx_t_x"},
	}
	for _, c := range cases {
		got, err := withDatabase(c.in, "openidx_t_x")
		if err != nil {
			t.Fatalf("withDatabase(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("withDatabase(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
