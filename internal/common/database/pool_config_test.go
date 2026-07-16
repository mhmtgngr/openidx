package database

import (
	"testing"
	"time"
)

const testDSN = "postgres://u:p@localhost:5432/openidx?sslmode=disable"

func TestEnvDuration(t *testing.T) {
	cases := []struct {
		name string
		set  bool
		val  string
		def  time.Duration
		want time.Duration
	}{
		{"unset uses default", false, "", 5 * time.Second, 5 * time.Second},
		{"valid parses", true, "12s", 5 * time.Second, 12 * time.Second},
		{"zero is honored", true, "0s", 5 * time.Second, 0},
		{"negative falls back", true, "-3s", 5 * time.Second, 5 * time.Second},
		{"garbage falls back", true, "notaduration", 5 * time.Second, 5 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const key = "TEST_ENV_DURATION_KNOB"
			if tc.set {
				t.Setenv(key, tc.val)
			} else {
				t.Setenv(key, "") // ensure unset/empty
			}
			if got := envDuration(key, tc.def); got != tc.want {
				t.Fatalf("envDuration(%q, %v) = %v, want %v", tc.val, tc.def, got, tc.want)
			}
		})
	}
}

// TestBuildPoolConfigConnectTimeoutDefault proves the availability belt: even
// with no env override, a dial is bounded (not pgx's default of 0 = unbounded),
// so a failover can't hang a reconnect indefinitely.
func TestBuildPoolConfigConnectTimeoutDefault(t *testing.T) {
	cfg, err := buildPoolConfig(testDSN)
	if err != nil {
		t.Fatalf("buildPoolConfig: %v", err)
	}
	if cfg.ConnConfig.ConnectTimeout != 5*time.Second {
		t.Fatalf("default ConnectTimeout = %v, want 5s", cfg.ConnConfig.ConnectTimeout)
	}
	// statement_timeout must be OFF by default (no surprise query aborts).
	if v, ok := cfg.ConnConfig.RuntimeParams["statement_timeout"]; ok {
		t.Fatalf("statement_timeout should be unset by default, got %q", v)
	}
}

func TestBuildPoolConfigConnectTimeoutOverride(t *testing.T) {
	t.Setenv("DB_CONNECT_TIMEOUT", "2s")
	cfg, err := buildPoolConfig(testDSN)
	if err != nil {
		t.Fatalf("buildPoolConfig: %v", err)
	}
	if cfg.ConnConfig.ConnectTimeout != 2*time.Second {
		t.Fatalf("ConnectTimeout = %v, want 2s", cfg.ConnConfig.ConnectTimeout)
	}
}

// TestBuildPoolConfigStatementTimeout proves the opt-in per-statement timeout is
// passed to Postgres as a runtime parameter in milliseconds.
func TestBuildPoolConfigStatementTimeout(t *testing.T) {
	t.Setenv("DB_STATEMENT_TIMEOUT", "30s")
	cfg, err := buildPoolConfig(testDSN)
	if err != nil {
		t.Fatalf("buildPoolConfig: %v", err)
	}
	got := cfg.ConnConfig.RuntimeParams["statement_timeout"]
	if got != "30000" {
		t.Fatalf("statement_timeout = %q, want \"30000\" (ms)", got)
	}
}

// TestBuildPoolConfigPreservesPoolSizing is a guard so the timeout additions
// don't accidentally disturb the carefully-sized pool defaults.
func TestBuildPoolConfigPreservesPoolSizing(t *testing.T) {
	cfg, err := buildPoolConfig(testDSN)
	if err != nil {
		t.Fatalf("buildPoolConfig: %v", err)
	}
	if cfg.MaxConns != 10 {
		t.Fatalf("MaxConns = %d, want 10", cfg.MaxConns)
	}
	if cfg.MinConns != 2 {
		t.Fatalf("MinConns = %d, want 2", cfg.MinConns)
	}
	if cfg.HealthCheckPeriod != time.Minute {
		t.Fatalf("HealthCheckPeriod = %v, want 1m", cfg.HealthCheckPeriod)
	}
}
