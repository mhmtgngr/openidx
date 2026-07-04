package credentials

import (
	"strings"
	"testing"
)

func TestMySQLQuoteLiteral(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"single quote", `a'b`, `'a\'b'`},
		{"backslash", `a\b`, `'a\\b'`},
		{"combined", `a'b\c`, `'a\'b\\c'`},
		{"plain", `hunter2`, `'hunter2'`},
		{"empty", ``, `''`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mysqlQuoteLiteral(tc.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("mysqlQuoteLiteral(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestMySQLQuoteLiteralNUL(t *testing.T) {
	if _, err := mysqlQuoteLiteral("a\x00b"); err == nil {
		t.Fatal("expected error for NUL byte, got nil")
	}
}

func baseMySQLCfg() map[string]any {
	return map[string]any{
		"host":            "db.example.com",
		"admin_secret_id": "sec-1",
		"admin_username":  "root",
		"target_user":     "svc_app",
	}
}

func TestMySQLConfigIdentifierValidation(t *testing.T) {
	// target_user rejections.
	badUsers := []string{"`admin`; DROP", "app user", "bob'--", "a\"b", "user;", ""}
	for _, u := range badUsers {
		cfg := baseMySQLCfg()
		cfg["target_user"] = u
		if _, err := mysqlConfigFromMap(cfg); err == nil {
			t.Errorf("expected rejection for target_user %q", u)
		}
	}

	// target_host rejections.
	badHosts := []string{"host name", "1.2.3.4'; DROP", `h"o`}
	for _, h := range badHosts {
		cfg := baseMySQLCfg()
		cfg["target_host"] = h
		if _, err := mysqlConfigFromMap(cfg); err == nil {
			t.Errorf("expected rejection for target_host %q", h)
		}
	}

	// accepted users.
	for _, u := range []string{"svc_app", "app-1", "user.name", "app%"} {
		cfg := baseMySQLCfg()
		cfg["target_user"] = u
		if _, err := mysqlConfigFromMap(cfg); err != nil {
			t.Errorf("expected accept for target_user %q, got %v", u, err)
		}
	}

	// accepted hosts.
	for _, h := range []string{"%", "10.0.0.1", "localhost", "10.0.%"} {
		cfg := baseMySQLCfg()
		cfg["target_host"] = h
		if _, err := mysqlConfigFromMap(cfg); err != nil {
			t.Errorf("expected accept for target_host %q, got %v", h, err)
		}
	}
}

func TestMySQLConfigDefaults(t *testing.T) {
	conf, err := mysqlConfigFromMap(baseMySQLCfg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.port != 3306 {
		t.Errorf("port default = %d, want 3306", conf.port)
	}
	if conf.targetHost != "%" {
		t.Errorf("target_host default = %q, want %%", conf.targetHost)
	}
}

func TestMySQLConfigRequiredFields(t *testing.T) {
	for _, missing := range []string{"host", "admin_secret_id", "admin_username", "target_user"} {
		cfg := baseMySQLCfg()
		delete(cfg, missing)
		_, err := mysqlConfigFromMap(cfg)
		if err == nil {
			t.Errorf("expected error when %q missing", missing)
			continue
		}
		if !strings.Contains(err.Error(), missing) {
			t.Errorf("error for missing %q = %v, want mention of field", missing, err)
		}
	}
}

func TestMySQLConfigPortParsing(t *testing.T) {
	cases := []struct {
		name string
		raw  any
		want int
	}{
		{"int", 3307, 3307},
		{"float64", float64(3308), 3308},
		{"string", "3309", 3309},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseMySQLCfg()
			cfg["port"] = tc.raw
			conf, err := mysqlConfigFromMap(cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if conf.port != tc.want {
				t.Fatalf("port = %d, want %d", conf.port, tc.want)
			}
		})
	}

	cfg := baseMySQLCfg()
	cfg["port"] = "notanumber"
	if _, err := mysqlConfigFromMap(cfg); err == nil {
		t.Fatal("expected error for invalid string port")
	}
}
