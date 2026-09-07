package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A retired setting has exactly one job: to say it is retired. These tests
// keep it from coming back by the two routes it left by — a struct binding
// with a default, and a line in a shipped config file — because either one
// makes it look live again to the operator reading it.

func TestRetiredSettingsAreReportedWhenSet(t *testing.T) {
	for _, name := range RetiredSettingNames() {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "false")
			lines := RetiredSettingsInUse()
			var found string
			for _, l := range lines {
				if strings.HasPrefix(l, name+" ") {
					found = l
				}
			}
			if found == "" {
				t.Fatalf("%s is set but RetiredSettingsInUse() returned %v", name, lines)
			}
			// The reason is the whole point: a line that names the variable and
			// stops has told the operator nothing they did not already know.
			if len(found) < len(name)+40 {
				t.Fatalf("%s reports without a reason: %q", name, found)
			}
		})
	}
}

func TestRetiredSettingsAreSilentWhenUnset(t *testing.T) {
	for _, name := range RetiredSettingNames() {
		if v, ok := os.LookupEnv(name); ok {
			t.Setenv(name, v) // restored by t.Setenv's cleanup
			os.Unsetenv(name)
		}
	}
	if got := RetiredSettingsInUse(); len(got) != 0 {
		t.Fatalf("no retired setting is set; want no report, got %v", got)
	}
}

// The route ENABLE_MFA and ENABLE_AUDIT_LOGGING actually took: a viper default
// plus a mapstructure field, which made `enable_mfa: true` look like a setting
// that did something.
//
// The key is the register's, not the name lowercased. A nested setting is
// bound under a dotted key ("sms.otp_length") whose struct tag is only the leaf
// ("otp_length"), so deriving the key from the variable name would have looked
// for `mapstructure:"sms_otp_length"`, found nothing, and passed while the field
// was still there.
func TestRetiredSettingsHaveNoBindingOrDefault(t *testing.T) {
	source, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatalf("read config.go: %v", err)
	}
	text := string(source)
	for _, name := range RetiredSettingNames() {
		key := RetiredSettingKey(name)
		if key == "" {
			t.Errorf("%s is retired with no viper key; the binding and default checks below cannot run", name)
			continue
		}
		leaf := key
		if i := strings.LastIndex(key, "."); i >= 0 {
			leaf = key[i+1:]
		}
		for _, forbidden := range []string{
			`v.SetDefault("` + key + `"`,
			`"` + key + `":`,
			`mapstructure:"` + leaf + `"`,
		} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s is retired but config.go still contains %s", name, forbidden)
			}
		}
	}
}

// And the route that made them visible to an operator who never read the Go: a
// line in something they copy and edit.
//
// The set is every operator-facing configuration surface this repository ships,
// not just ./configs — which is now empty, because the one file in it was named
// after a service while the loader looks only for config.yaml, so nothing could
// ever read it. A file an operator edits and a process never opens is the same
// defect one level up.
func TestRetiredSettingsAreNotInShippedConfigs(t *testing.T) {
	var files []string
	for _, pattern := range []string{
		"../../../configs/*.yaml",
		"../../../.env.example",
		"../../../deployments/docker/.env.production",
		"../../../deployments/apisix-edge/*.example",
		"../../../dev-kube/*.yaml",
	} {
		matched, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		files = append(files, matched...)
	}
	if len(files) == 0 {
		t.Fatal("no shipped configuration surfaces found; this test would pass vacuously")
	}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(body), "\n") {
			trimmed := strings.TrimSpace(line)
			for _, name := range RetiredSettingNames() {
				key := RetiredSettingKey(name)
				leaf := key
				if j := strings.LastIndex(key, "."); j >= 0 {
					leaf = key[j+1:]
				}
				// Two shapes, because the surfaces come in two shapes: a YAML
				// key (`fcm_server_key:`) and an environment assignment
				// (`JWT_SECRET=`). Checking only the first would pass over every
				// .env file in the list without reading a thing.
				if strings.HasPrefix(trimmed, leaf+":") || strings.HasPrefix(trimmed, name+"=") {
					t.Errorf("%s:%d offers the retired setting %s: %q", f, i+1, name, trimmed)
				}
			}
		}
	}
}
