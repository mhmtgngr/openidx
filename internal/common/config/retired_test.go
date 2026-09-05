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
func TestRetiredSettingsHaveNoBindingOrDefault(t *testing.T) {
	source, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatalf("read config.go: %v", err)
	}
	text := string(source)
	for _, name := range RetiredSettingNames() {
		key := strings.ToLower(name) // the viper key these were bound under
		for _, forbidden := range []string{
			`v.SetDefault("` + key + `"`,
			`"` + key + `":` + ` "` + name + `"`,
			`mapstructure:"` + key + `"`,
		} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s is retired but config.go still contains %s", name, forbidden)
			}
		}
	}
}

// And the route that made them visible to an operator who never read the Go:
// a line in a config file the services load from ./configs.
func TestRetiredSettingsAreNotInShippedConfigs(t *testing.T) {
	files, err := filepath.Glob("../../../configs/*.yaml")
	if err != nil {
		t.Fatalf("glob configs: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no configs/*.yaml found; this test would pass vacuously")
	}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(body), "\n") {
			for _, name := range RetiredSettingNames() {
				if strings.HasPrefix(strings.TrimSpace(line), strings.ToLower(name)+":") {
					t.Errorf("%s:%d offers the retired setting %s: %q", f, i+1, name, strings.TrimSpace(line))
				}
			}
		}
	}
}
