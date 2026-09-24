package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func loadWith(t *testing.T, env map[string]string) (*Config, error) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
	for k, v := range env {
		t.Setenv(k, v)
	}
	return Load("test")
}

// The negative half: a value no gate recognises stops the service, and the
// error names the setting, so "ABAC_ENFORCE=enfroce" cannot pass for a working
// control while every gate reads it as off.
func TestUnrecognisedTriStateValueFailsStartup(t *testing.T) {
	for _, s := range triStateSettings {
		t.Run(s.env, func(t *testing.T) {
			_, err := loadWith(t, map[string]string{s.env: "enfroce"})
			if err == nil {
				t.Fatalf("%s=enfroce loaded without error; it would silently mean off", s.env)
			}
			if !strings.Contains(err.Error(), s.env) {
				t.Fatalf("error does not name %s: %v", s.env, err)
			}
		})
	}
}

// The positive half: every spelling a gate's parser accepts still loads, and
// so does the setting left empty.
func TestRecognisedTriStateValuesLoad(t *testing.T) {
	for _, s := range triStateSettings {
		for _, v := range []string{"off", "observe", "enforce", "ENFORCE", " Observe ", ""} {
			if _, err := loadWith(t, map[string]string{s.env: v}); err != nil {
				t.Fatalf("%s=%q should load: %v", s.env, v, err)
			}
		}
	}
}

// Every setting whose default is off, observe or enforce is in the list the
// validator walks. The list is derived from setDefaults rather than written
// twice, so a gate added later without an entry in triStateSettings fails here
// instead of reopening the gap this validation closes.
func TestTriStateListCoversEveryTriStateDefault(t *testing.T) {
	listed := map[string]bool{}
	for _, s := range triStateSettings {
		listed[s.env] = true
	}
	v := viper.New()
	setDefaults(v, "test")
	found := 0
	for _, key := range v.AllKeys() {
		switch strings.ToLower(fmt.Sprint(v.Get(key))) {
		case "off", "observe", "enforce":
			found++
			if env := strings.ToUpper(key); !listed[env] {
				t.Errorf("%s defaults to %q, so it is an off|observe|enforce setting, but triStateSettings does not check %s", key, v.Get(key), env)
			}
		}
	}
	if found < len(triStateSettings) {
		t.Errorf("found %d tri-state defaults but the list has %d entries; the derivation is not seeing them", found, len(triStateSettings))
	}
}

// The boolean enforcement switches need no list entry because Load already
// refuses a non-boolean value. Pin that, so a future config change that made
// "yes" quietly mean false would fail here.
func TestNonBooleanEnforcementSwitchFailsStartup(t *testing.T) {
	for _, env := range []string{"ACCESS_ASSIGNMENT_ENFORCE", "ENABLE_OPA_AUTHZ"} {
		for _, v := range []string{"yes", "on", "enforce"} {
			if _, err := loadWith(t, map[string]string{env: v}); err == nil {
				t.Errorf("%s=%q loaded without error; it must not silently mean false", env, v)
			}
		}
		cfg, err := loadWith(t, map[string]string{env: "true"})
		if err != nil {
			t.Fatalf("%s=true should load: %v", env, err)
		}
		on := map[string]bool{"ACCESS_ASSIGNMENT_ENFORCE": cfg.AccessAssignmentEnforce, "ENABLE_OPA_AUTHZ": cfg.EnableOPAAuthz}[env]
		if !on {
			t.Errorf("%s=true loaded as false", env)
		}
	}
}
