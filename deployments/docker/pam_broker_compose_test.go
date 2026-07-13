// Package docker — structural guard for the PAM dedicated-broker compose overlay.
package docker

import (
	"os"
	"strings"
	"testing"
)

// TestPamBrokerComposeStructure validates that the pam-broker overlay declares
// both brokers, the shared recordings volume, the dedicated postgres, and wires
// the access-service to both broker URLs. It is a text/structure check (a real
// `docker compose config` merge is exercised in CI/manually — see
// README.pam-broker.md).
func TestPamBrokerComposeStructure(t *testing.T) {
	content, err := os.ReadFile("docker-compose.pam-broker.yml")
	if err != nil {
		t.Fatalf("failed to read docker-compose.pam-broker.yml: %v", err)
	}
	s := string(content)

	// Both brokers + the dedicated postgres + the tunnel sidecar.
	for _, svc := range []string{
		"pam-guac-postgres:",
		"pam-guacd:",
		"pam-guacamole:",
		"pam-guacd-ziti:",
		"pam-guacamole-ziti:",
		"pam-ziti-tunnel:",
	} {
		if !strings.Contains(s, svc) {
			t.Errorf("pam-broker overlay is missing service %q", svc)
		}
	}

	// The tunnel must share the ziti guacd's network namespace so its loopback
	// binds are the addresses guacd dials.
	if !strings.Contains(s, `network_mode: "service:pam-guacd-ziti"`) {
		t.Error("pam-ziti-tunnel must share pam-guacd-ziti's network namespace")
	}

	// The access-service must be pointed at BOTH brokers and share recordings.
	for _, env := range []string{
		"GUACAMOLE_URL=http://pam-guacamole:8080/guacamole",
		"GUACAMOLE_ZITI_URL=http://pam-guacamole-ziti:8080/guacamole",
		"GUACAMOLE_RECORDING_PATH=/recordings",
	} {
		if !strings.Contains(s, env) {
			t.Errorf("access-service override is missing %q", env)
		}
	}

	// The shared recordings volume must be mounted into both guacd's and
	// access-service (three mounts), and declared as a named volume.
	if n := strings.Count(s, "pam_recordings:/recordings"); n < 3 {
		t.Errorf("pam_recordings must be mounted into both guacd's + access-service (>=3 mounts), found %d", n)
	}
	for _, vol := range []string{"pam_recordings:", "pam_guac_pgdata:"} {
		if !strings.Contains(s, vol) {
			t.Errorf("named volume %q is not declared", vol)
		}
	}
}
