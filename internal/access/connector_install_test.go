package access

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/common/config"
)

// The embedded script must stay a byte-for-byte copy of the canonical one in
// deployments/scripts/, or the served installer drifts from the tested one.
func TestEmbeddedConnectorScriptMatchesDeployments(t *testing.T) {
	canonical, err := os.ReadFile(filepath.Join("..", "..", "deployments", "scripts", "connector-install.sh"))
	if err != nil {
		t.Fatalf("read canonical script: %v", err)
	}
	if string(canonical) != string(connectorInstallScript) {
		t.Fatal("internal/access/connector-install.sh differs from deployments/scripts/connector-install.sh; copy it over")
	}
}

// Without advertised_address the onboard command must be listener-less: no
// published 3022 and no ZITI_ROUTER_ADVERTISED_ADDRESS (private connector).
func TestRouterOnboardCommandListenerLess(t *testing.T) {
	cmd := routerOnboardCommand("priv-r1", "JWT", "ctrl.tdv.org", "1280", "", "1.6.12")
	for _, banned := range []string{"-p 3022:3022", "ZITI_ROUTER_ADVERTISED_ADDRESS", "ZITI_ROUTER_PORT"} {
		if strings.Contains(cmd, banned) {
			t.Errorf("listener-less command must not contain %q: %s", banned, cmd)
		}
	}
	for _, want := range []string{
		"-e ZITI_ENROLL_TOKEN='JWT'",
		"-e ZITI_CTRL_ADVERTISED_ADDRESS=ctrl.tdv.org",
		"-e ZITI_CTRL_ADVERTISED_PORT=1280",
		"-e ZITI_ROUTER_MODE=host",
		"-v priv-r1-data:/ziti-router",
		"openziti/ziti-router:1.6.12",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("command lacks %q: %s", want, cmd)
		}
	}
}

func TestConnectorInstallCommand(t *testing.T) {
	// The origin comes from the OAuth issuer's origin, like the agent mirror.
	s := &Service{config: &config.Config{OAuthIssuer: "https://id.tdv.org/api/v1/oauth"}}
	if got, want := s.boxOrigin(), "https://id.tdv.org"; got != want {
		t.Fatalf("boxOrigin() = %q, want %q", got, want)
	}

	cmd := connectorInstallCommand(s.boxOrigin(), "JWT", "ctrl.tdv.org", "1280", "site-a", "")
	wantPrefix := "curl -fsS https://id.tdv.org/api/v1/access/downloads/connector/install.sh | sudo bash -s -- --token 'JWT' --ctrl ctrl.tdv.org:1280 --name site-a"
	if cmd != wantPrefix {
		t.Errorf("private install_command = %q, want %q", cmd, wantPrefix)
	}
	if strings.Contains(cmd, "--advertised") {
		t.Error("private install_command must not carry --advertised")
	}

	pub := connectorInstallCommand(s.boxOrigin(), "JWT", "ctrl.tdv.org", "1280", "site-a", "192.0.2.4")
	if !strings.HasSuffix(pub, " --advertised 192.0.2.4") {
		t.Errorf("public install_command must end with --advertised: %q", pub)
	}

	// Loopback-only config yields no origin, so no install_command.
	loop := &Service{config: &config.Config{PublicBaseURL: "http://localhost:3000"}}
	if o := loop.boxOrigin(); o != "" {
		t.Errorf("loopback origin must be skipped, got %q", o)
	}
	if c := connectorInstallCommand("", "J", "h", "p", "n", ""); c != "" {
		t.Errorf("no origin must yield empty command, got %q", c)
	}
}
