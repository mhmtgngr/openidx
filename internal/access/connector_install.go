package access

// Serves the connector installer script (deployments/scripts/
// connector-install.sh) unauthenticated, like the agent downloads: the host
// that runs it has no credentials yet — the enrollment JWT in the command line
// is the entitlement. The script is embedded at build time from the copy in
// this package; connector-install.test.sh pins the two copies identical.

import (
	_ "embed"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed connector-install.sh
var connectorInstallScript []byte

// boxOrigin is the public origin this box is reached at, derived the same way
// the agent mirror derives its base: the OAuth issuer's origin, else
// PublicBaseURL; loopback origins are skipped. "" when nothing usable is set.
func (s *Service) boxOrigin() string {
	if s.config == nil {
		return ""
	}
	for _, raw := range []string{s.config.OAuthIssuer, s.config.PublicBaseURL} {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			continue
		}
		if isLoopbackHost(u.Hostname()) {
			continue
		}
		return u.Scheme + "://" + u.Host
	}
	return ""
}

// handleConnectorInstallScript serves GET /downloads/connector/install.sh.
func (s *Service) handleConnectorInstallScript(c *gin.Context) {
	c.Header("Content-Disposition", `inline; filename="install.sh"`)
	c.Data(http.StatusOK, "text/x-shellscript; charset=utf-8", connectorInstallScript)
}

// connectorInstallCommand is the copy-paste one-liner that fetches the
// installer from the box and runs it. origin is the public origin the box is
// reached at ("" when unknown — then the command is omitted). advertised is
// optional: without it the connector is outbound-only (private mode).
func connectorInstallCommand(origin, jwt, ctrlHost, ctrlPort, name, advertised string) string {
	if origin == "" {
		return ""
	}
	cmd := fmt.Sprintf("curl -fsS %s/api/v1/access/downloads/connector/install.sh | sudo bash -s -- --token '%s' --ctrl %s:%s --name %s",
		origin, jwt, ctrlHost, ctrlPort, name)
	if advertised != "" {
		cmd += " --advertised " + advertised
	}
	return cmd
}
