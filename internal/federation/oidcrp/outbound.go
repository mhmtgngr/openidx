package oidcrp

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/openidx/openidx/internal/common/netutil"
)

// AllowLoopbackEnv names the switch that lets a relying party reach an
// issuer on the loopback interface. It exists for tests and single-host
// development; production leaves it unset, so an administrator who types
// http://127.0.0.1:8200 as an issuer does not turn the sign-in path into a
// client of the platform's own services.
const AllowLoopbackEnv = "OIDCRP_ALLOW_LOOPBACK"

const maxRedirects = 5

func loopbackAllowed() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("OIDCRP_ALLOW_LOOPBACK")))
	return v == "1" || v == "true" || v == "yes"
}

// GuardedClient is the HTTP client a Discoverer uses when none is given.
// Every connection goes through netutil's outbound guard (the decision
// OIDX_OUTBOUND_ALLOWLIST governs for webhooks and SCIM): the name is
// resolved once, every address must be public or allowlisted, and the
// checked address is the one dialed, so DNS rebinding does not reach the
// metadata endpoint or an internal service. The discovery document's own
// token_endpoint and jwks_uri go through the same client. Redirects are
// followed only to https (or allowed loopback) targets, each hop dialed
// through the guard again.
func GuardedClient() (*http.Client, error) {
	raw := os.Getenv("OIDX_OUTBOUND_ALLOWLIST")
	if loopbackAllowed() {
		if raw != "" {
			raw += ","
		}
		raw += "127.0.0.0/8,::1/128,localhost"
	}
	allow, err := netutil.ParseAllowlist(raw)
	guard := netutil.NewOutboundGuard(allow)
	c := guard.Client(defaultHTTPTimeout)
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return errors.New("oidcrp: too many redirects")
		}
		if err := checkIssuerURL(req.URL.Scheme + "://" + req.URL.Host + req.URL.Path); err != nil {
			return fmt.Errorf("oidcrp: redirect refused: %w", err)
		}
		return nil
	}
	return c, err
}
