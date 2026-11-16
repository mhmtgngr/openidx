package doctor

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/openidx/openidx/agent/internal/tunnel"
)

// IdentityExpiryWarn is how long before expiry the identity check warns.
const IdentityExpiryWarn = 14 * 24 * time.Hour

// Inputs is what the caller already knows about this device. The CLI fills it
// from agent.json and the status pipe; the service can fill it in-process.
type Inputs struct {
	AgentID      string
	AgentVersion string
	ServerURL    string
	// ProxyURL is the proxy configured in agent.json, if any.
	ProxyURL string
	// ConfigErr is why agent.json could not be read, if it could not.
	ConfigErr   error
	Enrolled    bool
	AuthInvalid bool
	Revoked     bool
	// IdentityFile is the Ziti identity the agent expects; "" means none.
	IdentityFile string
	// TunnelExpected says the tunnel is enabled for this device.
	TunnelExpected bool
	// Tunnel is the tunnel's own report; nil means unknown.
	Tunnel *tunnel.Status
	// ServiceRunning is nil when it cannot be told.
	ServiceRunning *bool
}

func checkConfig(in Inputs) Check {
	c := Check{ID: CheckConfig, Status: StatusPass}
	switch {
	case in.ConfigErr != nil && errors.Is(in.ConfigErr, fs.ErrPermission):
		c.Status, c.Code = StatusFail, CodeConfigUnreadable
	case !in.Enrolled:
		c.Status, c.Code = StatusFail, CodeNotEnrolled
	}
	return c
}

func checkCredentials(in Inputs) Check {
	c := Check{ID: CheckCredentials, Status: StatusPass}
	switch {
	case in.Revoked:
		c.Status, c.Code = StatusFail, CodeDeviceRevoked
	case in.AuthInvalid:
		c.Status, c.Code = StatusFail, CodeAuthInvalid
	case !in.Enrolled:
		c.Status, c.Detail = StatusSkipped, "not enrolled"
	}
	return c
}

// checkIdentity reads the Ziti identity file's certificate (never its key)
// and reports when it expires.
func checkIdentity(in Inputs, readFile func(string) ([]byte, error), now time.Time) (Check, *time.Time) {
	c := Check{ID: CheckIdentity, Status: StatusPass}
	if in.IdentityFile == "" {
		c.Status, c.Detail = StatusSkipped, "no identity expected"
		return c, nil
	}
	notAfter, err := identityNotAfter(in.IdentityFile, readFile)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrPermission):
		c.Status, c.Detail = StatusSkipped, "needs elevation"
		return c, nil
	case errors.Is(err, fs.ErrNotExist):
		c.Status, c.Code = StatusFail, CodeIdentityMissing
		return c, nil
	default:
		c.Status, c.Code = StatusFail, CodeIdentityInvalid
		return c, nil
	}
	switch left := notAfter.Sub(now); {
	case left <= 0:
		c.Status, c.Code = StatusFail, CodeIdentityExpired
	case left < IdentityExpiryWarn:
		c.Status, c.Code = StatusWarn, CodeIdentityExpiring
	}
	c.Detail = "expires " + notAfter.UTC().Format("2006-01-02")
	return c, &notAfter
}

func identityNotAfter(path string, readFile func(string) ([]byte, error)) (time.Time, error) {
	raw, err := readFile(path)
	if err != nil {
		return time.Time{}, err
	}
	var doc struct {
		ID struct {
			Cert string `json:"cert"`
		} `json:"id"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return time.Time{}, fmt.Errorf("identity file is not JSON")
	}
	certPEM := []byte(strings.TrimPrefix(doc.ID.Cert, "pem:"))
	if ref, ok := strings.CutPrefix(doc.ID.Cert, "file:"); ok {
		if certPEM, err = readFile(strings.TrimPrefix(ref, "//")); err != nil {
			return time.Time{}, err
		}
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}, fmt.Errorf("identity holds no certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("identity certificate does not parse")
	}
	return cert.NotAfter, nil
}

func checkService(in Inputs) Check {
	c := Check{ID: CheckService, Status: StatusPass}
	switch {
	case in.ServiceRunning == nil:
		c.Status, c.Detail = StatusSkipped, "cannot tell from here"
	case !*in.ServiceRunning:
		c.Status, c.Code = StatusFail, CodeServiceNotRunning
	}
	return c
}

func checkTunnel(in Inputs) Check {
	c := Check{ID: CheckTunnel, Status: StatusPass}
	if !in.Enrolled {
		c.Status, c.Detail = StatusSkipped, "not enrolled"
		return c
	}
	if !in.TunnelExpected && (in.Tunnel == nil || in.Tunnel.State == tunnel.StateOff) {
		c.Status, c.Code = StatusWarn, CodeTunnelOff
		return c
	}
	if in.Tunnel == nil {
		c.Status, c.Detail = StatusSkipped, "cannot tell from here"
		return c
	}
	switch in.Tunnel.State {
	case tunnel.StateConnected:
		c.Detail = fmt.Sprintf("%d services", len(in.Tunnel.Services))
	case tunnel.StateNotInstalled:
		c.Status, c.Code = StatusFail, CodeTunnelNotInstalled
	case tunnel.StateOff:
		// Enabled in agent.json and off in fact: it should be running.
		c.Status, c.Code = StatusFail, CodeTunnelDown
	default:
		c.Status, c.Code, c.Detail = StatusFail, CodeTunnelDown, clip(in.Tunnel.LastError)
	}
	return c
}
