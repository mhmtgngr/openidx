package doctor

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// configProbePath answers 401 without credentials: reaching it proves the
// path to the server, and its Date header gives the server's clock.
const configProbePath = "/api/v1/access/agent/config"

// target is the server address the network checks aim at.
type target struct {
	Host     string
	Port     string
	HostPort string
	IsIP     bool
}

func parseServer(serverURL string) (target, error) {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil {
		return target{}, err
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return target{}, fmt.Errorf("server URL is not an http(s) URL")
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	host := u.Hostname()
	return target{
		Host:     host,
		Port:     port,
		HostPort: net.JoinHostPort(host, port),
		IsIP:     net.ParseIP(host) != nil,
	}, nil
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func checkDNS(ctx context.Context, p Probes, t target) Check {
	c := Check{ID: CheckDNS, Status: StatusPass}
	if t.IsIP {
		c.Status, c.Detail = StatusSkipped, "address is an IP"
		return c
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	addrs, err := p.Resolve(ctx, t.Host)
	switch {
	case err != nil && isTimeout(err):
		c.Status, c.Code = StatusFail, CodeDNSTimeout
	case err != nil || len(addrs) == 0:
		c.Status, c.Code = StatusFail, CodeDNSFail
	}
	if c.Status == StatusFail {
		c.Detail = t.Host
	}
	return c
}

func checkTCP(ctx context.Context, p Probes, t target) Check {
	c := Check{ID: CheckTCP, Status: StatusPass}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if err := p.DialTCP(ctx, t.HostPort); err != nil {
		c.Status, c.Code, c.Detail = StatusFail, CodeTCPBlocked, t.HostPort
		if isTimeout(err) {
			c.Code = CodeTCPTimeout
		}
	}
	return c
}

func checkTLS(ctx context.Context, p Probes, t target) Check {
	c := Check{ID: CheckTLS, Status: StatusPass}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	err := p.TLSHandshake(ctx, t.HostPort, t.Host)
	if err == nil {
		return c
	}
	c.Status, c.Code = StatusFail, CodeTLSFail
	var (
		unknown  x509.UnknownAuthorityError
		hostname x509.HostnameError
		invalid  x509.CertificateInvalidError
	)
	if errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		c.Code = CodeTLSUntrusted
	}
	return c
}

func checkHTTP(ctx context.Context, p Probes, serverURL string) (Check, *HTTPResult) {
	c := Check{ID: CheckHTTP, Status: StatusPass}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	res, err := p.HTTPGet(ctx, strings.TrimRight(strings.TrimSpace(serverURL), "/")+configProbePath)
	if err != nil {
		c.Status, c.Code = StatusFail, CodeHTTPFail
		if isTimeout(err) {
			c.Code = CodeHTTPTimeout
		}
		return c, nil
	}
	switch {
	case res.Status == 407:
		c.Status, c.Code = StatusFail, CodeProxyAuthRequired
	case res.Status >= 500:
		c.Status, c.Code, c.Detail = StatusFail, CodeServerHTTPError, fmt.Sprintf("status %d", res.Status)
	}
	return c, &res
}

// checkClock compares the device clock with the server's Date header. The
// returned skew is in seconds, positive when the device is ahead.
func checkClock(p Probes, r *HTTPResult) (Check, *int64) {
	c := Check{ID: CheckClock, Status: StatusPass}
	if r == nil || r.Date.IsZero() {
		c.Status, c.Detail = StatusSkipped, "server time unknown"
		return c, nil
	}
	skew := p.Now().Sub(r.Date)
	secs := int64(skew.Seconds())
	if skew > MaxClockSkew || skew < -MaxClockSkew {
		c.Status, c.Code, c.Detail = StatusFail, CodeClockSkew, fmt.Sprintf("%ds", secs)
	}
	return c, &secs
}

// proxyInfo names how the server is reached and through which proxy. Only
// host:port is kept: a proxy URL may carry credentials.
func proxyInfo(configured string, inUse *url.URL) (mode, host string) {
	if inUse == nil {
		return "none", ""
	}
	host = inUse.Host
	switch {
	case strings.TrimSpace(configured) != "":
		return "configured", host
	case envProxySet():
		return "environment", host
	default:
		return "system", host
	}
}

func envProxySet() bool {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if strings.TrimSpace(os.Getenv(k)) != "" {
			return true
		}
	}
	return false
}
