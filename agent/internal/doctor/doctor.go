package doctor

import (
	"context"
	"fmt"
	"os"
	"time"
)

// RunDeadline bounds a whole run.
const RunDeadline = 25 * time.Second

// Options tunes a run; the zero value is right outside tests.
type Options struct {
	ReadFile func(string) ([]byte, error)
}

// Run performs every check and returns the bundle. It always lists the ten
// checks in CheckOrder: one that cannot run is skipped, never left out.
func Run(ctx context.Context, in Inputs, p Probes, opt Options) Bundle {
	if opt.ReadFile == nil {
		opt.ReadFile = os.ReadFile
	}
	ctx, cancel := context.WithTimeout(ctx, RunDeadline)
	defer cancel()

	b := NewBundle(in.AgentID, in.AgentVersion, p.Now())
	b.Tunnel = in.Tunnel
	b.Enrollment = Enrollment{Enrolled: in.Enrolled, AuthInvalid: in.AuthInvalid, Revoked: in.Revoked}

	add := func(id string, fn func() Check) Check {
		c := guarded(id, fn)
		b.Checks = append(b.Checks, c)
		return c
	}
	skip := func(id, why string) {
		b.Checks = append(b.Checks, Check{ID: id, Status: StatusSkipped, Detail: why})
	}

	add(CheckConfig, func() Check { return checkConfig(in) })
	add(CheckCredentials, func() Check { return checkCredentials(in) })

	t, terr := parseServer(in.ServerURL)
	if in.ServerURL == "" || terr != nil {
		for _, id := range []string{CheckDNS, CheckTCP, CheckTLS, CheckHTTP, CheckClock} {
			skip(id, "no server configured")
		}
	} else {
		b.Net.ProxyMode, b.Net.ProxyHost = proxyInfo(in.ProxyURL, p.Proxy(in.ServerURL))
		viaProxy := b.Net.ProxyMode != "none"

		dns := Check{ID: CheckDNS, Status: StatusSkipped}
		if !viaProxy {
			dns = add(CheckDNS, func() Check { return checkDNS(ctx, p, t) })
		}
		b.Net.DNSOK = dns.Status != StatusFail
		switch {
		case viaProxy:
			// The proxy resolves and dials for us: a direct lookup or dial
			// says nothing about the path the agent really takes.
			skip(CheckDNS, "via proxy")
			skip(CheckTCP, "via proxy")
			skip(CheckTLS, "via proxy")
		case dns.Status == StatusFail:
			skip(CheckTCP, "name does not resolve")
			skip(CheckTLS, "name does not resolve")
		default:
			tcp := add(CheckTCP, func() Check { return checkTCP(ctx, p, t) })
			if tcp.Status == StatusFail {
				skip(CheckTLS, "no connection")
			} else {
				add(CheckTLS, func() Check { return checkTLS(ctx, p, t) })
			}
		}

		var res *HTTPResult
		add(CheckHTTP, func() Check {
			c, r := checkHTTP(ctx, p, in.ServerURL)
			res = r
			return c
		})
		add(CheckClock, func() Check {
			c, skew := checkClock(p, res)
			b.ClockSkewS = skew
			return c
		})
	}

	add(CheckIdentity, func() Check {
		c, notAfter := checkIdentity(in, opt.ReadFile, p.Now())
		b.Enrollment.CertNotAfter = notAfter
		return c
	})
	add(CheckService, func() Check { return checkService(in) })
	add(CheckTunnel, func() Check { return checkTunnel(in) })
	return b
}

// guarded times a check and turns a panic into a failed check, so one broken
// check cannot take the diagnosis down with it.
func guarded(id string, fn func() Check) (c Check) {
	start := time.Now()
	defer func() {
		if r := recover(); r != nil {
			c = Check{ID: id, Status: StatusFail, Code: CodeInternal, Detail: clip(fmt.Sprint(r))}
		}
		c.Millis = time.Since(start).Milliseconds()
	}()
	return fn()
}
