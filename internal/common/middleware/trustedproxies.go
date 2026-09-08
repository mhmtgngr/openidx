package middleware

import (
	"net"
	"os"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
)

// ConfigureTrustedProxies restricts which upstream hops gin will believe when it
// resolves the client IP from X-Forwarded-For.
//
// Why this matters (security): gin's DEFAULT trusts ALL proxies, so it reads the
// LEFTMOST X-Forwarded-For entry as the client IP. Since any HTTP client can send
// an arbitrary X-Forwarded-For header, c.ClientIP() is attacker-controllable by
// default. That IP feeds device-trust "known IP" auto-approval, geo/country
// blocking, risk scoring, rate limiting, and audit records — all of which become
// spoofable. An attacker could, for example, send "X-Forwarded-For: <corp IP>"
// to get an untrusted device auto-approved.
//
// In this deployment every service sits behind the edge (APISIX/nginx) and is
// reached over loopback (127.0.0.1). By trusting ONLY the loopback proxy, gin
// walks the XFF list right-to-left and stops at the first address that is NOT a
// trusted proxy — i.e. the real client IP that the edge appended via
// $proxy_add_x_forwarded_for — ignoring any client-supplied leftmost entries.
//
// The trusted set is overridable via OIDX_TRUSTED_PROXIES (comma-separated CIDRs
// or IPs) for deployments where the edge is not on loopback. Setting it to "*"
// restores gin's trust-all behavior (NOT recommended). An empty/unset value uses
// the secure loopback default.
//
// AND THE PREMISE ABOVE IS NOT TRUE OF THE DEPLOYMENTS THIS REPO SHIPS, which is
// why this function also mounts a detector. "Reached over loopback" describes a
// service and its edge sharing a network namespace. In deployments/docker the
// TLS proxy forwards with `proxy_pass http://oauth-service:8006` — one container
// to another — and under Helm an ingress pod forwards to a service pod. Both are
// non-loopback hops, and neither compose file, values.yaml nor .env.example set
// OIDX_TRUSTED_PROXIES.
//
// Measured, with only loopback trusted:
//
//	remote=127.0.0.1:5555   XFF="203.0.113.7"                -> ClientIP=203.0.113.7
//	remote=172.18.0.9:5555  XFF="203.0.113.7"                -> ClientIP=172.18.0.9
//	remote=172.18.0.9:5555  XFF="203.0.113.7, 172.18.0.9"    -> ClientIP=172.18.0.9
//
// So the hardening lands, in the shipped topology, as "ignore X-Forwarded-For
// entirely": nginx writes the client's address and the service discards it. That
// is safe against the spoof this function was written for and useless for
// everything its own comment says depends on the IP. Every request resolves to
// the proxy's address, so the per-IP rate-limit key becomes one bucket shared by
// every client (including the tighter auth-path bucket that exists to slow a
// brute force), audit records attribute every event to the proxy, and known-IP
// device-trust and geo-blocking compare against it.
//
// The default stays loopback: widening it by default would silently trust a
// forwarded header on any install whose services are directly reachable. What
// changes is that the mismatch is no longer silent. A request that arrives from
// an untrusted hop while carrying a forwarded client-IP header is reported —
// once per hop, with the address to add to OIDX_TRUSTED_PROXIES, and counted in
// openidx_forwarded_for_from_untrusted_hop_total so it shows up on a dashboard
// and not only in a log nobody reads.
func ConfigureTrustedProxies(router *gin.Engine, logger *zap.Logger) {
	proxies := defaultTrustedProxies()

	if env := strings.TrimSpace(os.Getenv("OIDX_TRUSTED_PROXIES")); env != "" {
		if env == "*" {
			// Explicit opt-out: trust all proxies (leftmost XFF). Loud warning.
			if logger != nil {
				logger.Warn("OIDX_TRUSTED_PROXIES=* : trusting ALL proxies; c.ClientIP() is spoofable via X-Forwarded-For")
			}
			if err := router.SetTrustedProxies(nil); err != nil && logger != nil {
				logger.Error("failed to clear trusted proxies", zap.Error(err))
			}
			// nil trusted proxies with default forwarded header still trusts all;
			// keep gin's default behavior by returning here.
			return
		}
		var parsed []string
		for _, p := range strings.Split(env, ",") {
			if p = strings.TrimSpace(p); p != "" {
				parsed = append(parsed, p)
			}
		}
		if len(parsed) > 0 {
			proxies = parsed
		}
	}

	if err := router.SetTrustedProxies(proxies); err != nil {
		if logger != nil {
			logger.Error("failed to set trusted proxies; falling back to loopback only", zap.Error(err))
		}
		proxies = defaultTrustedProxies()
		_ = router.SetTrustedProxies(proxies)
		router.Use(ReportDiscardedForwardedFor(proxies, logger))
		return
	}
	if logger != nil {
		logger.Info("trusted proxies configured (client IP resolved from X-Forwarded-For only for these hops)",
			zap.Strings("trusted_proxies", proxies))
	}
	router.Use(ReportDiscardedForwardedFor(proxies, logger))
}

// defaultTrustedProxies returns the loopback ranges the edge proxy connects from.
func defaultTrustedProxies() []string {
	return []string{"127.0.0.1/32", "::1/128"}
}

// forwardedHeaders are the headers gin consults when resolving the client IP
// (gin's default RemoteIPHeaders). A request carrying one of them was forwarded
// by something that believed it was a proxy.
var forwardedHeaders = []string{"X-Forwarded-For", "X-Real-IP"}

// maxReportedHops bounds the set of peer addresses this process will remember
// having reported. A misconfiguration has one or two hops; anything beyond that
// is a client sending the header on purpose, and it must not be able to grow a
// map by doing it. Past the cap the metric still counts every request — only the
// once-per-hop log suppression stops learning new addresses.
const maxReportedHops = 32

// ReportDiscardedForwardedFor reports requests whose forwarded client-IP header
// is being thrown away because the hop that sent it is not trusted.
//
// It is mounted by ConfigureTrustedProxies rather than by each service main, for
// the reason the security-header guard exists: a cross-cutting middleware that
// every main has to remember is one that seven mains remember. There is one call
// site, and it already had to be right.
//
// Membership is checked against the same list handed to gin rather than against
// gin's answer, because ClientIP() == RemoteIP() is also what a trusted proxy
// naming itself in X-Forwarded-For produces — a different situation with the
// same symptom. This never aborts a request: it observes, counts, and returns.
func ReportDiscardedForwardedFor(trusted []string, logger *zap.Logger) gin.HandlerFunc {
	nets := parseTrustedNets(trusted)

	var mu sync.Mutex
	reported := make(map[string]struct{}, maxReportedHops)

	return func(c *gin.Context) {
		if !hasForwardedHeader(c) {
			c.Next()
			return
		}

		peer := c.RemoteIP()
		ip := net.ParseIP(peer)
		if ip == nil || containsIP(nets, ip) {
			c.Next()
			return
		}

		forwardedFromUntrustedHopTotal.Inc()

		// Log only on the request that actually enters the hop into the set, so
		// the cap bounds the LINES as well as the map. Past it the counter is
		// what carries the rate; a thirty-third address is no longer an operator
		// reading off a list of hops to trust.
		mu.Lock()
		_, seen := reported[peer]
		first := !seen && len(reported) < maxReportedHops
		if first {
			reported[peer] = struct{}{}
		}
		mu.Unlock()

		if first && logger != nil {
			logger.Warn("forwarded client IP discarded: the hop that sent it is not a trusted proxy",
				logsafe.String("hop", peer),
				zap.Strings("trusted_proxies", trusted),
				zap.String("effect", "client IP resolves to the hop, so per-IP rate limits, audit IPs, "+
					"known-IP device trust and geo rules all see one address"),
				zap.String("fix", "add the hop to OIDX_TRUSTED_PROXIES, or ignore this if the caller "+
					"is a client sending the header itself"))
		}

		c.Next()
	}
}

func hasForwardedHeader(c *gin.Context) bool {
	for _, h := range forwardedHeaders {
		if c.Request.Header.Get(h) != "" {
			return true
		}
	}
	return false
}

// parseTrustedNets turns the entries gin was given into networks. An entry gin
// accepted parses here too; anything that does not is skipped rather than
// reported, since gin is the authority on the list it actually applied.
func parseTrustedNets(trusted []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(trusted))
	for _, entry := range trusted {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, n)
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return nets
}

func containsIP(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
