package middleware

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// forwardedFromUntrustedHopTotal counts requests whose forwarded client-IP
// header was discarded because the hop that sent it is not in the trusted set.
//
// It carries no label. The peer address belongs in the log line, which is
// emitted once per hop; as a metric label it would be unbounded cardinality
// handed to anyone who can send a header.
var forwardedFromUntrustedHopTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Namespace: "openidx",
		Name:      "forwarded_for_from_untrusted_hop_total",
		Help: "Requests carrying X-Forwarded-For or X-Real-IP from a hop absent from OIDX_TRUSTED_PROXIES. " +
			"The header is ignored and the hop's own address becomes the client IP, so per-IP rate limits, " +
			"audit IPs, known-IP device trust and geo rules all resolve to it. A steady rate means the " +
			"trusted set does not describe the deployment; an occasional one is a client sending the header.",
	},
)
