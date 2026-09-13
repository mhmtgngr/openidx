package middleware

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	admissionInflight = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "openidx",
			Subsystem: "admission",
			Name:      "inflight",
			Help:      "Requests currently holding an admission slot.",
		},
		[]string{"plane"},
	)

	admissionRejectedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Subsystem: "admission",
			Name:      "rejected_total",
			Help:      "Requests refused admission, by why. `queue_timeout` waited the full budget and never got a slot; `client_gone` hung up while queued and was never served at all.",
		},
		[]string{"plane", "reason"},
	)

	admissionQueueWaitSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "openidx",
			Subsystem: "admission",
			Name:      "queue_wait_seconds",
			Help:      "How long a request waited for a slot. Observed for admitted AND refused requests: a queue that is only measured when it succeeds hides the overload it exists to report.",
			// Sub-millisecond to the far side of a typical queue budget. The
			// interesting region is the shoulder where waiting starts, not the
			// tail, because by the tail the answer is already a 503.
			Buckets: []float64{0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		},
		[]string{"plane", "outcome"},
	)
)
