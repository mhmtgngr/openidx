package events

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Labelled by event type, which is a bounded set the code declares. Not by
// tenant: a per-tenant series on a path every write goes through turns one
// noisy tenant into a Prometheus outage.
var outboxPublishedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "openidx",
		Name:      "outbox_published_total",
		Help:      "Events written into the outbox, by type. Counted at the INSERT, so it includes rows whose transaction later rolled back -- compare it against the relay's delivered count to see the difference, not against it to measure loss.",
	},
	[]string{"event_type"},
)

var (
	outboxRelayDeliveredTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "outbox_relay_delivered_total",
			Help:      "Events the sink accepted AND whose outbox row was marked published, by type. A crash between those two facts redelivers, so this can undercount what the sink actually received -- which is the safe direction.",
		},
		[]string{"event_type"},
	)

	outboxRelayFailedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "outbox_relay_failed_total",
			Help:      "Delivery attempts the sink refused, by type. The rows stay in the backlog and are retried; sustained non-zero with a flat delivered_total means the sink is down, not that events are being lost.",
		},
		[]string{"event_type"},
	)

	outboxRelayLagSeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "openidx",
			Name:      "outbox_relay_lag_seconds",
			Help:      "Time from an event being written to it being delivered. Measured from created_at, so it includes time the relay was down -- which is the number an operator actually wants after an outage.",
			Buckets:   []float64{.05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 300, 900},
		},
	)
)

var outboxSweptTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Namespace: "openidx",
		Name:      "outbox_swept_total",
		Help:      "Delivered outbox rows aged out by the retention sweep. Only rows with published_at set are ever eligible, so this can never be a count of lost events.",
	},
)
