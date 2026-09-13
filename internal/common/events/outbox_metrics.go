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
