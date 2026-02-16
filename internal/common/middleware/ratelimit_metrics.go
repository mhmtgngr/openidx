package middleware

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	rlHitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "rate_limit_hits_total",
			Help:      "Total number of requests rejected by rate limiting",
		},
		[]string{"scope"},
	)

	rlFailOpenTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "rate_limit_fail_open_total",
			Help:      "Total number of requests allowed due to Redis unavailability (fail-open)",
		},
		[]string{"scope"},
	)
)
