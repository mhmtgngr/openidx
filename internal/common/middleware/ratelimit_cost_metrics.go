package middleware

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// No org label anywhere below. A tenant id is unbounded cardinality, and a
// metric that grows a series per tenant turns a tenant flood into a Prometheus
// outage -- the same shape of failure this middleware exists to prevent.
var (
	rlCostSpentTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "ratelimit_cost_spent_total",
			Help:      "Cost units admitted against tenant budgets. Cheap (never-shed) routes are not charged, so this counts expensive work only.",
		},
	)

	rlCostRejectedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "ratelimit_cost_rejected_total",
			Help:      "Requests over their tenant's cost budget, by mode and route cost. In observe mode the request was served anyway -- this is what enforcement WOULD have refused, and is how a budget gets sized before it is turned on.",
		},
		[]string{"mode", "cost"},
	)

	rlCostFailOpenTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "openidx",
			Name:      "ratelimit_cost_fail_open_total",
			Help:      "Expensive requests admitted without accounting because the rate-limit Redis could not answer. Sustained non-zero means the budget is not being enforced at all.",
		},
	)
)
