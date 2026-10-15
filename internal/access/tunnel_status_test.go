package access

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
)

// gatherFleet reads every gauge series of g as name{label=value} -> value.
func gatherFleet(t *testing.T, g prometheus.Gatherer) map[string]float64 {
	t.Helper()
	families, err := g.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	got := map[string]float64{}
	for _, f := range families {
		if f.GetType() != dto.MetricType_GAUGE {
			t.Errorf("%s is a %s, want a gauge", f.GetName(), f.GetType())
		}
		for _, m := range f.GetMetric() {
			key := f.GetName()
			for _, l := range m.GetLabel() {
				key += "{" + l.GetName() + "=" + l.GetValue() + "}"
			}
			got[key] = m.GetGauge().GetValue()
		}
	}
	return got
}

// fleetRegistry is a registry of c's own, so a test reads c and nothing else.
func fleetRegistry(t *testing.T, c prometheus.Collector) *prometheus.Registry {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register: %v", err)
	}
	return reg
}

// The scrape cache behind the fleet gauges: a count runs once per window,
// a scrape inside the window is answered from it, a failed count keeps the
// previous figure and is tried again, and a stale cache counts afresh.
func TestScrapeCacheCountsOncePerWindowAndKeepsTheLastFigureOnFailure(t *testing.T) {
	var c scrapeCache[float64]
	calls, failures := 0, 0
	value, fail := 3.0, false
	count := func(context.Context) (float64, error) {
		calls++
		if fail {
			return 0, errors.New("database away")
		}
		return value, nil
	}
	failed := func(error) { failures++ }

	if got := c.get(count, failed); got != 3 || calls != 1 {
		t.Fatalf("first scrape = %v after %d counts, want 3 after 1", got, calls)
	}
	value = 4
	if got := c.get(count, failed); got != 3 || calls != 1 {
		t.Errorf("a scrape inside the window = %v after %d counts, want the cached 3 after 1", got, calls)
	}

	c.at = time.Now().Add(-gaugeRefresh - time.Second)
	if got := c.get(count, failed); got != 4 || calls != 2 {
		t.Errorf("a scrape after the window = %v after %d counts, want 4 after 2", got, calls)
	}

	c.at = time.Now().Add(-gaugeRefresh - time.Second)
	fail = true
	if got := c.get(count, failed); got != 4 || calls != 3 || failures != 1 {
		t.Errorf("a failed count gave %v after %d counts and %d failures, want the previous 4, 3, 1", got, calls, failures)
	}
	// Nothing was cached by the failure: the next scrape tries again.
	if got := c.get(count, failed); got != 4 || calls != 4 || failures != 2 {
		t.Errorf("after a failure the next scrape gave %v after %d counts and %d failures, want 4, 4, 2", got, calls, failures)
	}
	fail = false
	value = 5
	if got := c.get(count, failed); got != 5 || calls != 5 {
		t.Errorf("once the count answers again: %v after %d counts, want 5 after 5", got, calls)
	}
}

// The fleet collector's series: every state and every gap is always a
// series, zero included; a status outside the vocabulary is not one; and the
// figures are what the count returned.
func TestFleetCollectorAlwaysExposesEveryStateAndGap(t *testing.T) {
	c := newFleetCollector(nil, zap.NewNop())
	c.cache.last = fleetCounts{
		byState: map[string]float64{"active": 7, "revoked": 2, "decommissioned": 9},
		gaps:    map[string]float64{"block_direct": 3},
	}
	c.cache.at = time.Now() // fresh: Collect must not reach for the (nil) database
	want := map[string]float64{
		"openidx_agents_by_state{state=active}":        7,
		"openidx_agents_by_state{state=pending}":       0,
		"openidx_agents_by_state{state=suspended}":     0,
		"openidx_agents_by_state{state=revoked}":       2,
		"openidx_tunnel_policy_gaps{gap=full_tunnel}":  0,
		"openidx_tunnel_policy_gaps{gap=block_direct}": 3,
	}
	if got := gatherFleet(t, fleetRegistry(t, c)); !reflect.DeepEqual(got, want) {
		t.Errorf("series = %v, want %v", got, want)
	}
}
