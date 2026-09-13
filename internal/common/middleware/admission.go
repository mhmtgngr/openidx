package middleware

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// ADMISSION CONTROL: A BOUND ON CONCURRENCY, WHICH IS NOT A RATE LIMIT.
//
// The rate limiter already in this package bounds ARRIVALS -- how many requests
// a caller may start per window. That is the right tool against one abusive
// client, and the wrong one against overload, because it cannot see what the
// process is already carrying. Two hundred requests per second is fine when
// each takes 5ms and fatal when a degraded database has pushed them to 2s, and
// a per-minute counter cannot tell those apart.
//
// What actually protects a fixed resource -- the connection pool, the CPU, the
// memory a request holds while it waits -- is a bound on how many requests are
// IN FLIGHT at once. Above that bound the process has nothing left to serve
// them with, so the honest answer is to say so immediately rather than to
// accept the work and hold it.
//
// THE FAILURE THIS PREVENTS is not "slow". Without a bound, an overloaded
// service accepts everything: goroutines pile up, each holding its request
// body, its context, its place in the pool queue. Latency climbs past every
// client's timeout, so the clients retry, which adds load. Nothing completes,
// memory grows, and the process dies with a queue full of work nobody is
// waiting for any more. A bounded queue with a fast refusal turns that into
// degraded-but-alive: some requests are refused in microseconds, the rest are
// served at normal speed.
//
// This is the runtime half of the design's claim that the expensive planes are
// SHEDDABLE (ADR-2, §4.3). Scaling ADMIN down to zero replicas sheds it; this
// sheds it under load without anyone touching a replica count, and does so at
// the first request rather than after the pod has fallen over.
//
// WHY A QUEUE AT ALL, rather than refusing the moment the slots are full: a
// burst that lasts 20ms is not overload, and refusing it would make the service
// look broken during ordinary jitter. The queue absorbs the burst; the TIMEOUT
// on the queue is what stops it absorbing an outage.

// AdmissionConfig bounds one plane's concurrency.
type AdmissionConfig struct {
	// Plane names this gate in its metrics -- "issue", "admin", "event". Every
	// gate is separate: a flood on ADMIN filling its slots must not consume
	// ISSUE's, which is the entire point of having planes.
	Plane string

	// MaxInflight is how many requests may hold a slot at once. Zero or less
	// disables the gate entirely, which is the default: a limit guessed rather
	// than measured is a self-inflicted outage, so an operator opts in with a
	// number they have sized against the pool behind this service.
	MaxInflight int

	// QueueTimeout is how long a request may wait for a slot before it is
	// refused. It should be well UNDER the client's own timeout: a request
	// refused at 5s when the caller gave up at 3s cost the server everything
	// and bought the caller nothing.
	QueueTimeout time.Duration

	// RetryAfter is the value sent with a 503. It is a promise about when there
	// might be room, so it must not be zero and must not be optimistic -- a
	// client that retries immediately turns one refusal into a retry storm,
	// which is the failure mode this whole mechanism exists to avoid.
	RetryAfter time.Duration

	// SkipPaths are never gated, matched exactly. Health, readiness and metrics
	// belong here always: they are how an operator finds out the gate is
	// shedding, and a gate that hides its own overload is worse than no gate.
	SkipPaths []string
}

// admissionGate is the runtime state behind one AdmissionConfig.
type admissionGate struct {
	cfg      AdmissionConfig
	slots    chan struct{}
	skip     map[string]bool
	inflight atomic.Int64
}

const (
	admissionOutcomeAdmitted = "admitted"
	admissionOutcomeRefused  = "refused"

	admissionReasonQueueTimeout = "queue_timeout"
	admissionReasonClientGone   = "client_gone"
)

// Admission returns a gate over MaxInflight concurrent requests. With
// MaxInflight <= 0 it returns a pass-through, so wiring it in before an
// operator has chosen a number changes nothing.
func Admission(cfg AdmissionConfig) gin.HandlerFunc {
	if cfg.MaxInflight <= 0 {
		return func(c *gin.Context) { c.Next() }
	}
	if cfg.Plane == "" {
		cfg.Plane = "default"
	}
	if cfg.QueueTimeout <= 0 {
		// A gate with no queue refuses ordinary jitter. 250ms absorbs a burst
		// without absorbing an outage.
		cfg.QueueTimeout = 250 * time.Millisecond
	}
	if cfg.RetryAfter <= 0 {
		cfg.RetryAfter = time.Second
	}

	g := &admissionGate{
		cfg:   cfg,
		slots: make(chan struct{}, cfg.MaxInflight),
		skip:  map[string]bool{},
	}
	for _, p := range cfg.SkipPaths {
		g.skip[p] = true
	}
	for _, p := range skipPaths { // /health, /metrics, /ready
		g.skip[p] = true
	}
	return g.handle
}

func (g *admissionGate) handle(c *gin.Context) {
	if g.skip[c.Request.URL.Path] {
		c.Next()
		return
	}

	start := time.Now()

	// The fast path: a free slot, no timer, no wait. Under normal load this is
	// every request, and it costs one channel send.
	select {
	case g.slots <- struct{}{}:
		g.admitted(c, start)
		return
	default:
	}

	// Full. Wait, but not past the budget -- and not past the client, who may
	// hang up while queued. Releasing that place immediately is what keeps the
	// queue a measure of real demand rather than of abandoned requests.
	timer := time.NewTimer(g.cfg.QueueTimeout)
	defer timer.Stop()

	select {
	case g.slots <- struct{}{}:
		g.admitted(c, start)
	case <-timer.C:
		g.refuse(c, start, admissionReasonQueueTimeout)
	case <-c.Request.Context().Done():
		g.refuse(c, start, admissionReasonClientGone)
	}
}

func (g *admissionGate) admitted(c *gin.Context, start time.Time) {
	admissionQueueWaitSeconds.WithLabelValues(g.cfg.Plane, admissionOutcomeAdmitted).
		Observe(time.Since(start).Seconds())
	admissionInflight.WithLabelValues(g.cfg.Plane).Set(float64(g.inflight.Add(1)))

	defer func() {
		<-g.slots
		admissionInflight.WithLabelValues(g.cfg.Plane).Set(float64(g.inflight.Add(-1)))
	}()

	c.Next()
}

func (g *admissionGate) refuse(c *gin.Context, start time.Time, reason string) {
	admissionQueueWaitSeconds.WithLabelValues(g.cfg.Plane, admissionOutcomeRefused).
		Observe(time.Since(start).Seconds())
	admissionRejectedTotal.WithLabelValues(g.cfg.Plane, reason).Inc()

	// A client that has already hung up gets no response -- writing one would
	// only spend the server's time on a socket nobody is reading. It is still
	// counted, because a queue full of abandoned requests is overload too.
	if reason == admissionReasonClientGone {
		c.Abort()
		return
	}

	// Retry-After in seconds, rounded UP: rounding a 1.5s promise down to 1s
	// invites the retry to arrive while the queue is still full.
	c.Header("Retry-After", strconv.Itoa(int(math.Ceil(g.cfg.RetryAfter.Seconds()))))
	c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
		"error":             "service_unavailable",
		"error_description": "The service is shedding load. Retry after the interval in the Retry-After header.",
	})
}

// ParseAdmissionDurations reads the two duration strings a service carries in
// its config (ADMISSION_QUEUE_TIMEOUT, ADMISSION_RETRY_AFTER). Empty means "use
// the default", which is the only silent case: a value that is present and
// unparseable is an error, so "250" -- which is not a Go duration and is almost
// certainly meant as milliseconds -- cannot be read as "default" and leave the
// operator believing they set something.
func ParseAdmissionDurations(queueTimeout, retryAfter string) (queue, retry time.Duration, err error) {
	if s := strings.TrimSpace(queueTimeout); s != "" {
		queue, err = time.ParseDuration(s)
		if err != nil {
			return 0, 0, fmt.Errorf("ADMISSION_QUEUE_TIMEOUT %q: %w (want a Go duration, e.g. 250ms)", s, err)
		}
		if queue <= 0 {
			return 0, 0, fmt.Errorf("ADMISSION_QUEUE_TIMEOUT %q must be positive", s)
		}
	}
	if s := strings.TrimSpace(retryAfter); s != "" {
		retry, err = time.ParseDuration(s)
		if err != nil {
			return 0, 0, fmt.Errorf("ADMISSION_RETRY_AFTER %q: %w (want a Go duration, e.g. 2s)", s, err)
		}
		if retry <= 0 {
			return 0, 0, fmt.Errorf("ADMISSION_RETRY_AFTER %q must be positive", s)
		}
	}
	return queue, retry, nil
}
