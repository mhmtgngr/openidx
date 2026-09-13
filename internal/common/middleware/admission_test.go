package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// Every assertion here drives the real middleware through a real gin engine.
// The gate is about concurrency, so the tests are about concurrency: a handler
// that blocks until the test lets it go is what makes "in flight" observable.

func admissionRouter(cfg AdmissionConfig, h gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(Admission(cfg))
	r.GET("/work", h)
	r.GET("/health", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

// blockingHandler holds every request until release is closed, and reports how
// many are inside at once.
type blockingHandler struct {
	release chan struct{}
	entered chan struct{}
	peak    atomic.Int64
	cur     atomic.Int64
}

func newBlockingHandler() *blockingHandler {
	return &blockingHandler{release: make(chan struct{}), entered: make(chan struct{}, 256)}
}

func (b *blockingHandler) fn(c *gin.Context) {
	n := b.cur.Add(1)
	for {
		p := b.peak.Load()
		if n <= p || b.peak.CompareAndSwap(p, n) {
			break
		}
	}
	b.entered <- struct{}{}
	<-b.release
	b.cur.Add(-1)
	c.Status(http.StatusOK)
}

// The bound is the whole point: never more than MaxInflight handlers running,
// however many callers arrive at once.
func TestAdmissionNeverExceedsMaxInflight(t *testing.T) {
	const max = 3
	b := newBlockingHandler()
	r := admissionRouter(AdmissionConfig{
		Plane: "test", MaxInflight: max, QueueTimeout: 2 * time.Second, RetryAfter: time.Second,
	}, b.fn)

	var wg sync.WaitGroup
	codes := make([]int, 12)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/work", nil))
			codes[i] = w.Code
		}(i)
	}

	// Wait for the gate to be full before letting anything finish.
	for i := 0; i < max; i++ {
		select {
		case <-b.entered:
		case <-time.After(2 * time.Second):
			close(b.release)
			wg.Wait()
			t.Fatalf("only %d request(s) reached the handler; the gate admitted fewer than MaxInflight", i)
		}
	}
	if got := b.cur.Load(); got != max {
		t.Errorf("%d handlers are running at once, want %d", got, max)
	}
	close(b.release)
	wg.Wait()

	if peak := b.peak.Load(); peak > max {
		t.Errorf("%d handlers ran concurrently; MaxInflight is %d and the bound is the whole point", peak, max)
	}
}

// A request that waits out the budget is refused with 503 and an honest
// Retry-After -- not held, and not answered 200 after the client gave up.
func TestAdmissionRefusesWithRetryAfterWhenTheQueueTimesOut(t *testing.T) {
	b := newBlockingHandler()
	r := admissionRouter(AdmissionConfig{
		Plane: "test", MaxInflight: 1, QueueTimeout: 40 * time.Millisecond, RetryAfter: 3 * time.Second,
	}, b.fn)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/work", nil))
	}()
	select {
	case <-b.entered:
	case <-time.After(2 * time.Second):
		close(b.release)
		t.Fatal("the first request never reached the handler")
	}

	start := time.Now()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/work", nil))
	waited := time.Since(start)

	close(b.release)
	wg.Wait()

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("a request that outwaited the queue got %d, want 503", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Error("no Retry-After on the refusal: a client with nothing to wait for retries immediately, which is the retry storm this gate exists to prevent")
	} else if n, err := strconv.Atoi(ra); err != nil || n < 1 {
		t.Errorf("Retry-After = %q, want a positive whole number of seconds", ra)
	}
	// It must have actually waited -- a gate that refuses instantly is not
	// absorbing the burst it was added for.
	if waited < 30*time.Millisecond {
		t.Errorf("refused after %s, but QueueTimeout was 40ms; the queue did not absorb anything", waited)
	}
	// And not much longer than the budget.
	if waited > 900*time.Millisecond {
		t.Errorf("refused after %s, far past the 40ms budget", waited)
	}
}

// A burst inside the budget is absorbed, not refused. This is why there is a
// queue at all.
func TestAdmissionAbsorbsABurstWithinTheBudget(t *testing.T) {
	var served atomic.Int64
	r := admissionRouter(AdmissionConfig{
		Plane: "test", MaxInflight: 2, QueueTimeout: 2 * time.Second, RetryAfter: time.Second,
	}, func(c *gin.Context) {
		time.Sleep(5 * time.Millisecond)
		served.Add(1)
		c.Status(http.StatusOK)
	})

	var wg sync.WaitGroup
	var refused atomic.Int64
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/work", nil))
			if w.Code == http.StatusServiceUnavailable {
				refused.Add(1)
			}
		}()
	}
	wg.Wait()

	if refused.Load() != 0 {
		t.Errorf("%d of 20 requests were refused, but 20 x 5ms over 2 slots is ~50ms against a 2s budget; the queue refused a burst it should have absorbed", refused.Load())
	}
	if served.Load() != 20 {
		t.Errorf("%d requests reached the handler, want 20", served.Load())
	}
}

// A caller that hangs up while queued must release its place at once. A queue
// measuring abandoned requests reports overload that is not there, and holds
// slots against callers who are still waiting.
func TestAdmissionReleasesTheQueueWhenTheClientHangsUp(t *testing.T) {
	b := newBlockingHandler()
	r := admissionRouter(AdmissionConfig{
		Plane: "test", MaxInflight: 1, QueueTimeout: 10 * time.Second, RetryAfter: time.Second,
	}, b.fn)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/work", nil))
	}()
	select {
	case <-b.entered:
	case <-time.After(2 * time.Second):
		close(b.release)
		t.Fatal("the first request never reached the handler")
	}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/work", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		r.ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(b.release)
		t.Fatal("a request whose client hung up stayed queued; its place is held against callers who are still waiting")
	}
	close(b.release)
	wg.Wait()
}

// Health, readiness and metrics are never gated. They are how an operator finds
// out the gate is shedding; a gate that hides its own overload is worse than no
// gate at all.
func TestAdmissionNeverGatesTheHealthEndpoints(t *testing.T) {
	b := newBlockingHandler()
	r := admissionRouter(AdmissionConfig{
		Plane: "test", MaxInflight: 1, QueueTimeout: 10 * time.Second, RetryAfter: time.Second,
	}, b.fn)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/work", nil))
	}()
	select {
	case <-b.entered:
	case <-time.After(2 * time.Second):
		close(b.release)
		t.Fatal("the first request never reached the handler")
	}

	done := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
		done <- w.Code
	}()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Errorf("/health answered %d while the gate was full, want 200", code)
		}
	case <-time.After(time.Second):
		t.Error("/health was queued behind the gate: the endpoint that reports overload cannot be the one overload silences")
	}
	close(b.release)
	wg.Wait()
}

// Wiring the gate in before an operator has sized it must change nothing. A
// limit guessed rather than measured is a self-inflicted outage.
//
// "Nothing" means NO SERIALISATION, not merely "no 503s". An earlier version of
// this test only counted status codes, and a mutation that turned MaxInflight=0
// into a one-slot gate passed it: thirty 2ms requests queue through one slot in
// 60ms, comfortably inside the default queue budget, so every one still
// answered 200. Concurrency is the property, so concurrency is what is
// measured.
func TestAdmissionIsAPassThroughUntilSized(t *testing.T) {
	const callers = 30
	var served atomic.Int64
	var cur, peak atomic.Int64
	start := make(chan struct{})

	r := admissionRouter(AdmissionConfig{Plane: "test", MaxInflight: 0}, func(c *gin.Context) {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		// Hold long enough that every caller is inside at once IF nothing is
		// serialising them.
		time.Sleep(30 * time.Millisecond)
		cur.Add(-1)
		served.Add(1)
		c.Status(http.StatusOK)
	})

	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/work", nil))
			if w.Code != http.StatusOK {
				t.Errorf("MaxInflight=0 refused a request with %d; an unsized gate must be a pass-through", w.Code)
			}
		}()
	}
	close(start)
	wg.Wait()

	if served.Load() != callers {
		t.Errorf("%d requests served, want %d", served.Load(), callers)
	}
	// Any gate at all would hold this down to its slot count. Well over one is
	// the signal that nothing is in the way; the exact number is the scheduler's
	// business, so this asks only that it is not serialised.
	if p := peak.Load(); p < callers/2 {
		t.Errorf("peak concurrency was %d of %d callers: something is serialising requests, so MaxInflight=0 is not the pass-through it claims to be", p, callers)
	}
}

// Two planes, two gates: filling one must not touch the other. That separation
// is the entire reason the planes exist.
func TestAdmissionGatesAreIndependentPerPlane(t *testing.T) {
	admin := newBlockingHandler()
	adminRouter := admissionRouter(AdmissionConfig{
		Plane: "admin", MaxInflight: 1, QueueTimeout: 20 * time.Millisecond, RetryAfter: time.Second,
	}, admin.fn)
	issueRouter := admissionRouter(AdmissionConfig{
		Plane: "issue", MaxInflight: 1, QueueTimeout: 20 * time.Millisecond, RetryAfter: time.Second,
	}, func(c *gin.Context) { c.Status(http.StatusOK) })

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		adminRouter.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/work", nil))
	}()
	select {
	case <-admin.entered:
	case <-time.After(2 * time.Second):
		close(admin.release)
		t.Fatal("the admin request never reached the handler")
	}

	// ADMIN is now full and refusing.
	w := httptest.NewRecorder()
	adminRouter.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/work", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("the full admin gate answered %d, want 503", w.Code)
	}

	// ISSUE must not have noticed.
	w = httptest.NewRecorder()
	issueRouter.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/work", nil))
	if w.Code != http.StatusOK {
		t.Errorf("the issue plane answered %d while admin was shedding; the planes are not independent, which is the whole reason they exist", w.Code)
	}

	close(admin.release)
	wg.Wait()
}
