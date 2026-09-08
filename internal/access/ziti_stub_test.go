package access

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
)

// A fake Ziti controller.
//
// Fifteen fixes across two commits on this branch share one shape: the handler
// calls the controller, checks THAT, and then writes the database mirror. When
// the mirror write failed the network had already changed and the API said the
// whole thing worked. Every one of them landed without a handler test, for the
// same reason each time -- reaching the first line of the fix means getting
// past an authenticated management API.
//
// It turns out that is a small thing to provide. mgmtBase() reads
// cfg.ZitiCtrlURL, mgmtRequestAt speaks plain HTTP, and a ZitiManager built as
// a struct literal skips the constructor's bootstrap entirely. So the whole
// controller is an httptest.Server that answers /authenticate and whatever
// endpoints the test names.
//
// The recorder is the point. These tests are about the SPLIT between the
// controller and the database, so a test has to be able to say "the controller
// call happened AND the row is still there" -- which is exactly the state the
// old code reported as success.

// zitiStub is a fake Ziti controller: it answers what a test tells it to and
// records every management call it received.
type zitiStub struct {
	*httptest.Server

	mu    sync.Mutex
	calls []string // "METHOD /path", in order

	// routes maps "METHOD /path/prefix" to a handler. The longest matching
	// prefix wins, so a test can answer /edge/management/v1/services broadly
	// and one service id specifically.
	routes map[string]http.HandlerFunc
}

// newZitiStub starts a controller that authenticates anybody and 404s
// everything else until the test says otherwise.
func newZitiStub(t *testing.T) *zitiStub {
	t.Helper()
	s := &zitiStub{routes: map[string]http.HandlerFunc{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.calls = append(s.calls, r.Method+" "+r.URL.Path)
		s.mu.Unlock()

		if strings.HasPrefix(r.URL.Path, "/edge/management/v1/authenticate") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]string{"token": "stub-session-token"},
			})
			return
		}

		s.mu.Lock()
		var best string
		var handler http.HandlerFunc
		for pattern, h := range s.routes {
			method, path, ok := strings.Cut(pattern, " ")
			if !ok || method != r.Method || !strings.HasPrefix(r.URL.Path, path) {
				continue
			}
			if len(path) > len(best) {
				best, handler = path, h
			}
		}
		s.mu.Unlock()

		if handler != nil {
			handler(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"NOT_FOUND"}}`))
	}))
	t.Cleanup(s.Close)
	return s
}

// on registers a handler for a "METHOD /path" prefix.
func (s *zitiStub) on(pattern string, h http.HandlerFunc) *zitiStub {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes[pattern] = h
	return s
}

// ok registers a handler answering 200 with the given JSON body.
func (s *zitiStub) ok(pattern, body string) *zitiStub {
	return s.on(pattern, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
}

// saw reports whether the controller received a call matching "METHOD /path"
// as a prefix.
func (s *zitiStub) saw(pattern string) bool {
	method, path, ok := strings.Cut(pattern, " ")
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.calls {
		cm, cp, _ := strings.Cut(c, " ")
		if cm == method && strings.HasPrefix(cp, path) {
			return true
		}
	}
	return false
}

// received returns every management call in order, for a failure message that
// says what the controller actually saw.
func (s *zitiStub) received() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.calls))
	copy(out, s.calls)
	return out
}

// zitiManagerAgainst builds a ZitiManager pointed at the stub.
//
// A struct literal rather than NewZitiManager: the constructor authenticates
// and then bootstraps identities and policies, which would make every test
// depend on the shape of a bootstrap none of them are about. The fields set
// here are exactly the ones the management path reads — a nil pool makes
// mgmtBase fall back to cfg.ZitiCtrlURL, which is the stub.
func zitiManagerAgainst(t *testing.T, stub *zitiStub, db *database.PostgresDB) *ZitiManager {
	t.Helper()
	return &ZitiManager{
		cfg: &config.Config{
			ZitiEnabled:            true,
			ZitiCtrlURL:            stub.URL,
			ZitiAdminUser:          "admin",
			ZitiAdminPassword:      "stub",
			ZitiInsecureSkipVerify: true,
		},
		logger:          zap.NewNop(),
		db:              db,
		mgmtClient:      &http.Client{Timeout: 5 * time.Second},
		mgmtToken:       "stub-session-token",
		hostedServices:  make(map[string]*hostedService),
		configTypeCache: make(map[string]string),
	}
}

// The stub has to actually work, and a stub nobody checks is the thing this
// branch keeps deleting. These two pin it.
func TestTheZitiStubAnswersTheManagementAPI(t *testing.T) {
	t.Parallel()

	stub := newZitiStub(t)
	stub.ok("GET /edge/management/v1/services", `{"data":[{"id":"svc-1","name":"a-service"}]}`)

	zm := zitiManagerAgainst(t, stub, nil)
	body, status, err := zm.mgmtRequest("GET", "/edge/management/v1/services", nil)
	if err != nil {
		t.Fatalf("mgmtRequest: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (calls: %v)", status, stub.received())
	}
	if !strings.Contains(string(body), "a-service") {
		t.Errorf("body = %s", body)
	}
	if !stub.saw("GET /edge/management/v1/services") {
		t.Errorf("the stub did not record the call; calls: %v", stub.received())
	}
}

func TestTheZitiStubRefusesWhatItWasNotToldToAnswer(t *testing.T) {
	t.Parallel()

	stub := newZitiStub(t)
	zm := zitiManagerAgainst(t, stub, nil)

	// A stub that answered 200 to everything would let a test pass while the
	// code called an endpoint nobody meant it to.
	_, status, err := zm.mgmtRequest("DELETE", "/edge/management/v1/services/svc-9", nil)
	if err != nil {
		t.Fatalf("mgmtRequest: %v", err)
	}
	if status != http.StatusNotFound {
		t.Errorf("an unregistered endpoint answered %d, want 404", status)
	}
}
