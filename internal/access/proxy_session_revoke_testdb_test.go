package access

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
)

// REVOKING A PROXY SESSION ENDS IT.
//
// A live proxy session is the Redis blob under proxy_session:<hash of the
// cookie>, and the proxy and forward-auth read nothing else. DELETE
// /sessions/:id used to mark the row and delete a key named after the row's id,
// which no session is stored under, so the revoked session went on working.
// Driven through the real route table and a real listener (the proxy is an
// httputil.ReverseProxy), with sessions seeded exactly as createSession writes
// them:
//
//   - the revoked session is refused at the proxy and at forward-auth on the
//     very next request, and its row reads revoked;
//   - another session of the same organization keeps working;
//   - another organization's session is not found, and keeps working;
//   - a revocation whose live session could not be deleted says so instead of
//     answering 200, and a retry finishes it.
func TestRevokingAProxySessionEndsIt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newAdminGateFixture(t)
	e := f.serve(t, f.db)
	hook := &sessionRedisHook{}
	e.svc.redis.Client.AddHook(hook)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	t.Cleanup(upstream.Close)
	hostA := "revoke-a-" + f.suffix + ".example.test"
	hostB := "revoke-b-" + f.suffix + ".example.test"
	routeA := f.seedProxyRoute(t, f.orgA, hostA, upstream.URL)
	routeB := f.seedProxyRoute(t, f.orgB, hostB, upstream.URL)

	srv := httptest.NewServer(e.r)
	t.Cleanup(srv.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	send := func(req *http.Request, token string) (int, string) {
		t.Helper()
		req.AddCookie(&http.Cookie{Name: "_openidx_proxy_session", Value: token})
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", req.Method, req.URL, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("Location") + string(body)
	}
	// proxy is the data plane itself: the catch-all route, found by Host.
	proxy := func(host, token string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/payslips", nil)
		req.Host = host
		return send(req, token)
	}
	// decide is forward-auth, as APISIX calls it for a request to host.
	decider := e.caller(f.userA, f.orgA)
	decide := func(host, token string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/access/auth/decide", nil)
		req.Header.Set("X-Forwarded-Host", host)
		req.Header.Set("X-Forwarded-Uri", "/payslips")
		req.Header.Set("X-Test-Caller", decider)
		return send(req, token)
	}
	refused := func(code int, body string) bool {
		return code == http.StatusFound && strings.HasPrefix(body, "/access/.auth/login")
	}
	isRevoked := func(id string) bool {
		t.Helper()
		var r bool
		if err := f.db.Pool.QueryRow(f.ctx, `SELECT COALESCE(revoked, false) FROM proxy_sessions WHERE id = $1::uuid`, id).Scan(&r); err != nil {
			t.Fatalf("read session %s: %v", id, err)
		}
		return r
	}
	admin := e.caller(f.adminA, f.orgA, "admin")
	revoke := func(id string) (int, string) {
		t.Helper()
		return e.do(admin, http.MethodDelete, "/api/v1/access/sessions/"+id, "")
	}

	target := f.seedLiveProxySession(t, e, f.orgA, f.userA, routeA)
	kept := f.seedLiveProxySession(t, e, f.orgA, f.adminA, routeA)
	other := f.seedLiveProxySession(t, e, f.orgB, f.adminB, routeB)
	for _, s := range []struct {
		name, host string
		sess       liveProxySession
	}{{"the target", hostA, target}, {"a colleague's", hostA, kept}, {"another organization's", hostB, other}} {
		if code, body := proxy(s.host, s.sess.token); code != http.StatusOK || body != "upstream-ok" {
			t.Fatalf("before any revocation, %s session at the proxy: %d %q", s.name, code, body)
		}
	}
	if code, body := decide(hostA, target.token); code != http.StatusOK {
		t.Fatalf("before any revocation, forward-auth: %d %q", code, body)
	}

	if code, body := revoke(target.id); code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if code, body := proxy(hostA, target.token); !refused(code, body) {
		t.Errorf("the revoked session at the proxy: %d %q, want a redirect to sign in", code, body)
	}
	if code, body := decide(hostA, target.token); !refused(code, body) {
		t.Errorf("the revoked session at forward-auth: %d %q, want a redirect to sign in", code, body)
	}
	if !isRevoked(target.id) {
		t.Error("the revoked session's row does not read revoked")
	}
	if code, body := proxy(hostA, kept.token); code != http.StatusOK {
		t.Errorf("a colleague's session after the revocation: %d %q", code, body)
	}
	if code, body := decide(hostA, kept.token); code != http.StatusOK {
		t.Errorf("a colleague's session at forward-auth after the revocation: %d %q", code, body)
	}

	if code, body := revoke(other.id); code != http.StatusNotFound {
		t.Errorf("revoke another organization's session: %d %s, want 404", code, body)
	}
	if code, body := proxy(hostB, other.token); code != http.StatusOK || isRevoked(other.id) {
		t.Errorf("another organization's session after a refused revocation: %d %q, revoked=%v", code, body, isRevoked(other.id))
	}
	for _, id := range []string{"00000000-0000-0000-0000-00000000beef", "not-a-session"} {
		if code, body := revoke(id); code != http.StatusNotFound {
			t.Errorf("revoke %q: %d %s, want 404", id, code, body)
		}
	}

	// Redis refuses the delete: the row is revoked and the session is still
	// live, and the answer has to say which of those is true.
	stuck := f.seedLiveProxySession(t, e, f.orgA, f.operatorA, routeA)
	hook.failDel.Store(true)
	code, body := revoke(stuck.id)
	hook.failDel.Store(false)
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "still live") {
		t.Errorf("revoke with the live session undeletable: %d %s, want 503 saying it is still live", code, body)
	}
	if code, body := proxy(hostA, stuck.token); code != http.StatusOK {
		t.Errorf("the undeleted session should still reach the upstream, as the 503 said: %d %q", code, body)
	}
	if code, body := revoke(stuck.id); code != http.StatusOK {
		t.Errorf("retry the revocation: %d %s", code, body)
	}
	if code, body := proxy(hostA, stuck.token); !refused(code, body) {
		t.Errorf("the session after the retried revocation: %d %q, want a redirect to sign in", code, body)
	}
}

// THE IDLE WINDOW'S REFRESH CANNOT BRING A REVOKED SESSION BACK.
//
// updateSessionActivity reads the blob, stamps last_active and writes it back.
// A revocation that deletes the blob between that read and that write used to
// be undone by the write, for a fresh twelve hours. The hook deletes the blob
// right after the read, which is exactly that interleaving; the write must not
// recreate it. Without the interleaving the refresh still does its job.
func TestTheIdleRefreshCannotBringARevokedSessionBack(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newAdminGateFixture(t)
	e := f.serve(t, f.db)
	hook := &sessionRedisHook{}
	e.svc.redis.Client.AddHook(hook)
	routeID := f.seedProxyRoute(t, f.orgA, "refresh-"+f.suffix+".example.test", "http://127.0.0.1:9/")
	ctx := context.Background()

	refresh := func(s liveProxySession) {
		t.Helper()
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.AddCookie(&http.Cookie{Name: "_openidx_proxy_session", Value: s.token})
		e.svc.updateSessionActivity(c, &ProxySession{ID: s.id, LastActiveAt: time.Now().Add(-time.Minute)})
	}

	live := f.seedLiveProxySession(t, e, f.orgA, f.userA, routeID)
	before := blobLastActive(t, e, live)
	time.Sleep(1100 * time.Millisecond) // last_active is in whole seconds
	refresh(live)
	if after := blobLastActive(t, e, live); after <= before {
		t.Errorf("the refresh did not slide a live session's idle window: last_active %d, was %d", after, before)
	}

	revoked := f.seedLiveProxySession(t, e, f.orgA, f.operatorA, routeID)
	hook.revokeAfterGet.Store("proxy_session:" + hashToken(revoked.token))
	refresh(revoked)
	if n, err := e.svc.redis.Client.Exists(ctx, "proxy_session:"+hashToken(revoked.token)).Result(); err != nil || n != 0 {
		t.Errorf("a session revoked between the refresh's read and its write came back (exists=%d, err %v)", n, err)
	}
}

// liveProxySession is a proxy session as createSession leaves it: a row and
// the blob the data plane reads, bound to the host of the route it is for.
type liveProxySession struct{ id, token string }

func (f *adminGateFixture) seedLiveProxySession(t *testing.T, e *adminGateEngine, org, user, route string) liveProxySession {
	t.Helper()
	token := "cookie-" + user + "-" + route
	var id, fromURL string
	if err := f.db.Pool.QueryRow(f.ctx, `
		INSERT INTO proxy_sessions (org_id, user_id, route_id, session_token, ip_address, user_agent, expires_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4, '203.0.113.9', 'test', NOW() + INTERVAL '1 hour')
		RETURNING id::text, (SELECT from_url FROM proxy_routes WHERE id = $3::uuid)`,
		org, user, route, hashToken(token)).Scan(&id, &fromURL); err != nil {
		t.Fatalf("seed proxy session: %v", err)
	}
	routeURL, err := url.Parse(fromURL)
	if err != nil {
		t.Fatalf("route %s from_url %q: %v", route, fromURL, err)
	}
	blob, err := json.Marshal(map[string]interface{}{
		"id":          id,
		"user_id":     user,
		"email":       user + "@example.test",
		"name":        "Someone",
		"roles":       []string{},
		"host":        sessionHost(routeURL.Host),
		"expires":     time.Now().Add(time.Hour).Unix(),
		"last_active": time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.redis.Client.Set(context.Background(), "proxy_session:"+hashToken(token), blob, time.Hour).Err(); err != nil {
		t.Fatalf("seed the live session: %v", err)
	}
	return liveProxySession{id: id, token: token}
}

func (f *adminGateFixture) seedProxyRoute(t *testing.T, org, host, upstream string) string {
	t.Helper()
	var id string
	if err := f.db.Pool.QueryRow(f.ctx, `
		INSERT INTO proxy_routes (org_id, name, from_url, to_url, require_auth)
		VALUES ($1::uuid, $2, $3, $4, true) RETURNING id::text`,
		org, host, "https://"+host, upstream).Scan(&id); err != nil {
		t.Fatalf("seed route %s: %v", host, err)
	}
	return id
}

func blobLastActive(t *testing.T, e *adminGateEngine, s liveProxySession) int64 {
	t.Helper()
	raw, err := e.svc.redis.Client.Get(context.Background(), "proxy_session:"+hashToken(s.token)).Bytes()
	if err != nil {
		t.Fatalf("read the live session: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	v, _ := m["last_active"].(float64)
	return int64(v)
}

// sessionRedisHook injects the two Redis events these tests need: a DEL that
// fails, and a revocation that lands between a read of one key and the write
// that follows it.
type sessionRedisHook struct {
	failDel        atomic.Bool
	revokeAfterGet atomic.Value // string: the key to delete right after it is read
}

func (h *sessionRedisHook) DialHook(next goredis.DialHook) goredis.DialHook { return next }

func (h *sessionRedisHook) ProcessPipelineHook(next goredis.ProcessPipelineHook) goredis.ProcessPipelineHook {
	return next
}

func (h *sessionRedisHook) ProcessHook(next goredis.ProcessHook) goredis.ProcessHook {
	return func(ctx context.Context, cmd goredis.Cmder) error {
		if cmd.Name() == "del" && h.failDel.Load() {
			err := errors.New("injected: redis refused the delete")
			cmd.SetErr(err)
			return err
		}
		err := next(ctx, cmd)
		if key, _ := h.revokeAfterGet.Load().(string); key != "" && cmd.Name() == "get" {
			if args := cmd.Args(); len(args) > 1 && args[1] == key {
				h.revokeAfterGet.Store("")
				if derr := next(ctx, goredis.NewIntCmd(ctx, "del", key)); derr != nil {
					return derr
				}
			}
		}
		return err
	}
}
