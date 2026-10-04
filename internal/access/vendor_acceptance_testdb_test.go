package access

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/governance"
	"github.com/openidx/openidx/internal/oauth"
)

// The acceptance criterion of #975, the last row of section 10 of the
// third-party access framework: during the approved window an external
// (vendor) user reaches the approved targets and nothing else, and an expired,
// unapproved or out-of-scope attempt is refused at every enforcement point,
// OAuth, the proxy, the Ziti dial and PAM.
//
// One vendor user and their sponsor. Three applications, each an OIDC client
// that requires assignment and a BrowZer route on the overlay, and three PAM
// entries on the overlay that the vendor may see and ask for:
//
//   - approved: asked for through governance, approved by the sponsor and then
//     by the administrator, for a window;
//   - unapproved: the application asked for and denied by the sponsor; the
//     entry asked for and approved by the sponsor only, one of its two steps;
//   - out of scope: never asked for.
//
// Every request goes through governance's own routes and its own token check,
// with tokens signed by a key published at the JWKS URL governance reads. The
// window then closes the way it closes on an install: its end passes and the
// governance service's expiry tick runs.
//
// Each enforcement point is the real one:
//
//   - OAuth: /oauth/authorize on oauth-service's routes, from a live browser
//     session, minting a code or refusing;
//   - the proxy: handleProxy as the router's NoRoute, from a proxy session,
//     reaching the upstream or refusing before it;
//   - the Ziti dial: the vendor identity's role attributes as the user sync
//     patches them, against the Dial policy the reconciler writes, on a stand-in
//     controller that matches the two the way the controller does;
//   - PAM: connect, on a stand-in broker, and the lifecycle sweep that ends a
//     session whose grant ended.
//
// Not proved here, and said in docs/evidence/display-equals-enforcement.md:
//
//   - the end is as late as the sweeps that carry it. An application's
//     assignment is removed by the governance tick, every five minutes; the
//     proxy then holds its answer for up to thirty seconds, and the overlay
//     drops the vendor's attribute at the next sync of their identity. A PAM
//     grant ends at the window itself;
//   - a network service, the third kind of target a vendor can be opened. An
//     approved request for one opens no dial yet: no Dial policy names the
//     jit-<request-id> attribute it adds.
func TestAVendorReachesOnlyWhatTheirSponsorApprovedAndOnlyInTheWindow(t *testing.T) {
	f := newExternalPamFixture(t)
	ctx := context.Background()
	bypass := orgctx.WithBypassRLS(ctx)
	inOrg := func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: f.org}))
		c.Next()
	}
	mini := miniredis.RunT(t)
	rc := goredis.NewClient(&goredis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	rds := &database.RedisClient{Client: rc}

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	t.Cleanup(upstream.Close)

	// ---- the targets ----
	type app struct{ id, clientID, host, service string }
	newApp := func(name string) app {
		t.Helper()
		a := app{clientID: name + "-" + f.suffix, host: name + "-" + f.suffix + ".example.test", service: "vendor-" + name + "-" + f.suffix}
		route := f.scalar(`INSERT INTO proxy_routes (org_id, name, from_url, to_url, ziti_enabled, ziti_service_name, browzer_enabled, hosting_mode)
			VALUES ($1, $2, $3, $4, true, $5, true, 'direct') RETURNING id::text`,
			f.org, a.clientID, "https://"+a.host, upstream.URL, a.service)
		a.id = f.scalar(`INSERT INTO applications (org_id, client_id, name, type, route_id, require_assignment)
			VALUES ($1, $2, $3, 'web', $4, true) RETURNING id::text`, f.org, a.clientID, name, route)
		f.exec(`INSERT INTO oauth_clients (org_id, client_id, name, type, redirect_uris, grant_types, response_types, scopes, pkce_required)
			VALUES ($1, $2, $3, 'public', $4::jsonb, '["authorization_code"]', '["code"]', '["openid","profile","email"]', true)`,
			f.org, a.clientID, name, `["https://`+a.host+`/callback"]`)
		return a
	}
	approvedApp, unapprovedApp, outOfScopeApp := newApp("ticketing"), newApp("billing"), newApp("payroll")

	newEntry := func(name string) string {
		t.Helper()
		id := f.scalar(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port, username, reach_mode)
			VALUES ($1, $2, 'ssh', $3, 22, 'deploy', 'ziti') RETURNING id::text`,
			f.org, name+"-"+f.suffix, name+".example.test")
		// Eligibility: the vendor sees the entry and may ask for it. Only a
		// fulfilled request lets them connect.
		f.exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
			VALUES ($1, $2, 'user', $3, '{view}')`, f.org, id, f.external)
		return id
	}
	approvedEntry, unapprovedEntry, outOfScopeEntry := newEntry("db-01"), newEntry("db-02"), newEntry("db-03")

	// ---- governance, behind its own token check ----
	keys := newAcceptanceTokens(t, f.org)
	gsvc := governance.NewService(f.db, rds, &config.Config{OAuthJWKSURL: keys.jwksURL, OAuthIssuer: keys.issuer}, zap.NewNop())
	gov := gin.New()
	gov.Use(inOrg)
	governance.RegisterRoutes(gov, gsvc)
	govCall := func(token, method, path, body string) (int, map[string]interface{}) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/api/v1/governance"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		gov.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	administrator := f.scalar(`SELECT id::text FROM users WHERE username = 'admin'`)
	vendorToken := keys.token(t, f.external, "user")
	sponsorToken := keys.token(t, f.admin, "user")
	adminToken := keys.token(t, administrator, "admin")
	file := func(resourceType, resourceID string) string {
		t.Helper()
		code, body := govCall(vendorToken, http.MethodPost, "/requests",
			`{"resource_type":"`+resourceType+`","resource_id":"`+resourceID+`","resource_name":"target","justification":"maintenance window","duration":"2h"}`)
		if code != http.StatusCreated {
			t.Fatalf("the vendor asks for %s %s: %d %v", resourceType, resourceID, code, body)
		}
		return f.scalar(`SELECT id::text FROM access_requests WHERE requester_id = $1 AND resource_id = $2::uuid
			ORDER BY created_at DESC LIMIT 1`, f.external, resourceID)
	}
	decide := func(token, requestID, decision string) {
		t.Helper()
		if code, body := govCall(token, http.MethodPost, "/requests/"+requestID+"/"+decision, `{"comments":"checked"}`); code != http.StatusOK {
			t.Fatalf("%s request %s: %d %v", decision, requestID, code, body)
		}
	}
	statusOf := func(requestID string) string {
		return f.scalar(`SELECT status FROM access_requests WHERE id = $1`, requestID)
	}

	// ---- OAuth, from the vendor's browser session ----
	osvc, err := oauth.NewService(f.db, rds, &config.Config{
		AccessAssignmentEnforce: true, ABACEnforce: "off", OAuthIssuer: keys.issuer,
		OAuthLoginURL: "https://console.example.test/login",
	}, zap.NewNop(), nil)
	if err != nil {
		t.Fatalf("oauth service: %v", err)
	}
	idp := gin.New()
	idp.Use(inOrg)
	oauth.RegisterRoutes(idp, osvc, func(c *gin.Context) { c.AbortWithStatus(http.StatusUnauthorized) })
	// The browser session a password and authenticator sign-in leaves: the
	// session row, and the openidx_sso cookie bound to it in Redis
	// (internal/oauth/browser_session.go). Renaming either makes the approved
	// target's authorize below fall back to the login page, and fail.
	browserSession := f.scalar(`INSERT INTO sessions (user_id, client_id, expires_at, org_id, auth_methods, mfa_verified_at)
		VALUES ($1, 'admin-console', NOW() + interval '8 hours', $2, '{pwd,otp}', NOW()) RETURNING id::text`, f.external, f.org)
	ssoCookie := randomToken(t)
	if err := rc.Set(ctx, "sso_session:"+ssoCookie, browserSession, time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	// signsIn reports whether /oauth/authorize mints the vendor a code for the
	// application, and what it answered.
	signsIn := func(a app) (bool, string) {
		t.Helper()
		sum := sha256.Sum256([]byte("verifier-" + a.clientID))
		q := url.Values{
			"client_id": {a.clientID}, "redirect_uri": {"https://" + a.host + "/callback"},
			"response_type": {"code"}, "scope": {"openid"}, "state": {"st-1"},
			"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
		req.AddCookie(&http.Cookie{Name: "openidx_sso", Value: ssoCookie})
		idp.ServeHTTP(w, req)
		answer := w.Body.String()
		if w.Code == http.StatusFound {
			loc, _ := url.Parse(w.Header().Get("Location"))
			answer = loc.String()
			if loc.Host == a.host && loc.Query().Get("code") != "" {
				return true, answer
			}
		}
		return false, http.StatusText(w.Code) + " " + answer
	}

	// ---- the proxy, from a proxy session per host ----
	f.svc.redis = rds
	f.svc.config.AccessAssignmentEnforce = true
	proxyRouter := gin.New()
	proxyRouter.NoRoute(f.svc.handleProxy)
	proxy := httptest.NewServer(proxyRouter)
	t.Cleanup(proxy.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// reaches reports whether a request the vendor sends through the proxy to
	// the application's host arrives at the upstream.
	reaches := func(a app) (bool, int) {
		t.Helper()
		cookie := randomToken(t)
		blob, _ := json.Marshal(map[string]interface{}{
			"id": "proxy-" + cookie[:8], "user_id": f.external, "email": f.externalAccount, "name": "Vendor",
			"roles": []string{}, "host": a.host, "org_id": f.org,
			"expires": time.Now().Add(time.Hour).Unix(), "last_active": time.Now().Unix(),
		})
		if err := rc.Set(ctx, "proxy_session:"+hashToken(cookie), blob, time.Hour).Err(); err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodGet, proxy.URL+"/tickets", nil)
		req.Host = a.host
		req.AddCookie(&http.Cookie{Name: proxySessionCookie, Value: cookie})
		before := upstreamHits.Load()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("through the proxy to %s: %v", a.host, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		arrived := upstreamHits.Load() > before
		if arrived != (resp.StatusCode == http.StatusOK && string(body) == "upstream-ok") {
			t.Fatalf("through the proxy to %s: %d %q, and the upstream was reached: %v", a.host, resp.StatusCode, body, arrived)
		}
		return arrived, resp.StatusCode
	}

	// ---- the overlay ----
	overlay := &acceptanceOverlay{policies: &fakeController{}, attrs: map[string][]string{}}
	ctrl := httptest.NewServer(overlay)
	t.Cleanup(ctrl.Close)
	zcfg := MockConfig(t)
	zcfg.ZitiCtrlURL = ctrl.URL
	zm := &ZitiManager{cfg: zcfg, logger: zap.NewNop(), db: f.db, mgmtToken: "t", mgmtClient: ctrl.Client()}
	vendorIdentity := "zid-" + f.suffix
	f.exec(`INSERT INTO ziti_identities (ziti_id, name, identity_type, user_id, enrolled, org_id)
		VALUES ($1, $2, 'User', $3, true, $4)`, vendorIdentity, "vendor-"+f.suffix, f.external, f.org)
	// BrowZer is on, so the vendor's identity carries #browzer-users like every
	// clientless user's: the blanket grant a BrowZer route's Dial policy names
	// when assignment is not enforced.
	f.exec(`INSERT INTO ziti_browzer_config (auth_policy_id, enabled) VALUES ('browzer-auth', true)`)
	reconciler := NewZitiReconciler(f.db, zap.NewNop(), newZitiProviderWith(zm), "").SetAssignmentEnforce(true)
	ours := map[string]bool{approvedApp.service: true, unapprovedApp.service: true, outOfScopeApp.service: true}
	desired, err := reconciler.loadDesiredRoutes(ctx)
	if err != nil {
		t.Fatalf("load the overlay routes: %v", err)
	}
	for _, d := range desired {
		if ours[d.ServiceName] {
			if err := reconciler.ensurePolicies(ctx, zm, d); err != nil {
				t.Fatalf("converge %s: %v", d.ServiceName, err)
			}
		}
	}
	// Every service is dialable by whoever holds its application, and by no
	// one else: a refusal below is the policy refusing, not a policy missing.
	for _, a := range []app{approvedApp, unapprovedApp, outOfScopeApp} {
		if got := overlay.dialRoles(a.service); !slices.Equal(got, []string{"#app-" + a.id}) {
			t.Fatalf("the Dial policy of %s names %v, want only #app-%s", a.service, got, a.id)
		}
	}
	// syncVendor patches the vendor identity's attributes, as the user sync's
	// staleness poll does.
	syncVendor := func() {
		t.Helper()
		if err := zm.SyncGroupAttributesForUser(bypass, f.external); err != nil {
			t.Fatalf("sync the vendor's overlay identity: %v", err)
		}
	}
	dials := func(a app) bool { return overlay.dials(a.service, vendorIdentity) }

	// ---- PAM ----
	connect := func(entryID string) (int, map[string]interface{}) {
		t.Helper()
		return f.call(f.external, http.MethodPost, "/pam/entries/"+entryID+"/connect", "{}")
	}
	launchStatus := func(launchID string) string {
		return f.scalar(`SELECT status FROM pam_entry_access_requests WHERE id = $1`, launchID)
	}

	// ---- the window opens ----
	appRequest := file("application", approvedApp.id)
	deniedRequest := file("application", unapprovedApp.id)
	entryRequest := file("pam_entry", approvedEntry)
	halfRequest := file("pam_entry", unapprovedEntry)
	for _, id := range []string{appRequest, entryRequest, halfRequest} {
		decide(sponsorToken, id, "approve")
	}
	decide(sponsorToken, deniedRequest, "deny")
	for _, id := range []string{appRequest, entryRequest} {
		decide(adminToken, id, "approve")
	}
	for id, want := range map[string]string{appRequest: "fulfilled", entryRequest: "fulfilled", deniedRequest: "denied", halfRequest: "pending"} {
		if got := statusOf(id); got != want {
			t.Fatalf("request %s is %s, want %s", id, got, want)
		}
	}
	syncVendor()
	if attrs := overlay.attributes(vendorIdentity); !slices.Contains(attrs, "browzer-users") {
		t.Fatalf("the vendor's identity carries %v: without #browzer-users it is not the clientless user this test is about", attrs)
	}

	var session string
	t.Run("in the window the vendor reaches the approved targets and nothing else", func(t *testing.T) {
		if ok, answer := signsIn(approvedApp); !ok {
			t.Errorf("OAuth: the approved application minted no code: %s", answer)
		}
		for _, a := range []app{unapprovedApp, outOfScopeApp} {
			if ok, answer := signsIn(a); ok || !strings.Contains(answer, "access_denied") {
				t.Errorf("OAuth: %s answered %s, want access_denied", a.clientID, answer)
			}
		}

		if ok, code := reaches(approvedApp); !ok {
			t.Errorf("proxy: the approved application answered %d, want the upstream", code)
		}
		for _, a := range []app{unapprovedApp, outOfScopeApp} {
			if ok, code := reaches(a); ok || code != http.StatusForbidden {
				t.Errorf("proxy: %s answered %d, want 403 before the upstream", a.host, code)
			}
		}

		if !dials(approvedApp) {
			t.Errorf("Ziti: the vendor cannot dial the approved application: identity %v", overlay.attributes(vendorIdentity))
		}
		for _, a := range []app{unapprovedApp, outOfScopeApp} {
			if dials(a) {
				t.Errorf("Ziti: the vendor dials %s", a.service)
			}
		}

		// The approved entry: the window's grant, and the sponsor's launch
		// approval that I5 asks of every external session.
		code, body := f.call(f.external, http.MethodPost, "/pam/entries/"+approvedEntry+"/request", `{"reason":"patching"}`)
		launch, _ := body["request_id"].(string)
		if code != http.StatusCreated || launch == "" {
			t.Fatalf("PAM: ask for a launch approval: %d %v", code, body)
		}
		if code, body := f.call(f.admin, http.MethodPost, "/pam/sponsored/entry-requests/"+launch+"/approve", "{}"); code != http.StatusOK {
			t.Fatalf("PAM: the sponsor approves the launch: %d %v", code, body)
		}
		if code, body := connect(approvedEntry); code != http.StatusOK {
			t.Fatalf("PAM: the approved entry: %d %v, want 200", code, body)
		}
		own := f.broker.conn("pam-" + approvedEntry + "-x-" + f.external)
		if own == nil {
			t.Fatal("PAM: the vendor's session has no connection on the broker")
		}
		session = f.broker.serving(own.ID, f.externalAccount)

		// The other two, each with a launch approval of its own, so that what
		// refuses them is the missing grant: the approval is not spent.
		for _, entryID := range []string{unapprovedEntry, outOfScopeEntry} {
			launch := f.approval(entryID)
			if code, body := connect(entryID); code != http.StatusForbidden || body["error"] != "not permitted" {
				t.Errorf("PAM: entry %s answered %d %v, want 403 not permitted", entryID, code, body)
			}
			if got := launchStatus(launch); got != "approved" {
				t.Errorf("PAM: the refused launch on %s spent its approval: %s", entryID, got)
			}
		}
	})

	// ---- the window closes ----
	// The grant governance wrote for the entry ends with the request's window.
	if same := f.scalar(`SELECT (g.expires_at = r.expires_at)::text FROM pam_entry_grants g
		JOIN access_requests r ON r.id = g.request_id WHERE g.request_id = $1`, entryRequest); same != "true" {
		t.Fatal("the entry's grant does not end with the request's window")
	}
	// Two hours and a minute pass: the window's end is behind both.
	f.exec(`UPDATE access_requests SET expires_at = expires_at - interval '2 hours 1 minute' WHERE id IN ($1, $2)`, appRequest, entryRequest)
	f.exec(`UPDATE pam_entry_grants SET expires_at = expires_at - interval '2 hours 1 minute' WHERE request_id = $1`, entryRequest)
	gsvc.RunJITExpiryOnce(ctx)
	for _, id := range []string{appRequest, entryRequest} {
		if got := statusOf(id); got != "expired" {
			t.Fatalf("request %s is %s after the expiry tick, want expired", id, got)
		}
	}
	// And the sweeps downstream of it run: the proxy's assignment answers are
	// thirty seconds old, the user sync patches the vendor's identity, and the
	// lifecycle sweep looks at the live sessions.
	f.svc.assignCache.Range(func(k, v interface{}) bool {
		e := v.(assignCacheEntry)
		e.at = e.at.Add(-groupCacheTTL)
		f.svc.assignCache.Store(k, e)
		return true
	})
	syncVendor()
	f.svc.runLifecycleEnforcement(bypass)

	t.Run("after the window every enforcement point refuses the vendor", func(t *testing.T) {
		if ok, answer := signsIn(approvedApp); ok || !strings.Contains(answer, "access_denied") {
			t.Errorf("OAuth: the expired application answered %s, want access_denied", answer)
		}
		if ok, code := reaches(approvedApp); ok || code != http.StatusForbidden {
			t.Errorf("proxy: the expired application answered %d, want 403 before the upstream", code)
		}
		if dials(approvedApp) {
			t.Errorf("Ziti: the vendor still dials the expired application: identity %v", overlay.attributes(vendorIdentity))
		}
		launch := f.approval(approvedEntry)
		if code, body := connect(approvedEntry); code != http.StatusForbidden || body["error"] != "not permitted" {
			t.Errorf("PAM: the expired entry answered %d %v, want 403 not permitted", code, body)
		}
		if got := launchStatus(launch); got != "approved" {
			t.Errorf("PAM: the refused launch spent its approval: %s", got)
		}
		if f.broker.isServing(session) {
			t.Error("PAM: the session opened in the window is still served after it")
		}
		row := f.scalar(`SELECT id::text || ' ' || status FROM pam_entry_sessions
			WHERE entry_id = $1 AND user_id = $2 ORDER BY started_at DESC LIMIT 1`, approvedEntry, f.external)
		sessionID, status, _ := strings.Cut(row, " ")
		if status != "ended" {
			t.Errorf("PAM: the session opened in the window is %s after it, want ended", status)
		}
		if got := f.scalar(`SELECT COALESCE(string_agg(details->>'reason', ','), '') FROM unified_audit_events
			WHERE event_type = 'pam.session_ended' AND details->>'session_id' = $1`, sessionID); got != sessionEndGrantEnded {
			t.Errorf("PAM: the session's end is audited with reasons %q, want %q", got, sessionEndGrantEnded)
		}
	})
}

// acceptanceTokens signs access tokens the way oauth-service signs the
// console's: RS256, typed at+jwt, naming their organization and allowed to
// call the OpenIDX API, with the key published at a JWKS URL.
type acceptanceTokens struct {
	key             *rsa.PrivateKey
	jwksURL, issuer string
	org             string
}

func newAcceptanceTokens(t *testing.T, org string) *acceptanceTokens {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]interface{}{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "acceptance",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(srv.Close)
	return &acceptanceTokens{key: key, jwksURL: srv.URL, issuer: "https://idp.example.test", org: org}
}

func (a *acceptanceTokens) token(t *testing.T, userID string, roles ...string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": userID, "org_id": a.org, "roles": roles, "openidx_api": true,
		"client_id": "admin-console", "iss": a.issuer,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["typ"] = "at+jwt"
	tok.Header["kid"] = "acceptance"
	signed, err := tok.SignedString(a.key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// acceptanceOverlay stands in for the Ziti controller: fakeController keeps the
// service policies the reconciler writes, and this keeps each identity's role
// attributes as the user sync reads and patches them.
type acceptanceOverlay struct {
	policies *fakeController
	mu       sync.Mutex
	attrs    map[string][]string
}

func (o *acceptanceOverlay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const identities = "/edge/management/v1/identities/"
	id := strings.TrimPrefix(r.URL.Path, identities)
	if id == r.URL.Path || id == "" || strings.Contains(id, "/") {
		o.policies.handler()(w, r)
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"id": id, "roleAttributes": o.attrs[id]}})
	case http.MethodPatch:
		var body struct {
			RoleAttributes *[]string `json:"roleAttributes"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.RoleAttributes != nil {
			o.attrs[id] = append([]string(nil), *body.RoleAttributes...)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"id": id}})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (o *acceptanceOverlay) attributes(identity string) []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.attrs[identity]...)
}

// dialRoles returns the identity roles of every Dial policy on the service.
func (o *acceptanceOverlay) dialRoles(service string) []string {
	o.policies.mu.Lock()
	defer o.policies.mu.Unlock()
	var roles []string
	for _, p := range o.policies.policies {
		if p.Type == "Dial" && slices.Contains(p.ServiceRoles, "#"+service) {
			roles = append(roles, p.IdentityRoles...)
		}
	}
	return roles
}

// dials reports whether the identity may dial the service: whether a Dial
// policy on the service names the identity, by its id or by an attribute it
// carries, which is how the controller reads a policy's identity roles.
func (o *acceptanceOverlay) dials(service, identity string) bool {
	attrs := o.attributes(identity)
	o.policies.mu.Lock()
	defer o.policies.mu.Unlock()
	for _, p := range o.policies.policies {
		if p.Type != "Dial" || !slices.Contains(p.ServiceRoles, "#"+service) {
			continue
		}
		for _, role := range p.IdentityRoles {
			switch {
			case role == "#all":
				return true
			case strings.HasPrefix(role, "@") && role[1:] == identity:
				return true
			case strings.HasPrefix(role, "#") && slices.Contains(attrs, role[1:]):
				return true
			}
		}
	}
	return false
}

// randomToken is a cookie value of the shape the services mint.
func randomToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
