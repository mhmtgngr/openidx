package access

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/migrations"
)

// fakeBroker stands in for the Guacamole API and remembers what it was told:
// each connection's parameters, the broker accounts it created and the READ
// permissions it granted.
type fakeBroker struct {
	mu          sync.Mutex
	nextID      int
	conns       map[string]*fakeBrokerConn
	accounts    map[string]bool
	permissions map[string][]string
	// failAccounts makes the broker refuse to read or create accounts, which
	// is how a per-user identity fails at the moment of launch.
	failAccounts bool
	// active is the sessions the broker is serving, by active-connection id;
	// profiles the sharing profiles, by id, naming their connection.
	active   map[string]fakeBrokerActive
	profiles map[string]string
}

type fakeBrokerActive struct{ Conn, User string }

type fakeBrokerConn struct {
	ID, Name, Protocol string
	Params             map[string]string
}

func newFakeBroker(t *testing.T) (*fakeBroker, string) {
	t.Helper()
	b := &fakeBroker{conns: map[string]*fakeBrokerConn{}, accounts: map[string]bool{}, permissions: map[string][]string{},
		active: map[string]fakeBrokerActive{}, profiles: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(b.serve))
	t.Cleanup(srv.Close)
	return b, srv.URL
}

func (b *fakeBroker) serve(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	const data = "/api/session/data/postgresql"
	type connBody struct {
		Name       string            `json:"name"`
		Protocol   string            `json:"protocol"`
		Parameters map[string]string `json:"parameters"`
	}
	path := r.URL.Path
	switch {
	case path == "/api/tokens":
		_, _ = w.Write([]byte(`{"authToken":"tok","dataSource":"postgresql"}`))
	case path == data+"/connections" && r.Method == http.MethodGet:
		out := map[string]map[string]string{}
		for id, c := range b.conns {
			out[id] = map[string]string{"identifier": id, "name": c.Name, "protocol": c.Protocol}
		}
		_ = json.NewEncoder(w).Encode(out)
	case path == data+"/connections" && r.Method == http.MethodPost:
		var body connBody
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, c := range b.conns {
			if c.Name == body.Name {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"message":"a connection with this name already exists"}`))
				return
			}
		}
		b.nextID++
		id := strconv.Itoa(b.nextID)
		b.conns[id] = &fakeBrokerConn{ID: id, Name: body.Name, Protocol: body.Protocol, Params: body.Parameters}
		_ = json.NewEncoder(w).Encode(map[string]string{"identifier": id})
	case strings.HasPrefix(path, data+"/connections/") && r.Method == http.MethodPut:
		c, ok := b.conns[strings.TrimPrefix(path, data+"/connections/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body connBody
		_ = json.NewDecoder(r.Body).Decode(&body)
		c.Name, c.Protocol, c.Params = body.Name, body.Protocol, body.Parameters
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(path, data+"/users/") && strings.HasSuffix(path, "/permissions"):
		account := strings.TrimSuffix(strings.TrimPrefix(path, data+"/users/"), "/permissions")
		var ops []map[string]string
		_ = json.NewDecoder(r.Body).Decode(&ops)
		for _, op := range ops {
			if op["op"] == "add" {
				b.permissions[account] = append(b.permissions[account], strings.TrimPrefix(op["path"], "/connectionPermissions/"))
			}
		}
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(path, data+"/users") && b.failAccounts:
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"broker down"}`))
	case strings.HasPrefix(path, data+"/users/") && r.Method == http.MethodGet:
		if !b.accounts[strings.TrimPrefix(path, data+"/users/")] {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	case path == data+"/users" && r.Method == http.MethodPost:
		var body struct {
			Username string `json:"username"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		b.accounts[body.Username] = true
		_, _ = w.Write([]byte(`{}`))
	case path == data+"/activeConnections" && r.Method == http.MethodGet:
		out := map[string]map[string]string{}
		for id, a := range b.active {
			out[id] = map[string]string{"connectionIdentifier": a.Conn, "username": a.User}
		}
		_ = json.NewEncoder(w).Encode(out)
	case path == data+"/activeConnections" && r.Method == http.MethodPatch:
		var ops []map[string]string
		_ = json.NewDecoder(r.Body).Decode(&ops)
		for _, op := range ops {
			if op["op"] == "remove" {
				delete(b.active, strings.TrimPrefix(op["path"], "/"))
			}
		}
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(path, data+"/activeConnections/") && strings.Contains(path, "/sharingCredentials/"):
		if _, live := b.active[strings.Split(strings.TrimPrefix(path, data+"/activeConnections/"), "/")[0]]; !live {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"values":{"key":"share-key"}}`))
	case path == data+"/sharingProfiles" && r.Method == http.MethodGet:
		out := map[string]map[string]string{}
		for id, conn := range b.profiles {
			out[id] = map[string]string{"identifier": id, "name": "openidx-readonly-share-" + conn, "primaryConnectionIdentifier": conn}
		}
		_ = json.NewEncoder(w).Encode(out)
	case path == data+"/sharingProfiles" && r.Method == http.MethodPost:
		var body struct {
			Primary string `json:"primaryConnectionIdentifier"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		b.nextID++
		id := "p" + strconv.Itoa(b.nextID)
		b.profiles[id] = body.Primary
		_ = json.NewEncoder(w).Encode(map[string]string{"identifier": id})
	default:
		_, _ = w.Write([]byte(`{}`))
	}
}

// serving marks connection connID as being used by account, as the browser
// opening the connect URL would, and returns the active-connection id.
func (b *fakeBroker) serving(connID, account string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextID++
	id := "active-" + strconv.Itoa(b.nextID)
	b.active[id] = fakeBrokerActive{Conn: connID, User: account}
	return id
}

func (b *fakeBroker) isServing(activeID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.active[activeID]
	return ok
}

// conn returns a copy of the named connection, or nil.
func (b *fakeBroker) conn(name string) *fakeBrokerConn {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.conns {
		if c.Name == name {
			params := map[string]string{}
			for k, v := range c.Params {
				params[k] = v
			}
			return &fakeBrokerConn{ID: c.ID, Name: c.Name, Protocol: c.Protocol, Params: params}
		}
	}
	return nil
}

func (b *fakeBroker) granted(account, connID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, id := range b.permissions[account] {
		if id == connID {
			return true
		}
	}
	return false
}

// auditTrail captures the events the access service posts to the audit
// service, which it does in the background.
type auditTrail struct {
	mu     sync.Mutex
	events []map[string]interface{}
}

func newAuditTrail(t *testing.T) (*auditTrail, string) {
	t.Helper()
	a := &auditTrail{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		ev := map[string]interface{}{}
		_ = json.Unmarshal(raw, &ev)
		a.mu.Lock()
		a.events = append(a.events, ev)
		a.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)
	return a, srv.URL
}

// has waits up to three seconds for an event with action and outcome whose
// details carry every key and value in want.
func (a *auditTrail) has(action, outcome string, want map[string]interface{}) bool {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		for _, ev := range a.events {
			if ev["action"] != action || ev["outcome"] != outcome {
				continue
			}
			details, _ := ev["details"].(map[string]interface{})
			match := true
			for k, v := range want {
				if details[k] != v {
					match = false
				}
			}
			if match {
				a.mu.Unlock()
				return true
			}
		}
		a.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// externalPamFixture is the org, the people and the service the I5/I7 tests
// share: an internal administrator who sponsors an activated external user, an
// internal operator, a fake broker behind both the direct and the overlay
// broker clients, and an audit trail.
type externalPamFixture struct {
	t                         *testing.T
	db                        *database.PostgresDB
	org, suffix               string
	admin, operator, external string
	externalAccount           string
	svc                       *Service
	broker                    *fakeBroker
	audit                     *auditTrail
}

func newExternalPamFixture(t *testing.T) *externalPamFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	f := &externalPamFixture{t: t, db: db, org: "00000000-0000-0000-0000-000000000010",
		suffix: strconv.FormatInt(time.Now().UnixNano(), 10)}
	f.admin = f.scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		f.org, "xp-admin-"+f.suffix)
	f.operator = f.scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		f.org, "xp-operator-"+f.suffix)
	vendor := f.scalar(`INSERT INTO vendor_organizations (org_id, name) VALUES ($1, $2) RETURNING id::text`, f.org, "Acme "+f.suffix)
	f.externalAccount = "xp-vendor-" + f.suffix + "@supplier.example.test"
	f.external = f.scalar(`
		INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
		VALUES ($1, $2, $3, 'external', $4, $5, NOW() + interval '30 days') RETURNING id::text`,
		f.org, "xp-vendor-"+f.suffix, f.externalAccount, vendor, f.admin)
	f.exec(`INSERT INTO mfa_totp (user_id, secret, enabled, org_id) VALUES ($1, 'JBSWY3DPEHPK3PXP', true, $2)`, f.external, f.org)

	var brokerURL, auditURL string
	f.broker, brokerURL = newFakeBroker(t)
	f.audit, auditURL = newAuditTrail(t)
	client := func(component string) *GuacamoleClient {
		return &GuacamoleClient{
			baseURL: brokerURL, publicBaseURL: brokerURL, dataSource: "postgresql", authToken: "tok",
			username: "guacadmin", password: "guacadmin",
			httpClient: testResilient(http.DefaultClient), logger: zap.NewNop(), db: db,
			component: component, perUserIdentities: true, tokenCipher: secretcrypt.NewNoop(),
		}
	}
	logger := zap.NewNop()
	f.svc = &Service{db: db, logger: logger, auditService: NewUnifiedAuditService(db, logger), auditURL: auditURL,
		config:          &config.Config{GuacamoleRecordingPath: "/recordings", PAMSSHRequireHostKey: true},
		guacamoleClient: client("guacamole"), guacamoleZitiClient: client("guacamole-ziti"),
		zitiProvider: newZitiProviderWith(&ZitiManager{})}
	return f
}

func (f *externalPamFixture) octx() context.Context {
	return orgctx.With(context.Background(), orgctx.Org{ID: f.org})
}

func (f *externalPamFixture) scalar(q string, args ...interface{}) string {
	f.t.Helper()
	var v string
	if err := f.db.Pool.QueryRow(f.octx(), q, args...).Scan(&v); err != nil {
		f.t.Fatalf("(%s): %v", q, err)
	}
	return v
}

func (f *externalPamFixture) exec(q string, args ...interface{}) {
	f.t.Helper()
	if _, err := f.db.Pool.Exec(f.octx(), q, args...); err != nil {
		f.t.Fatalf("(%s): %v", q, err)
	}
}

// entry creates a session entry and grants view, connect and reveal on it to
// the operator and the external user.
func (f *externalPamFixture) entry(name, entryType, reach string, port int, settings string) string {
	f.t.Helper()
	id := f.scalar(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port, username, reach_mode,
			require_approval, record_session, allow_reveal, break_glass_enabled, settings)
		VALUES ($1, $2, $3, $4, $5, 'deploy', $6, false, false, true, true, $7::jsonb) RETURNING id::text`,
		f.org, name+"-"+f.suffix, entryType, name+".example.test", port, reach, settings)
	for _, u := range []string{f.operator, f.external} {
		f.exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
			VALUES ($1, $2, 'user', $3, '{view,connect,reveal}')`, f.org, id, u)
	}
	return id
}

// approval files an approved launch request for the external user on entryID.
func (f *externalPamFixture) approval(entryID string) string {
	return f.scalar(`INSERT INTO pam_entry_access_requests (org_id, entry_id, requester_id, reason, status, expires_at)
		VALUES ($1, $2, $3, 'maintenance', 'approved', NOW() + interval '1 hour') RETURNING id::text`, f.org, entryID, f.external)
}

func (f *externalPamFixture) router(userID string, roles ...string) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: f.org}))
		c.Set("user_id", userID)
		c.Set("roles", append([]string{}, roles...))
		c.Next()
	})
	r.POST("/pam/entries/:id/connect", f.svc.handlePamConnect)
	r.POST("/pam/entries/:id/request", f.svc.handlePamRequestAccess)
	r.POST("/pam/entry-requests/:id/approve", f.svc.handlePamApproveRequest)
	r.POST("/pam/entry-requests/:id/deny", f.svc.handlePamDenyRequest)
	r.GET("/pam/sponsored/entry-requests", f.svc.handlePamListSponsoredRequests)
	r.POST("/pam/sponsored/entry-requests/:id/approve", f.svc.handlePamSponsorApproveRequest)
	r.POST("/pam/sponsored/entry-requests/:id/deny", f.svc.handlePamSponsorDenyRequest)
	r.GET("/pam/sponsored/sessions", f.svc.handlePamListSponsoredSessions)
	r.POST("/pam/sponsored/sessions/:id/watch", f.svc.handlePamSponsorWatchSession)
	r.POST("/pam/sponsored/sessions/:id/end", f.svc.handlePamSponsorEndSession)
	r.POST("/pam/apps/:id/launch", f.svc.handleWindowsAppLaunch)
	r.POST("/pam/entries/:id/reveal", f.svc.handlePamRevealEntry)
	r.POST("/pam/entries/:id/break-glass", f.svc.handlePamBreakGlass)
	r.POST("/pam/connect/ssh", f.svc.handleSSHConnect)
	r.POST("/pam/connect/cloud", f.svc.handleCloudConnect)
	r.GET("/pam/entries/:id/ws", f.svc.handlePamWSConnect)
	r.GET("/pam/entries", f.svc.handlePamListEntries)
	r.GET("/pam/entries/:id", f.svc.handlePamGetEntry)
	r.GET("/pam/broker/status", f.svc.handlePamBrokerStatus)
	r.GET("/guacamole/my-connections", f.svc.handleListMyGuacConnections)
	return r
}

func (f *externalPamFixture) call(userID, method, path, body string, roles ...string) (int, map[string]interface{}) {
	f.t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	f.router(userID, roles...).ServeHTTP(w, req)
	out := map[string]interface{}{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// I5 and I7 of the third-party access framework at the launch paths, on the
// migrated schema, through the real handlers and a broker that remembers what
// it was told. An external user's session is approved, recorded, on the
// overlay, hardened and on a broker connection and identity of its own,
// whatever the entry says; an internal user's session on the same entries is
// what the entries say.
func TestAnExternalUsersSessionRunsUnderTheEnforcedControls(t *testing.T) {
	f := newExternalPamFixture(t)
	settings := `{"enable-sftp":"true","disable-copy":"false","disable-paste":"false","recording-exclude-output":"true","color-scheme":"gray-black"}`
	maint := f.entry("maint", "ssh", "ziti", 22, settings)
	legacy := f.entry("legacy", "ssh", "direct", 22, `{}`)
	connect := func(userID, entryID string, roles ...string) (int, map[string]interface{}) {
		t.Helper()
		return f.call(userID, http.MethodPost, "/pam/entries/"+entryID+"/connect", "{}", roles...)
	}
	status := func(requestID string) string {
		return f.scalar(`SELECT status FROM pam_entry_access_requests WHERE id = $1`, requestID)
	}

	t.Run("the overlay holds for an external user whatever PAM_REQUIRE_ZTNA says", func(t *testing.T) {
		if code, body := connect(f.external, legacy); code != http.StatusForbidden || body["code"] != "ztna_required_direct_reach" {
			t.Errorf("an external user on a direct-reach entry with the gate off: %d %v, want 403 ztna_required_direct_reach", code, body)
		}
		if code, body := connect(f.operator, legacy); code != http.StatusOK {
			t.Errorf("an internal user on the same entry with the gate off: %d %v, want 200", code, body)
		}
		if !f.audit.has("pam.ztna.denied", "failure", map[string]interface{}{"code": "ztna_required_direct_reach", "external": true}) {
			t.Error("no pam.ztna.denied event marked external and failure reached the audit service")
		}
		// The launcher reads the mode to disable Connect before the click.
		if _, body := f.call(f.external, http.MethodGet, "/pam/broker/status", ""); body["require_ztna"] != "enforce" {
			t.Errorf("the broker status tells an external user require_ztna=%v, want enforce", body["require_ztna"])
		}
		if _, body := f.call(f.operator, http.MethodGet, "/pam/broker/status", ""); body["require_ztna"] != "off" {
			t.Errorf("the broker status tells an internal user require_ztna=%v, want the setting's off", body["require_ztna"])
		}
	})

	t.Run("an external user needs a launch approval whatever the entry says", func(t *testing.T) {
		if code, body := connect(f.external, maint); code != http.StatusForbidden || body["approval_required"] != true {
			t.Errorf("an external user on an entry that asks no approval: %d %v, want 403 approval_required", code, body)
		}
		if code, body := connect(f.operator, maint); code != http.StatusOK {
			t.Errorf("an internal user on the same entry: %d %v, want 200", code, body)
		}
		shared := f.broker.conn("pam-" + maint)
		if shared == nil {
			t.Fatal("the internal user's launch left no shared connection on the broker")
		}
		for k, want := range map[string]string{"enable-sftp": "true", "disable-copy": "false", "recording-exclude-output": "true"} {
			if shared.Params[k] != want {
				t.Errorf("the internal user's session has %s=%q, want the entry's %q", k, shared.Params[k], want)
			}
		}
		if _, recorded := shared.Params["recording-path"]; recorded {
			t.Error("the internal user's session on an entry that records nothing was recorded")
		}
	})

	t.Run("an approved external session is recorded, hardened and on its own connection and identity", func(t *testing.T) {
		code, body := f.call(f.external, http.MethodPost, "/pam/entries/"+maint+"/request", `{"reason":"patching"}`)
		requestID, _ := body["request_id"].(string)
		if code != http.StatusCreated || requestID == "" {
			t.Fatalf("an external user asks for a launch approval on an entry that asks none: %d %v, want 201", code, body)
		}
		if code, body := f.call(f.admin, http.MethodPost, "/pam/entry-requests/"+requestID+"/approve", "{}", "admin"); code != http.StatusOK {
			t.Fatalf("approve: %d %v", code, body)
		}
		sharedBefore := f.scalar(`SELECT COALESCE(guacamole_connection_id, '') FROM pam_entries WHERE id = $1`, maint)

		code, body = connect(f.external, maint)
		if code != http.StatusOK {
			t.Fatalf("an approved external user: %d %v, want 200", code, body)
		}
		if body["recorded"] != true {
			t.Errorf("the launch answers recorded=%v, want true", body["recorded"])
		}
		policy, _ := body["session_policy"].(map[string]interface{})
		if policy["clipboard"] != false || policy["file_transfer"] != false || policy["recorded"] != true {
			t.Errorf("the launch answers session_policy %v", policy)
		}
		if status(requestID) != "consumed" {
			t.Errorf("the approval is %s after the launch, want consumed", status(requestID))
		}

		own := f.broker.conn("pam-" + maint + "-x-" + f.external)
		if own == nil {
			t.Fatal("the external user's session has no connection of its own on the broker")
		}
		for k, want := range map[string]string{
			"disable-copy": "true", "disable-paste": "true", "enable-drive": "false", "enable-sftp": "false",
			"sftp-disable-download": "true", "sftp-disable-upload": "true", "disable-download": "true",
			"disable-upload": "true", "enable-printing": "false",
			"recording-path": "/recordings", "recording-include-keys": "true", "color-scheme": "gray-black",
		} {
			if own.Params[k] != want {
				t.Errorf("the external session's %s is %q, want %q", k, own.Params[k], want)
			}
		}
		if v, ok := own.Params["recording-exclude-output"]; ok {
			t.Errorf("the external session kept recording-exclude-output=%q", v)
		}
		if shared := f.broker.conn("pam-" + maint); shared == nil || shared.Params["enable-sftp"] != "true" {
			t.Error("the external user's launch rewrote the entry's shared connection")
		}
		if after := f.scalar(`SELECT COALESCE(guacamole_connection_id, '') FROM pam_entries WHERE id = $1`, maint); after != sharedBefore {
			t.Errorf("the entry's stored connection moved from %q to %q: the next internal launch would ride the external one", sharedBefore, after)
		}
		if !f.broker.granted(f.externalAccount, own.ID) {
			t.Error("the external user's broker account was not given its connection")
		}
		if shared := f.broker.conn("pam-" + maint); f.broker.granted(f.externalAccount, shared.ID) {
			t.Error("the external user's broker account was given the shared connection")
		}
		row := f.scalar(`SELECT COALESCE(recording_path, '') || ' ' || COALESCE(guac_username, '')
			FROM pam_entry_sessions WHERE entry_id = $1 AND user_id = $2 ORDER BY started_at DESC LIMIT 1`, maint, f.external)
		if !strings.HasPrefix(row, "/recordings/pam-"+maint+"-") || !strings.HasSuffix(row, " "+f.externalAccount) {
			t.Errorf("the external session's row reads %q, want a recording path and the user's own broker account", row)
		}

		if code, body := connect(f.external, maint); code != http.StatusForbidden || body["approval_required"] != true {
			t.Errorf("a second launch on a spent approval: %d %v, want 403 approval_required", code, body)
		}
	})

	t.Run("a launch that cannot be what I5 says is refused, before the approval where it can be", func(t *testing.T) {
		zitiBroker := f.svc.guacamoleZitiClient
		zitiBroker.perUserIdentities = false
		request := f.approval(maint)
		if code, body := connect(f.external, maint); code != http.StatusServiceUnavailable || body["code"] != "external_broker_identity_required" {
			t.Errorf("an external user on a broker without per-user identities: %d %v, want 503 external_broker_identity_required", code, body)
		}
		if status(request) != "approved" {
			t.Errorf("the refused launch spent the approval: it is %s", status(request))
		}
		if code, body := connect(f.operator, maint); code != http.StatusOK {
			t.Errorf("an internal user on the same broker: %d %v, want 200", code, body)
		}
		zitiBroker.perUserIdentities = true

		f.svc.config.GuacamoleRecordingPath = ""
		if code, body := connect(f.external, maint); code != http.StatusServiceUnavailable || body["code"] != "external_recording_unavailable" {
			t.Errorf("an external user with nowhere to record to: %d %v, want 503 external_recording_unavailable", code, body)
		}
		if status(request) != "approved" {
			t.Errorf("the refused launch spent the approval: it is %s", status(request))
		}
		f.svc.config.GuacamoleRecordingPath = "/recordings"

		// The per-user identity can also fail at the moment of launch, after
		// the approval is spent; the launch core then holds only a URL with
		// the shared token, which opens every connection on the broker, and
		// drops it rather than hand it to an external user.
		f.broker.mu.Lock()
		f.broker.failAccounts = true
		f.broker.mu.Unlock()
		f.exec(`DELETE FROM guacamole_users WHERE user_id = $1`, f.external)
		if code, body := connect(f.external, maint); code != http.StatusServiceUnavailable || body["code"] != "external_broker_identity_required" || body["connect_url"] != nil {
			t.Errorf("an external user whose broker account fails at launch: %d %v, want 503 external_broker_identity_required and no URL", code, body)
		}
		if code, body := connect(f.operator, maint); code != http.StatusOK || body["connect_url"] == nil {
			t.Errorf("an internal user on the same broker falls back to the shared token: %d %v, want 200", code, body)
		}
		f.broker.mu.Lock()
		f.broker.failAccounts = false
		f.broker.mu.Unlock()
		f.approval(maint)
		if code, body := connect(f.external, maint); code != http.StatusOK {
			t.Errorf("an approval once the broker is set up: %d %v, want 200", code, body)
		}
		if !f.audit.has("pam.launch_denied", "failure", map[string]interface{}{"code": "external_broker_identity_required"}) {
			t.Error("no pam.launch_denied event for the missing broker identity reached the audit service")
		}
	})

	t.Run("no administrator bypass applies to an external user", func(t *testing.T) {
		nogrant := f.scalar(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port, reach_mode)
			VALUES ($1, $2, 'ssh', 'nogrant.example.test', 22, 'ziti') RETURNING id::text`, f.org, "nogrant-"+f.suffix)
		if code, body := connect(f.external, nogrant, "admin"); code != http.StatusForbidden || body["error"] != "not permitted" {
			t.Errorf("an external user whose token claims admin, on an entry they hold no grant on: %d %v, want 403 not permitted", code, body)
		}
		if code, body := connect(f.admin, nogrant, "admin"); code != http.StatusOK {
			t.Errorf("an internal administrator on the same entry: %d %v, want 200", code, body)
		}
	})

	t.Run("a Windows app launch is held to the same controls", func(t *testing.T) {
		host := f.entry("apphost", "rdp", "ziti", 3389, `{"enable-drive":"true"}`)
		app := f.scalar(`INSERT INTO windows_apps (org_id, host_entry_id, alias, display_name)
			VALUES ($1, $2, 'notepad', 'Notepad') RETURNING id::text`, f.org, host)
		launch := func(userID string) (int, map[string]interface{}) {
			t.Helper()
			return f.call(userID, http.MethodPost, "/pam/apps/"+app+"/launch", "{}")
		}
		if code, body := launch(f.external); code != http.StatusForbidden || body["approval_required"] != true {
			t.Errorf("an external user's app launch with no approval: %d %v, want 403 approval_required", code, body)
		}
		f.approval(host)
		code, body := launch(f.external)
		if code != http.StatusOK || body["session_policy"] == nil {
			t.Fatalf("an approved external user's app launch: %d %v, want 200 with a session_policy", code, body)
		}
		own := f.broker.conn(fmt.Sprintf("pam-%s-app-%s-x-%s", host, app, f.external))
		if own == nil {
			t.Fatal("the external user's app session has no connection of its own")
		}
		if own.Params["enable-drive"] != "false" || own.Params["remote-app"] != "||notepad" || own.Params["recording-path"] != "/recordings" {
			t.Errorf("the external app session's parameters are %v", own.Params)
		}

		// The overlay gate, which this path did not ask before, for everyone.
		hostedApp := func(name, reach string) string {
			host := f.entry(name, "rdp", reach, 3389, `{}`)
			return f.scalar(`INSERT INTO windows_apps (org_id, host_entry_id, alias, display_name)
				VALUES ($1, $2, 'calc', 'Calculator') RETURNING id::text`, f.org, host)
		}
		directApp, overlayApp := hostedApp("directhost", "direct"), hostedApp("overlayhost", "ziti")
		f.svc.config.PAMRequireZTNA = "enforce"
		defer func() { f.svc.config.PAMRequireZTNA = "" }()
		if code, body := f.call(f.operator, http.MethodPost, "/pam/apps/"+directApp+"/launch", "{}"); code != http.StatusForbidden || body["code"] != "ztna_required_direct_reach" {
			t.Errorf("an internal user's app on a direct-reach host under enforce: %d %v, want 403 ztna_required_direct_reach", code, body)
		}
		if code, body := f.call(f.operator, http.MethodPost, "/pam/apps/"+overlayApp+"/launch", "{}"); code != http.StatusOK {
			t.Errorf("an internal user's app on an overlay host under enforce: %d %v, want 200", code, body)
		}
	})
}

// I5 at the paths that hand over a credential: an external user is refused
// reveal, break-glass, an SSH certificate and cloud keys, and the browser
// terminal, which records nothing. Each refusal is audited. An internal user
// with the same grants passes the external check and is answered by the
// entry's or the service's own state.
func TestAnExternalUserIsRefusedEveryCredentialPath(t *testing.T) {
	f := newExternalPamFixture(t)
	maint := f.entry("maint", "ssh", "ziti", 22, `{}`)
	legacy := f.entry("legacy", "ssh", "direct", 22, `{}`)
	missing := "00000000-0000-0000-0000-00000000dead"

	for _, c := range []struct {
		name, method, path, body string
		external                 string
		internalStatus           int
	}{
		{"reveal", http.MethodPost, "/pam/entries/" + maint + "/reveal", `{"reason":"maintenance"}`, "external_reveal_forbidden", http.StatusNotFound},
		{"break-glass", http.MethodPost, "/pam/entries/" + maint + "/break-glass", `{"reason":"the primary is down"}`, "external_reveal_forbidden", http.StatusBadRequest},
		{"an SSH certificate", http.MethodPost, "/pam/connect/ssh", `{"host":"maint.example.test","principal":"deploy"}`, "external_ssh_ca_forbidden", http.StatusServiceUnavailable},
		{"cloud keys", http.MethodPost, "/pam/connect/cloud",
			`{"role_arn":"arn:aws:iam::123456789012:role/ops","secret_id":"00000000-0000-0000-0000-0000000000aa"}`, "external_cloud_jit_forbidden", http.StatusServiceUnavailable},
		{"the browser terminal", http.MethodGet, "/pam/entries/" + maint + "/ws", "", "external_recording_unavailable", http.StatusForbidden},
	} {
		if code, body := f.call(f.external, c.method, c.path, c.body); code != http.StatusForbidden || body["code"] != c.external {
			t.Errorf("%s as an external user: %d %v, want 403 %s", c.name, code, body, c.external)
		}
		if code, body := f.call(f.operator, c.method, c.path, c.body); code != c.internalStatus || body["code"] != nil {
			t.Errorf("%s as an internal user with the same grants: %d %v, want %d from past the external check", c.name, code, body, c.internalStatus)
		}
	}
	if code, body := f.call(f.external, http.MethodPost, "/pam/entries/"+missing+"/reveal", `{"reason":"maintenance"}`); code != http.StatusForbidden || body["code"] != "external_reveal_forbidden" {
		t.Errorf("reveal of an entry that does not exist, as an external user: %d %v, want the same 403", code, body)
	}

	// The browser terminal now asks the overlay gate too, for everyone.
	f.svc.config.PAMRequireZTNA = "enforce"
	if code, body := f.call(f.operator, http.MethodGet, "/pam/entries/"+legacy+"/ws", ""); code != http.StatusForbidden || body["code"] != "ztna_required_direct_reach" {
		t.Errorf("the browser terminal on a direct-reach entry under enforce: %d %v, want 403 ztna_required_direct_reach", code, body)
	}
	f.svc.config.PAMRequireZTNA = ""

	for action, details := range map[string]map[string]interface{}{
		"pam.reveal_denied":   {"code": "external_reveal_forbidden", "path": "reveal", "entry_id": maint},
		"pam.ssh_cert_denied": {"code": "external_ssh_ca_forbidden", "host": "maint.example.test"},
		"pam.cloud_jit_denied": {"code": "external_cloud_jit_forbidden",
			"role_arn": "arn:aws:iam::123456789012:role/ops"},
		"pam.launch_denied": {"code": "external_recording_unavailable", "path": "browser_terminal"},
	} {
		if !f.audit.has(action, "failure", details) {
			t.Errorf("no %s event with %v and outcome failure reached the audit service", action, details)
		}
	}
	if !f.audit.has("pam.reveal_denied", "failure", map[string]interface{}{"path": "break_glass", "entry_id": maint}) {
		t.Error("no pam.reveal_denied event for break-glass reached the audit service")
	}

	// What the console reads says what the launch will do: an external user
	// is shown the approval and the recording their launch will have, and no
	// reveal or break-glass; an internal user is shown the entry's own row.
	listed := func(userID string) map[string]interface{} {
		t.Helper()
		code, body := f.call(userID, http.MethodGet, "/pam/entries", "")
		if code != http.StatusOK {
			t.Fatalf("list as %s: %d %v", userID, code, body)
		}
		entries, _ := body["entries"].([]interface{})
		for _, e := range entries {
			if m, _ := e.(map[string]interface{}); m["id"] == maint {
				return m
			}
		}
		t.Fatalf("the list as %s does not hold the entry", userID)
		return nil
	}
	shown := func(e map[string]interface{}) string {
		return fmt.Sprintf("approval=%v recorded=%v reveal=%v break_glass=%v actions=%v",
			e["require_approval"], e["record_session"], e["allow_reveal"], e["break_glass_enabled"], e["actions"])
	}
	if got, want := shown(listed(f.external)), "approval=true recorded=true reveal=false break_glass=false actions=[connect view]"; got != want {
		t.Errorf("the list shows an external user %s, want %s", got, want)
	}
	if got, want := shown(listed(f.operator)), "approval=false recorded=false reveal=true break_glass=true actions=[connect reveal view]"; got != want {
		t.Errorf("the list shows an internal user %s, want the entry's own %s", got, want)
	}
	if code, body := f.call(f.external, http.MethodGet, "/pam/entries/"+maint, ""); code != http.StatusOK ||
		shown(body) != "approval=true recorded=true reveal=false break_glass=false actions=<nil>" {
		t.Errorf("the entry shows an external user %d %s", code, shown(body))
	}

	// The same for a route-backed connection, as My Privileged Access lists it.
	route := f.scalar(`INSERT INTO proxy_routes (org_id, name, from_url, to_url, enabled)
		VALUES ($1, $2, $3, 'ssh://198.51.100.9:22', true) RETURNING id::text`,
		f.org, "bastion-"+f.suffix, "https://bastion-"+f.suffix+".example.test")
	f.exec(`INSERT INTO guacamole_connections (route_id, org_id, guacamole_connection_id, protocol, hostname, port, require_approval, record_session)
		VALUES ($1, $2, $3, 'ssh', '198.51.100.9', 22, false, false)`, route, f.org, "guac-"+f.suffix)
	routeEntry := f.scalar(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port, proxy_route_id, require_approval, record_session)
		VALUES ($1, $2, 'ssh', '198.51.100.9', 22, $3, false, false) RETURNING id::text`, f.org, "bastion-"+f.suffix, route)
	for _, u := range []string{f.operator, f.external} {
		f.exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
			VALUES ($1, $2, 'user', $3, '{connect}')`, f.org, routeEntry, u)
	}
	routeShownOf := func(userID, routeID string, roles ...string) string {
		t.Helper()
		_, body := f.call(userID, http.MethodGet, "/guacamole/my-connections", "", roles...)
		conns, _ := body["connections"].([]interface{})
		for _, c := range conns {
			if m, _ := c.(map[string]interface{}); m["route_id"] == routeID {
				return fmt.Sprintf("approval=%v recorded=%v", m["require_approval"], m["record_session"])
			}
		}
		return "not listed"
	}
	routeShown := func(userID string) string { return routeShownOf(userID, route) }
	if got := routeShown(f.external); got != "approval=true recorded=true" {
		t.Errorf("My Privileged Access shows an external user %s, want approval=true recorded=true", got)
	}
	if got := routeShown(f.operator); got != "approval=false recorded=false" {
		t.Errorf("My Privileged Access shows an internal user %s, want the entry's own approval=false recorded=false", got)
	}
	// A route nobody granted: an administrator sees it, an external user
	// whose token claims admin does not.
	closed := f.scalar(`INSERT INTO proxy_routes (org_id, name, from_url, to_url, enabled)
		VALUES ($1, $2, $3, 'ssh://198.51.100.10:22', true) RETURNING id::text`,
		f.org, "closed-"+f.suffix, "https://closed-"+f.suffix+".example.test")
	f.exec(`INSERT INTO guacamole_connections (route_id, org_id, guacamole_connection_id, protocol, hostname, port, require_approval, record_session)
		VALUES ($1, $2, $3, 'ssh', '198.51.100.10', 22, false, false)`, closed, f.org, "guac-closed-"+f.suffix)
	f.exec(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port, proxy_route_id)
		VALUES ($1, $2, 'ssh', '198.51.100.10', 22, $3)`, f.org, "closed-"+f.suffix, closed)
	if got := routeShownOf(f.external, closed, "admin"); got != "not listed" {
		t.Errorf("My Privileged Access shows an external user whose token claims admin an ungranted route: %s", got)
	}
	if got := routeShownOf(f.admin, closed, "admin"); got == "not listed" {
		t.Error("My Privileged Access does not show an internal administrator the ungranted route")
	}
}

// I7's ceiling at the lifecycle sweep: an external user's session ends once it
// has run longer than externalid.MaxPamSession, whatever grant it rides, and
// is audited with reason max_duration; an internal user's session of the same
// age and a younger external session run on. When the grant has ended too,
// the reason is grant_ended.
func TestAnExternalSessionEndsAtItsMaximumDuration(t *testing.T) {
	f := newExternalPamFixture(t)
	maint := f.entry("maint", "ssh", "ziti", 22, `{}`)
	ungranted := f.scalar(`INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
		SELECT org_id, $2::text, $2::text || '@supplier.example.test', 'external', vendor_org_id, sponsor_user_id, account_expires_at
		  FROM users WHERE id = $1 RETURNING id::text`, f.external, "xp-ungranted-"+f.suffix)
	session := func(userID, age string, bypass interface{}) string {
		return f.scalar(`INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol, admin_bypass, started_at)
			VALUES ($1, $2, $3, 'ssh', $4, NOW() - $5::interval) RETURNING id::text`, f.org, maint, userID, bypass, age)
	}
	none := []string{}
	sessions := map[string]string{
		"external9h":       session(f.external, "9 hours", none),
		"externalLegacy9h": session(f.external, "9 hours", nil),
		"external1h":       session(f.external, "1 hour", none),
		"internal9h":       session(f.operator, "9 hours", none),
		"ungranted9h":      session(ungranted, "9 hours", none),
	}
	want := map[string]string{
		"external9h": "ended max_duration", "externalLegacy9h": "ended max_duration",
		"external1h": "active ", "internal9h": "active ",
		"ungranted9h": "ended grant_ended",
	}
	f.svc.runLifecycleEnforcement(orgctx.WithBypassRLS(context.Background()))
	for name, w := range want {
		got := f.scalar(`SELECT s.status || ' ' || COALESCE((SELECT string_agg(e.details->>'reason', ',')
				FROM unified_audit_events e WHERE e.event_type = 'pam.session_ended' AND e.details->>'session_id' = s.id::text), '')
			FROM pam_entry_sessions s WHERE s.id = $1`, sessions[name])
		if got != w {
			t.Errorf("the %s session reads %q after the sweep, want %q", name, got, w)
		}
	}
}
