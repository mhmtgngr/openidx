package access

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
	"github.com/openidx/openidx/internal/vault"
)

// The SSH CA signs a certificate only for an SSH entry the caller may connect
// to.
//
// POST /pam/connect/ssh used to sign whatever host and login the caller named,
// behind nothing but a fresh MFA step: any signed-in member of the
// organization could ask for root on every host whose sshd trusts the org CA.
// The certificate is a credential for a login on every such host, so the
// grant that decides it is the one on the PAM entry that registers the pair.
//
// The test drives the real handlers on the migrated schema with the vault the
// access service runs, makes entries and grants through the admin routes, and
// asks the CA for certificates as each kind of caller. The requireFreshMFA
// step in front of the route is a separate control and is not mounted here.
func TestSSHCertificateFollowsTheEntryGrant(t *testing.T) {
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

	const org = "00000000-0000-0000-0000-000000000010"      // seeded by migrations
	const otherOrg = "00000000-0000-0000-0000-0000000000e2" // a second tenant
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	seedUser := func(name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	admin := seedUser("ssh-admin")
	approver := seedUser("ssh-approver")
	granted := seedUser("ssh-granted")
	member := seedUser("ssh-member")
	viewer := seedUser("ssh-viewer")
	lapsed := seedUser("ssh-lapsed")
	stranger := seedUser("ssh-stranger")
	var group string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO groups (org_id, name) VALUES ($1::uuid, $2) RETURNING id::text`,
		org, "db-operators-"+suffix).Scan(&group); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1::uuid, $2::uuid, $3::uuid)`,
		member, group, org); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	// The audit service: records what the handlers post.
	type posted struct{ action, outcome, entryID, principal string }
	var mu sync.Mutex
	var events []posted
	auditSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var ev struct {
			Action  string                 `json:"action"`
			Outcome string                 `json:"outcome"`
			Details map[string]interface{} `json:"details"`
		}
		_ = json.Unmarshal(raw, &ev)
		entryID, _ := ev.Details["entry_id"].(string)
		principal, _ := ev.Details["principal"].(string)
		mu.Lock()
		events = append(events, posted{ev.Action, ev.Outcome, entryID, principal})
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(auditSrv.Close)

	logger := zap.NewNop()
	svc := &Service{db: db, config: &config.Config{}, logger: logger,
		auditService: NewUnifiedAuditService(db, logger), auditURL: auditSrv.URL}
	ring, err := vault.KeyringFromConfig(vault.KeyConfig{
		KEK: base64.StdEncoding.EncodeToString([]byte("ssh-ca-grant-test-kek-0123456789")),
	})
	if err != nil {
		t.Fatalf("vault keyring: %v", err)
	}
	vaultSvc, err := vault.NewService(db, ring, nil, time.Minute, logger)
	if err != nil {
		t.Fatalf("vault service: %v", err)
	}
	svc.SetVaultService(vaultSvc)

	as := func(userID string, roles ...string) *gin.Engine {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			c.Set("user_id", userID)
			c.Set("roles", append([]string{}, roles...))
			c.Next()
		})
		r.POST("/pam/ssh-ca/init", svc.handleInitSSHCA)
		r.POST("/pam/entries", svc.handlePamCreateEntry)
		r.POST("/pam/entries/:id/grants", svc.handlePamAddEntryGrant)
		r.POST("/pam/entries/:id/request", svc.handlePamRequestAccess)
		r.POST("/pam/entry-requests/:id/approve", svc.handlePamApproveRequest)
		r.POST("/pam/connect/ssh", svc.handleSSHConnect)
		return r
	}
	call := func(r *gin.Engine, path, body string) (int, map[string]interface{}) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	adminAPI := as(admin, "admin")
	code, body := call(adminAPI, "/pam/ssh-ca/init", "")
	caPub, _ := body["public_key"].(string)
	if code != http.StatusCreated || caPub == "" {
		t.Fatalf("init CA: %d %v", code, body)
	}

	createEntry := func(js string) string {
		t.Helper()
		code, body := call(adminAPI, "/pam/entries", js)
		id, _ := body["id"].(string)
		if code != http.StatusCreated || id == "" {
			t.Fatalf("create entry %s: %d %v", js, code, body)
		}
		return id
	}
	grant := func(entry, js string) {
		t.Helper()
		if code, body := call(adminAPI, "/pam/entries/"+entry+"/grants", js); code != http.StatusCreated {
			t.Fatalf("grant %s: %d %v", js, code, body)
		}
	}
	deploy := createEntry(`{"name":"db01 deploy","entry_type":"ssh","hostname":"db01.example.test","username":"deploy"}`)
	ops := createEntry(`{"name":"db01 ops","entry_type":"ssh","hostname":"db01.example.test","username":"ops","require_approval":true}`)
	cred := createEntry(`{"name":"svc login","entry_type":"credential","username":"svc"}`)
	linked := createEntry(`{"name":"db03","entry_type":"ssh","hostname":"db03.example.test","credential_entry_id":"` + cred + `"}`)
	connectGrant := func(principalType, principalID string) string {
		return `{"principal_type":"` + principalType + `","principal_id":"` + principalID + `","actions":["connect"]}`
	}
	grant(deploy, connectGrant("user", granted))
	grant(deploy, connectGrant("group", group))
	grant(deploy, `{"principal_type":"user","principal_id":"`+viewer+`","actions":["view"]}`)
	grant(deploy, `{"principal_type":"user","principal_id":"`+lapsed+`","actions":["connect"],"expires_at":"`+
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)+`"}`)
	grant(ops, connectGrant("user", granted))
	grant(linked, connectGrant("user", granted))

	// The same pair, registered and granted in another tenant.
	var foreign string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO pam_entries (org_id, name, entry_type, hostname, username)
		VALUES ($1::uuid, 'db02 deploy', 'ssh', 'db02.example.test', 'deploy') RETURNING id::text`,
		otherOrg).Scan(&foreign); err != nil {
		t.Fatalf("seed foreign entry: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
		VALUES ($1::uuid, $2::uuid, 'user', $3, '{connect}')`, otherOrg, foreign, granted); err != nil {
		t.Fatalf("seed foreign grant: %v", err)
	}

	certFor := func(userID, host, principal string, roles ...string) (int, map[string]interface{}) {
		t.Helper()
		return call(as(userID, roles...), "/pam/connect/ssh",
			`{"host":"`+host+`","principal":"`+principal+`","reason":"maintenance"}`)
	}
	// assertIssued checks the answer is a certificate the org CA signed for
	// exactly the principal, against the expected entry.
	assertIssued := func(t *testing.T, body map[string]interface{}, principal, entry string) {
		t.Helper()
		raw, _ := body["certificate"].(string)
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(raw))
		if err != nil {
			t.Fatalf("certificate does not parse: %v (%v)", err, body)
		}
		cert, ok := pk.(*ssh.Certificate)
		if !ok {
			t.Fatalf("answer is not a certificate: %T", pk)
		}
		if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != principal {
			t.Errorf("certificate principals = %v, want [%s]", cert.ValidPrincipals, principal)
		}
		if got := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert.SignatureKey))); got != caPub {
			t.Errorf("certificate signed by %q, want the org CA %q", got, caPub)
		}
		if body["entry_id"] != entry {
			t.Errorf("entry_id = %v, want %s", body["entry_id"], entry)
		}
	}

	for _, tc := range []struct {
		name      string
		user      string
		roles     []string
		host      string
		principal string
		wantEntry string // "" means refused
	}{
		{"a user granted connect gets the entry's login", granted, nil, "db01.example.test", "deploy", deploy},
		{"the host matches however it is spelt", granted, nil, " DB01.Example.TEST. ", "deploy", deploy},
		{"a member of a granted group gets the login", member, nil, "db01.example.test", "deploy", deploy},
		{"a login the user holds no entry for is refused", granted, nil, "db01.example.test", "root", ""},
		{"a host nobody registered is refused", granted, nil, "db09.example.test", "deploy", ""},
		{"a user with no grant is refused", stranger, nil, "db01.example.test", "deploy", ""},
		{"a view-only grant is refused", viewer, nil, "db01.example.test", "deploy", ""},
		{"a lapsed grant is refused", lapsed, nil, "db01.example.test", "deploy", ""},
		{"the login of a linked credential counts", granted, nil, "db03.example.test", "svc", linked},
		{"another tenant's entry and grant count for nothing here", granted, nil, "db02.example.test", "deploy", ""},
		{"an administrator gets a registered login without a grant", admin, []string{"admin"}, "db01.example.test", "deploy", deploy},
		{"an administrator is refused a login nobody registered", admin, []string{"admin"}, "db01.example.test", "root", ""},
		{"an administrator passes the approval gate, as on connect", admin, []string{"admin"}, "db01.example.test", "ops", ops},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := certFor(tc.user, tc.host, tc.principal, tc.roles...)
			if tc.wantEntry == "" {
				if code != http.StatusForbidden || body["code"] != "ssh_target_not_granted" {
					t.Fatalf("got %d %v, want 403 ssh_target_not_granted", code, body)
				}
				if _, leaked := body["certificate"]; leaked {
					t.Fatal("a refusal carried a certificate")
				}
				return
			}
			if code != http.StatusOK {
				t.Fatalf("got %d %v, want 200", code, body)
			}
			assertIssued(t, body, tc.principal, tc.wantEntry)
		})
	}

	t.Run("an entry that requires approval spends one approval per certificate", func(t *testing.T) {
		code, body := certFor(granted, "db01.example.test", "ops")
		if code != http.StatusForbidden || body["approval_required"] != true || body["entry_id"] != ops {
			t.Fatalf("before approval: %d %v, want 403 approval_required on the ops entry", code, body)
		}
		code, body = call(as(granted), "/pam/entries/"+ops+"/request", `{"reason":"rotate the ops key"}`)
		requestID, _ := body["request_id"].(string)
		if code != http.StatusCreated || requestID == "" {
			t.Fatalf("file request: %d %v", code, body)
		}
		if code, body := call(as(approver, "admin"), "/pam/entry-requests/"+requestID+"/approve", `{}`); code != http.StatusOK {
			t.Fatalf("approve: %d %v", code, body)
		}
		code, body = certFor(granted, "db01.example.test", "ops")
		if code != http.StatusOK {
			t.Fatalf("after approval: %d %v, want 200", code, body)
		}
		assertIssued(t, body, "ops", ops)
		if code, body := certFor(granted, "db01.example.test", "ops"); code != http.StatusForbidden || body["approval_required"] != true {
			t.Fatalf("second certificate on one approval: %d %v, want 403 approval_required", code, body)
		}
	})

	t.Run("a refusal records no session and is audited as a failure", func(t *testing.T) {
		var n int
		if err := db.Pool.QueryRow(ctx,
			`SELECT count(*) FROM brokered_sessions WHERE user_id = ANY($1::uuid[])`,
			[]string{stranger, viewer, lapsed}).Scan(&n); err != nil {
			t.Fatalf("count sessions: %v", err)
		}
		if n != 0 {
			t.Errorf("refused callers have %d brokered session(s), want 0", n)
		}
		if err := db.Pool.QueryRow(ctx,
			`SELECT count(*) FROM brokered_sessions WHERE user_id = $1::uuid AND principal = 'deploy'`,
			member).Scan(&n); err != nil || n != 1 {
			t.Errorf("the group member's certificate: %d session row(s), err %v, want 1", n, err)
		}

		deadline := time.Now().Add(3 * time.Second)
		var denied, issued bool
		for time.Now().Before(deadline) && !(denied && issued) {
			mu.Lock()
			for _, e := range events {
				if e.action == "pam.ssh_cert_denied" && e.outcome == "failure" && e.principal == "root" {
					denied = true
				}
				if e.action == "pam.ssh_cert_issued" && e.entryID == linked && e.principal == "svc" {
					issued = true
				}
			}
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}
		if !denied {
			t.Error("no pam.ssh_cert_denied event with outcome failure reached the audit service")
		}
		if !issued {
			t.Error("pam.ssh_cert_issued does not name the entry the certificate was issued against")
		}
	})
}

func TestNormalizeSSHHost(t *testing.T) {
	for in, want := range map[string]string{
		"db01.example.test":    "db01.example.test",
		" DB01.Example.TEST. ": "db01.example.test",
		"10.0.0.5":             "10.0.0.5",
		"":                     "",
		"   ":                  "",
	} {
		if got := normalizeSSHHost(in); got != want {
			t.Errorf("normalizeSSHHost(%q) = %q, want %q", in, got, want)
		}
	}
}
