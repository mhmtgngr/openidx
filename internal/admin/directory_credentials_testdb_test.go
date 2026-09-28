package admin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
	"github.com/openidx/openidx/internal/directory"
)

// THE DIRECTORIES' CREDENTIALS, AT REST AND ON THE WAY OUT.
//
// POST and PUT /api/v1/directories stored the LDAP bind password, the Azure
// AD client secret and the HR system's API key in directory_integrations.config
// as they came, in plaintext, and GET /directories and /directories/:id
// returned them, as did the create response.
//
// Driven through RegisterRoutes, wired as cmd/admin-api wires it (the admin
// service, keyed by ENCRYPTION_KEY, and the directory service it syncs and
// tests with, given the same key), against a migrated database, an LDAP
// server and an HR API that record the credentials they receive:
//   - each credential is stored sealed, opening with the key, and no read or
//     create response returns it, sealed or not: <key>_set says one is stored;
//   - the connection test, a sync and the login pass-through the identity and
//     oauth services make sign in with the opened credential;
//   - an update that leaves the credential out keeps it for the same target,
//     and is refused for another host, endpoint or TLS setting;
//   - a credential stored in plaintext by an earlier release is never
//     returned, still works, and is sealed by the next save, or by the startup
//     sweep, which seals each such row once and needs a key to;
//   - one sealed with a key this service does not hold is refused before
//     anything is sent, with the reason, and works once it is sent again;
//   - a sealed value from a client is refused, so the API cannot be made to
//     open another directory's credential for a server of the caller's
//     choosing;
//   - a plain user reads none of it.
func TestDirectoryCredentialsAreSealedAndNeverReturned(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	t.Cleanup(cleanup)
	ctx := orgctx.WithBypassRLS(context.Background())
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	const key = "0123456789abcdef0123456789abcdef"
	cipher, err := secretcrypt.New(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}

	var org string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, "dirs-"+suffix).Scan(&org); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	seedUser := func(name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	admin, plain := seedUser("admin"), seedUser("user")
	callers := map[string][]string{admin: {"admin"}, plain: {"user"}}

	svc := NewService(db, &database.RedisClient{}, &config.Config{EncryptionKey: key}, zap.NewNop())
	dirSvc := directory.NewService(db, zap.NewNop(), cipher)
	svc.SetDirectoryService(&directorySyncerForTest{dirSvc})

	r := gin.New()
	v1 := r.Group("/api/v1")
	v1.Use(func(c *gin.Context) {
		who := c.GetHeader("X-Test-Caller")
		c.Set("user_id", who)
		c.Set("roles", callers[who])
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Next()
	})
	RegisterRoutes(v1, svc)

	do := func(who, method, path, body string) (int, string) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-Caller", who)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	stored := func(id, k string) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx,
			`SELECT COALESCE(config ->> $2, '') FROM directory_integrations WHERE id = $1::uuid`, id, k).Scan(&v); err != nil {
			t.Fatalf("read stored config: %v", err)
		}
		return v
	}
	storedConfig := func(id string) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx,
			`SELECT config::text FROM directory_integrations WHERE id = $1::uuid`, id).Scan(&v); err != nil {
			t.Fatalf("read stored config: %v", err)
		}
		return v
	}
	mustBeSealed := func(t *testing.T, id, k, want string) string {
		t.Helper()
		sealed := stored(id, k)
		if !secretcrypt.IsEncrypted(sealed) || strings.Contains(sealed, want) {
			t.Fatalf("the stored %s is %q, not a sealed value", k, sealed)
		}
		if got, err := cipher.Decrypt(sealed); err != nil || got != want {
			t.Fatalf("the stored %s opens as %q (%v), want %q", k, got, err, want)
		}
		return sealed
	}
	secretFields := []string{`"bind_password":`, `"client_secret":`, `"api_key":`}
	returnsNone := func(t *testing.T, what, body string, secrets ...string) {
		t.Helper()
		for _, s := range secrets {
			if strings.Contains(body, s) {
				t.Errorf("%s returned a stored credential (%q): %s", what, s, body)
			}
		}
		for _, f := range secretFields {
			if strings.Contains(body, f) {
				t.Errorf("%s returned a %s field: %s", what, f, body)
			}
		}
	}
	readsNeverReturn := func(t *testing.T, id, setFlag string, secrets ...string) {
		t.Helper()
		for _, path := range []string{"/api/v1/directories", "/api/v1/directories/" + id} {
			code, body := do(admin, http.MethodGet, path, "")
			if code != http.StatusOK {
				t.Fatalf("GET %s: %d %s", path, code, body)
			}
			returnsNone(t, "GET "+path, body, secrets...)
		}
		_, body := do(admin, http.MethodGet, "/api/v1/directories/"+id, "")
		if !strings.Contains(body, `"`+setFlag+`":true`) {
			t.Errorf("GET /directories/%s does not say a credential is stored: %s", id, body)
		}
	}
	create := func(t *testing.T, name, dirType string, cfg map[string]any) string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"name": name + "-" + suffix, "type": dirType, "config": cfg, "enabled": true})
		code, resp := do(admin, http.MethodPost, "/api/v1/directories", string(body))
		if code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", name, code, resp)
		}
		secret, _ := cfg[directory.SecretKeyFor(dirType)].(string)
		returnsNone(t, "the create response", resp, secret)
		if !strings.Contains(resp, `"`+directory.SecretSetKey(directory.SecretKeyFor(dirType))+`":true`) {
			t.Errorf("the create response does not say a credential is stored: %s", resp)
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(resp), &created); err != nil || created.ID == "" {
			t.Fatalf("create %s: no id in %s", name, resp)
		}
		return created.ID
	}
	update := func(id, name, dirType string, cfg map[string]any) (int, string) {
		body, _ := json.Marshal(map[string]any{"name": name, "type": dirType, "config": cfg, "enabled": true})
		return do(admin, http.MethodPut, "/api/v1/directories/"+id, string(body))
	}
	seedRow := func(name, dirType, cfg string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO directory_integrations (id, name, type, config, enabled, sync_status, org_id)
			VALUES (gen_random_uuid(), $1, $2, $3::jsonb, true, 'never', $4::uuid) RETURNING id::text`,
			name+"-"+suffix, dirType, cfg, org).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		return id
	}
	syncOutcome := func(t *testing.T, id string) (string, string) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for {
			var status, msg string
			err := db.Pool.QueryRow(ctx, `
				SELECT status, COALESCE(error_message, '') FROM directory_sync_logs
				 WHERE directory_id = $1::uuid ORDER BY started_at DESC LIMIT 1`, id).Scan(&status, &msg)
			if err == nil && status != "running" {
				return status, msg
			}
			if time.Now().After(deadline) {
				t.Fatalf("the sync of %s did not finish (%q, %v)", id, status, err)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	ldapSrv := newFakeLDAPServer(t)
	hr := newFakeHRAPI(t)
	collector := newFakeHRAPI(t)

	const bindDN = "cn=svc,dc=example,dc=test"
	const bindPassword = "Bind-S3cret"
	const clientSecret = "Az-S3cret"
	const apiKey = "HR-K3y"
	ldapConfig := func() map[string]any {
		return map[string]any{
			"host": "127.0.0.1", "port": ldapSrv.port(), "bind_dn": bindDN, "bind_password": bindPassword,
			"base_dn": "dc=example,dc=test", "user_filter": "(objectClass=person)",
			"attribute_mapping": map[string]any{"username": "uid", "email": "mail"},
		}
	}
	hrConfig := func(base string) map[string]any {
		return map[string]any{"provider": "bamboohr", "base_url": base, "subdomain": "acme", "api_key": apiKey}
	}
	without := func(cfg map[string]any, k string) map[string]any {
		delete(cfg, k)
		return cfg
	}

	var ldapID, azureID, hrID string
	t.Run("each credential is stored sealed, and the create response returns none", func(t *testing.T) {
		ldapID = create(t, "ldap", "ldap", ldapConfig())
		azureID = create(t, "entra", "azure_ad", map[string]any{"tenant_id": "tenant-1", "client_id": "client-1", "client_secret": clientSecret})
		hrID = create(t, "hr", "hris", hrConfig(hr.URL))
		mustBeSealed(t, ldapID, "bind_password", bindPassword)
		mustBeSealed(t, azureID, "client_secret", clientSecret)
		mustBeSealed(t, hrID, "api_key", apiKey)
	})

	t.Run("no read returns one, sealed or not", func(t *testing.T) {
		all := []string{bindPassword, clientSecret, apiKey, stored(ldapID, "bind_password"), stored(azureID, "client_secret"), stored(hrID, "api_key")}
		readsNeverReturn(t, ldapID, "bind_password_set", all...)
		readsNeverReturn(t, azureID, "client_secret_set", all...)
		readsNeverReturn(t, hrID, "api_key_set", all...)
	})

	t.Run("a plain user reads none of it", func(t *testing.T) {
		if code, body := do(plain, http.MethodGet, "/api/v1/directories", ""); code != http.StatusForbidden {
			t.Errorf("a plain user listed the directories: %d %s", code, body)
		}
	})

	t.Run("the connection test signs in with the opened credential", func(t *testing.T) {
		if code, body := do(admin, http.MethodPost, "/api/v1/directories/"+ldapID+"/test", ""); code != http.StatusOK {
			t.Fatalf("test the LDAP directory: %d %s", code, body)
		}
		if got := ldapSrv.lastBind(t); got.dn != bindDN || got.password != bindPassword {
			t.Fatalf("the LDAP server got a bind as %q with %q", got.dn, got.password)
		}
		if code, body := do(admin, http.MethodPost, "/api/v1/directories/"+hrID+"/test", ""); code != http.StatusOK {
			t.Fatalf("test the HR directory: %d %s", code, body)
		}
		if got := hr.lastKey(t); got != apiKey {
			t.Fatalf("the HR API got the key %q", got)
		}
	})

	t.Run("so does a sync", func(t *testing.T) {
		before := hr.count()
		if code, body := do(admin, http.MethodPost, "/api/v1/directories/"+hrID+"/sync", ""); code != http.StatusOK {
			t.Fatalf("sync: %d %s", code, body)
		}
		if status, msg := syncOutcome(t, hrID); status != "success" {
			t.Fatalf("the sync ended %q: %s", status, msg)
		}
		if hr.count() == before || hr.lastKey(t) != apiKey {
			t.Fatalf("the sync did not sign in to the HR API with the key: %v", hr.received())
		}
	})

	t.Run("and so does the login pass-through the identity and oauth services make", func(t *testing.T) {
		before := ldapSrv.count()
		// No such user on the fake server, so the bind that matters is the
		// service account's, which finds the user.
		_ = dirSvc.VerifyPassword(orgctx.With(context.Background(), orgctx.Org{ID: org}), ldapID, "alice", "alice-password")
		if ldapSrv.count() == before {
			t.Fatal("the login pass-through did not bind")
		}
		if got := ldapSrv.binds()[before]; got.dn != bindDN || got.password != bindPassword {
			t.Fatalf("the login pass-through bound as %q with %q", got.dn, got.password)
		}
	})

	t.Run("an update that leaves the credential out keeps it, for the same target", func(t *testing.T) {
		sealedBefore := stored(ldapID, "bind_password")
		cfg := without(ldapConfig(), "bind_password")
		cfg["bind_password_set"] = true // a read sent back
		cfg["user_filter"] = "(objectClass=inetOrgPerson)"
		if code, body := update(ldapID, "ldap-renamed-"+suffix, "ldap", cfg); code != http.StatusOK {
			t.Fatalf("update without the bind password: %d %s", code, body)
		}
		if got := stored(ldapID, "bind_password"); got != sealedBefore {
			t.Fatalf("the stored bind password changed to %q", got)
		}
		if strings.Contains(storedConfig(ldapID), "_set") {
			t.Errorf("a read's flag was stored: %s", storedConfig(ldapID))
		}
		if code, body := do(admin, http.MethodPost, "/api/v1/directories/"+ldapID+"/test", ""); code != http.StatusOK {
			t.Fatalf("test after the update: %d %s", code, body)
		}
		if got := ldapSrv.lastBind(t); got.password != bindPassword {
			t.Fatalf("after the update the LDAP server got %q", got.password)
		}

		if code, body := update(hrID, "hr-renamed-"+suffix, "hris", without(hrConfig(hr.URL), "api_key")); code != http.StatusOK {
			t.Fatalf("update without the API key: %d %s", code, body)
		}
		mustBeSealed(t, hrID, "api_key", apiKey)
		if code, body := update(azureID, "entra-renamed-"+suffix, "azure_ad",
			map[string]any{"tenant_id": "tenant-1", "client_id": "client-1", "client_secret": ""}); code != http.StatusOK {
			t.Fatalf("update with an empty client secret: %d %s", code, body)
		}
		mustBeSealed(t, azureID, "client_secret", clientSecret)
	})

	t.Run("and not for another target", func(t *testing.T) {
		hrBefore, ldapBefore := storedConfig(hrID), storedConfig(ldapID)
		code, body := update(hrID, "hr-"+suffix, "hris", without(hrConfig(collector.URL), "api_key"))
		if code != http.StatusBadRequest || !strings.Contains(body, "config.api_key") || !strings.Contains(body, "kept only while") {
			t.Fatalf("moving the HR directory to another endpoint without its key: %d %s", code, body)
		}
		for name, change := range map[string]func(map[string]any){
			"another host":             func(c map[string]any) { c["host"] = "ldap-2.example.test" },
			"another port":             func(c map[string]any) { c["port"] = 3389 },
			"another bind DN":          func(c map[string]any) { c["bind_dn"] = "cn=other,dc=example,dc=test" },
			"TLS verification off":     func(c map[string]any) { c["skip_tls_verify"] = true },
			"referrals followed":       func(c map[string]any) { c["follow_referrals"] = true },
			"StartTLS turned on":       func(c map[string]any) { c["start_tls"] = true },
			"a directory of each type": func(c map[string]any) {},
		} {
			cfg := without(ldapConfig(), "bind_password")
			change(cfg)
			dirType := "ldap"
			if name == "a directory of each type" {
				dirType = "active_directory"
			}
			code, body := update(ldapID, "ldap-"+suffix, dirType, cfg)
			if code != http.StatusBadRequest || !strings.Contains(body, "config.bind_password") {
				t.Errorf("%s, without the bind password: %d %s", name, code, body)
			}
		}
		if storedConfig(hrID) != hrBefore || storedConfig(ldapID) != ldapBefore {
			t.Fatal("a refused update changed what is stored")
		}
		if n := collector.count(); n != 0 {
			t.Fatalf("the other endpoint was sent %d request(s): %v", n, collector.received())
		}

		cfg := hrConfig(collector.URL)
		cfg["api_key"] = "Collector-K3y"
		if code, body := update(hrID, "hr-"+suffix, "hris", cfg); code != http.StatusOK {
			t.Fatalf("moving it with a key of its own: %d %s", code, body)
		}
		mustBeSealed(t, hrID, "api_key", "Collector-K3y")
		if code, body := do(admin, http.MethodPost, "/api/v1/directories/"+hrID+"/test", ""); code != http.StatusOK {
			t.Fatalf("test after the move: %d %s", code, body)
		}
		if got := collector.lastKey(t); got != "Collector-K3y" {
			t.Fatalf("the new endpoint got %q", got)
		}
	})

	// A row as an earlier release left it: the credential in plaintext.
	t.Run("a credential stored in plaintext by an earlier release is never returned, still works, and is sealed by the next save", func(t *testing.T) {
		legacy, _ := json.Marshal(hrConfig(hr.URL))
		legacy = bytes.Replace(legacy, []byte(apiKey), []byte("Legacy-K3y"), 1)
		legacyID := seedRow("hr-legacy", "hris", string(legacy))
		if got := stored(legacyID, "api_key"); got != "Legacy-K3y" {
			t.Fatalf("the legacy fixture stored %q", got)
		}
		readsNeverReturn(t, legacyID, "api_key_set", "Legacy-K3y")
		if code, body := do(admin, http.MethodPost, "/api/v1/directories/"+legacyID+"/test", ""); code != http.StatusOK {
			t.Fatalf("test the legacy directory: %d %s", code, body)
		}
		if got := hr.lastKey(t); got != "Legacy-K3y" {
			t.Fatalf("the HR API got %q", got)
		}
		if code, body := update(legacyID, "hr-legacy-"+suffix, "hris", without(hrConfig(hr.URL), "api_key")); code != http.StatusOK {
			t.Fatalf("save the legacy directory: %d %s", code, body)
		}
		mustBeSealed(t, legacyID, "api_key", "Legacy-K3y")
	})

	// A key rotated out without cmd/rekey leaves a sealed value this service
	// cannot open. Sent as it is, it would be a wrong password, which a
	// directory server counts toward the service account's lockout.
	t.Run("a credential sealed with a key this service does not hold is refused, and nothing is sent", func(t *testing.T) {
		other, err := secretcrypt.New("fedcba9876543210fedcba9876543210")
		if err != nil {
			t.Fatalf("cipher: %v", err)
		}
		foreign, err := other.Encrypt("Rotated-Out-1")
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		cfg := ldapConfig()
		cfg["bind_password"] = foreign
		raw, _ := json.Marshal(cfg)
		foreignID := seedRow("ldap-foreign", "ldap", string(raw))
		readsNeverReturn(t, foreignID, "bind_password_set", foreign)

		binds := ldapSrv.count()
		code, body := do(admin, http.MethodPost, "/api/v1/directories/"+foreignID+"/test", "")
		if code != http.StatusBadRequest || !strings.Contains(body, "cannot be decrypted") || strings.Contains(body, foreign) {
			t.Fatalf("a test with a credential the key cannot open: %d %s", code, body)
		}
		code, body = do(admin, http.MethodPost, "/api/v1/directories/"+foreignID+"/diagnose", "")
		if code != http.StatusBadRequest || !strings.Contains(body, "cannot be decrypted") {
			t.Fatalf("diagnostics with a credential the key cannot open: %d %s", code, body)
		}
		err = dirSvc.VerifyPassword(orgctx.With(context.Background(), orgctx.Org{ID: org}), foreignID, "alice", "alice-password")
		if err == nil || !strings.Contains(err.Error(), "cannot be decrypted") {
			t.Fatalf("the login pass-through with a credential the key cannot open: %v", err)
		}
		if code, body := do(admin, http.MethodPost, "/api/v1/directories/"+foreignID+"/sync", ""); code != http.StatusOK {
			t.Fatalf("sync: %d %s", code, body)
		}
		if status, msg := syncOutcome(t, foreignID); status != "failed" || !strings.Contains(msg, "cannot be decrypted") {
			t.Fatalf("the sync with a credential the key cannot open ended %q: %q", status, msg)
		}
		if ldapSrv.count() != binds {
			t.Fatalf("the LDAP server was sent a bind: %v", ldapSrv.lastBind(t))
		}

		code, body = update(foreignID, "ldap-foreign-"+suffix, "ldap", without(ldapConfig(), "bind_password"))
		if code != http.StatusBadRequest || !strings.Contains(body, "cannot be decrypted with this service's ENCRYPTION_KEY; send it again") {
			t.Fatalf("an update keeping a credential the key cannot open: %d %s", code, body)
		}
		if code, body := update(foreignID, "ldap-foreign-"+suffix, "ldap", ldapConfig()); code != http.StatusOK {
			t.Fatalf("sent again: %d %s", code, body)
		}
		mustBeSealed(t, foreignID, "bind_password", bindPassword)
		if code, body := do(admin, http.MethodPost, "/api/v1/directories/"+foreignID+"/test", ""); code != http.StatusOK {
			t.Fatalf("test once it is sent again: %d %s", code, body)
		}
	})

	t.Run("a sealed value from a client is refused, so the API opens none for the caller", func(t *testing.T) {
		sealed := stored(ldapID, "bind_password")
		lure := newFakeLDAPServer(t)
		cfg := ldapConfig()
		cfg["port"] = lure.port()
		cfg["bind_password"] = sealed
		body, _ := json.Marshal(map[string]any{"name": "lure-" + suffix, "type": "ldap", "config": cfg, "enabled": true})
		if code, resp := do(admin, http.MethodPost, "/api/v1/directories", string(body)); code != http.StatusBadRequest || !strings.Contains(resp, "sealed value is not accepted") {
			t.Fatalf("create with a sealed bind password: %d %s", code, resp)
		}
		if code, resp := update(hrID, "hr-"+suffix, "ldap", cfg); code != http.StatusBadRequest || !strings.Contains(resp, "sealed value is not accepted") {
			t.Fatalf("update with a sealed bind password: %d %s", code, resp)
		}
		diag, _ := json.Marshal(map[string]any{"type": "ldap", "config": cfg})
		if code, resp := do(admin, http.MethodPost, "/api/v1/directory-diagnose", string(diag)); code != http.StatusBadRequest || !strings.Contains(resp, "sealed value is not accepted") {
			t.Fatalf("diagnose with a sealed bind password: %d %s", code, resp)
		}
		if n := lure.count(); n != 0 {
			t.Fatalf("the caller's server was sent %d bind(s): %v", n, lure.lastBind(t))
		}
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM directory_integrations WHERE name = $1`, "lure-"+suffix).Scan(&n); err != nil || n != 0 {
			t.Fatalf("a refused create stored %d row(s) (%v)", n, err)
		}
	})

	t.Run("the startup sweep seals what is left, once", func(t *testing.T) {
		ldapRaw, _ := json.Marshal(ldapConfig())
		sweptLDAP := seedRow("ldap-swept", "ldap", string(ldapRaw))
		sweptAzure := seedRow("entra-swept", "azure_ad", `{"tenant_id":"t","client_id":"c","client_secret":"Swept-Az"}`)
		sweptHR := seedRow("hr-swept", "hris", `{"subdomain":"acme","api_key":"Swept-HR","sync_interval":60}`)
		alreadySealed := stored(ldapID, "bind_password")

		keyless := directory.NewService(db, zap.NewNop(), secretcrypt.NewNoop())
		if n, err := keyless.SealStoredSecrets(context.Background()); err != nil || n != 0 {
			t.Fatalf("without a key the sweep sealed %d (%v); it has nothing to seal with", n, err)
		}
		if got := stored(sweptHR, "api_key"); got != "Swept-HR" {
			t.Fatalf("a keyless sweep rewrote a row to %q", got)
		}

		n, err := dirSvc.SealStoredSecrets(context.Background())
		if err != nil || n != 3 {
			t.Fatalf("the sweep sealed %d (%v), want the three plaintext rows", n, err)
		}
		mustBeSealed(t, sweptLDAP, "bind_password", bindPassword)
		mustBeSealed(t, sweptAzure, "client_secret", "Swept-Az")
		mustBeSealed(t, sweptHR, "api_key", "Swept-HR")
		if !strings.Contains(storedConfig(sweptHR), `"sync_interval": 60`) {
			t.Errorf("the sweep changed the rest of the config: %s", storedConfig(sweptHR))
		}
		if got := stored(ldapID, "bind_password"); got != alreadySealed {
			t.Errorf("the sweep rewrote a credential that was already sealed")
		}
		if n, err := dirSvc.SealStoredSecrets(context.Background()); err != nil || n != 0 {
			t.Errorf("a second sweep sealed %d (%v), want 0", n, err)
		}
	})
}

// directorySyncerForTest is cmd/admin-api's directorySyncAdapter.
type directorySyncerForTest struct{ dir *directory.Service }

func (a *directorySyncerForTest) TestConnection(ctx context.Context, dirType string, configBytes []byte) error {
	return a.dir.TestConnection(ctx, dirType, configBytes)
}

func (a *directorySyncerForTest) TriggerSync(ctx context.Context, directoryID string, fullSync bool) error {
	return a.dir.TriggerSync(ctx, directoryID, fullSync)
}

func (a *directorySyncerForTest) GetSyncLogs(ctx context.Context, directoryID string, limit int) (interface{}, error) {
	return a.dir.GetSyncLogs(ctx, directoryID, limit)
}

func (a *directorySyncerForTest) GetSyncState(ctx context.Context, directoryID string) (interface{}, error) {
	return a.dir.GetSyncState(ctx, directoryID)
}

func (a *directorySyncerForTest) Diagnose(ctx context.Context, dirType string, configBytes []byte) (interface{}, error) {
	return a.dir.Diagnose(ctx, dirType, configBytes)
}

// fakeHRAPI answers BambooHR's employee directory with no employees and
// records the API key each request signs in with.
type fakeHRAPI struct {
	*httptest.Server
	mu   sync.Mutex
	keys []string
}

func newFakeHRAPI(t *testing.T) *fakeHRAPI {
	t.Helper()
	f := &fakeHRAPI{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		f.mu.Lock()
		f.keys = append(f.keys, user)
		f.mu.Unlock()
		if r.URL.Path != "/v1/employees/directory" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"employees":[]}`))
	}))
	t.Cleanup(f.Server.Close)
	return f
}

func (f *fakeHRAPI) received() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.keys...)
}

func (f *fakeHRAPI) count() int { return len(f.received()) }

func (f *fakeHRAPI) lastKey(t *testing.T) string {
	t.Helper()
	keys := f.received()
	if len(keys) == 0 {
		t.Fatal("the HR API was sent nothing")
	}
	return keys[len(keys)-1]
}

// fakeLDAPServer answers the bind and search requests a connection test and a
// login pass-through make (every bind succeeds, every search finds nothing)
// and records the DN and password of each bind. The BER is written by hand,
// for the two responses it needs.
type fakeLDAPServer struct {
	ln net.Listener
	mu sync.Mutex
	bs []fakeLDAPBind
}

type fakeLDAPBind struct{ dn, password string }

func newFakeLDAPServer(t *testing.T) *fakeLDAPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeLDAPServer{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeLDAPServer) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeLDAPServer) binds() []fakeLDAPBind {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeLDAPBind(nil), f.bs...)
}

func (f *fakeLDAPServer) count() int { return len(f.binds()) }

func (f *fakeLDAPServer) lastBind(t *testing.T) fakeLDAPBind {
	t.Helper()
	b := f.binds()
	if len(b) == 0 {
		t.Fatal("the LDAP server was sent no bind")
	}
	return b[len(b)-1]
}

func (f *fakeLDAPServer) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)
	for {
		tag, msg, err := berRead(r)
		if err != nil || tag != 0x30 {
			return
		}
		_, id, rest, ok := berSplit(msg) // messageID
		if !ok {
			return
		}
		op, body, _, ok := berSplit(rest) // protocolOp
		if !ok {
			return
		}
		switch op {
		case 0x60: // BindRequest: version, name, simple [0] password
			_, _, rest, _ := berSplit(body)
			_, dn, rest, _ := berSplit(rest)
			_, pw, _, _ := berSplit(rest)
			f.mu.Lock()
			f.bs = append(f.bs, fakeLDAPBind{dn: string(dn), password: string(pw)})
			f.mu.Unlock()
			_, _ = conn.Write(ldapSuccess(id, 0x61)) // BindResponse
		case 0x63: // SearchRequest
			_, _ = conn.Write(ldapSuccess(id, 0x65)) // SearchResultDone
		default: // unbind, abandon, anything else
			return
		}
	}
}

// ldapSuccess is an LDAPMessage carrying an LDAPResult of success, with an
// empty matched DN and diagnostic message, under the given application tag.
func ldapSuccess(id []byte, op byte) []byte {
	result := []byte{0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
	inner := append([]byte{0x02, byte(len(id))}, id...)
	inner = append(inner, op, byte(len(result)))
	inner = append(inner, result...)
	return append([]byte{0x30, byte(len(inner))}, inner...)
}

func berRead(r *bufio.Reader) (byte, []byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	n, err := berLength(r)
	if err != nil {
		return 0, nil, err
	}
	buf := make([]byte, n)
	_, err = io.ReadFull(r, buf)
	return tag, buf, err
}

func berLength(r io.ByteReader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if b < 0x80 {
		return int(b), nil
	}
	n := int(b & 0x7f)
	if n == 0 || n > 4 {
		return 0, fmt.Errorf("unsupported BER length form %#x", b)
	}
	l := 0
	for i := 0; i < n; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		l = l<<8 | int(b)
	}
	return l, nil
}

func berSplit(b []byte) (tag byte, value, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	br := bytes.NewReader(b[1:])
	n, err := berLength(br)
	if err != nil {
		return 0, nil, nil, false
	}
	start := len(b) - br.Len()
	if start+n > len(b) {
		return 0, nil, nil, false
	}
	return b[0], b[start : start+n], b[start+n:], true
}
