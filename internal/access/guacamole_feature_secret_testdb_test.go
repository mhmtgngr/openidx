package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/migrations"
)

// THE GUACAMOLE FEATURE'S PASSWORD, AT REST AND ON THE WAY OUT.
//
// POST /api/v1/access/services/:id/features/guacamole/enable creates the
// broker connection with the username and password in its body, and wrote the
// body into service_features.config as it came: the password in plaintext, in
// the table, its backups and any replica. GET /services/:id/features,
// /services/:id/status and /services/status returned the config, password
// included.
//
// Driven through RegisterRoutes, wired as cmd/access-service wires it (the
// feature manager set on the service, which hands it the service's
// ENCRYPTION_KEY cipher, and the Guacamole client after it), against a broker
// that records the connections it is asked to create:
//   - the broker gets the password, and the table holds it sealed, and it
//     opens with the key;
//   - no read returns it, sealed or not, and each says one is stored;
//   - an enable that leaves it out keeps it for the same target, and not for
//     another host;
//   - a password stored in plaintext by an earlier release is never returned,
//     still reaches the broker, and is sealed by the next enable, or by the
//     startup sweep, which seals each such row once and needs a key to;
//   - a password sealed with a key the service does not hold is refused
//     before the broker is asked, and is used once it is sent again;
//   - a plain user reads none of it.
func TestTheGuacamoleFeaturePasswordIsSealedAndNeverReturned(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := orgctx.WithBypassRLS(context.Background())
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	const key = "0123456789abcdef0123456789abcdef"
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	broker := newRecordingGuacBroker(t)
	cfg := &config.Config{
		Environment:            "production",
		EncryptionKey:          key,
		GuacamoleURL:           broker.URL,
		GuacamoleAdminUser:     "broker-admin",
		GuacamoleAdminPassword: "broker-admin-password",
	}
	mini := miniredis.RunT(t)
	rc := goredis.NewClient(&goredis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	svc := NewService(db, &database.RedisClient{Client: rc}, cfg, zap.NewNop())
	svc.SetAuditService(NewUnifiedAuditService(db, zap.NewNop()))
	fm := NewFeatureManager(db, zap.NewNop())
	svc.SetFeatureManager(fm)
	gc, err := NewGuacamoleClient(cfg, db, zap.NewNop())
	if err != nil {
		t.Fatalf("guacamole client: %v", err)
	}
	svc.SetGuacamoleClient(gc)
	opener, err := secretcrypt.New(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
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

	r := gin.New()
	RegisterRoutes(r, svc, func(c *gin.Context) {
		who := c.GetHeader("X-Test-Caller")
		c.Set("user_id", who)
		c.Set("org_id", org)
		c.Set("roles", callers[who])
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Next()
	})
	do := func(who, method, path, body string) (int, string) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-Caller", who)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}

	seedRoute := func(name, remoteHost string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO proxy_routes (org_id, name, from_url, to_url, require_auth, route_type, remote_host, remote_port)
			VALUES ($1::uuid, $2, $3, $4, true, 'ssh', $5, 22) RETURNING id::text`,
			org, name+"-"+suffix, "https://"+name+"-"+suffix+".example.test", "http://"+remoteHost, remoteHost).Scan(&id); err != nil {
			t.Fatalf("seed route %s: %v", name, err)
		}
		return id
	}
	storedPassword := func(route string) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, `
			SELECT COALESCE(config ->> 'guacamole_password', '') FROM service_features
			 WHERE route_id = $1::uuid AND feature_name = 'guacamole'`, route).Scan(&v); err != nil {
			t.Fatalf("read stored config: %v", err)
		}
		return v
	}
	mustBeSealed := func(route, want string) string {
		t.Helper()
		sealed := storedPassword(route)
		if !secretcrypt.IsEncrypted(sealed) || strings.Contains(sealed, want) {
			t.Fatalf("the stored password is %q, not a sealed value", sealed)
		}
		if got, err := opener.Decrypt(sealed); err != nil || got != want {
			t.Fatalf("the stored password opens as %q (%v), want %q", got, err, want)
		}
		return sealed
	}
	enable := func(route, body string) {
		t.Helper()
		if code, resp := do(admin, http.MethodPost, "/api/v1/access/services/"+route+"/features/guacamole/enable", body); code != http.StatusOK {
			t.Fatalf("enable %s: %d %s", body, code, resp)
		}
	}
	disable := func(route string) {
		t.Helper()
		if code, resp := do(admin, http.MethodPost, "/api/v1/access/services/"+route+"/features/guacamole/disable", ""); code != http.StatusOK {
			t.Fatalf("disable: %d %s", code, resp)
		}
	}
	readsNeverReturn := func(t *testing.T, route string, secrets ...string) {
		t.Helper()
		for _, path := range []string{
			"/api/v1/access/services/" + route + "/features",
			"/api/v1/access/services/" + route + "/status",
			"/api/v1/access/services/status",
		} {
			code, body := do(admin, http.MethodGet, path, "")
			if code != http.StatusOK {
				t.Fatalf("GET %s: %d %s", path, code, body)
			}
			for _, s := range secrets {
				if strings.Contains(body, s) {
					t.Errorf("GET %s returned the stored password (%q)", path, s)
				}
			}
			if strings.Contains(body, `"guacamole_password":`) {
				t.Errorf("GET %s returned a guacamole_password field: %s", path, body)
			}
			if path != "/api/v1/access/services/status" && !strings.Contains(body, `"guacamole_password_set":true`) {
				t.Errorf("GET %s does not say a password is stored: %s", path, body)
			}
		}
	}

	route := seedRoute("guac", "db.internal.example")
	const secret = "S3cret-ssh-pass"

	t.Run("the broker gets the password, and the table holds it sealed", func(t *testing.T) {
		enable(route, `{"guacamole_username":"ops","guacamole_password":"`+secret+`"}`)
		got := broker.last(t)
		if got["password"] != secret || got["username"] != "ops" || got["hostname"] != "db.internal.example" {
			t.Fatalf("the broker was asked for %v", got)
		}
		mustBeSealed(route, secret)
	})

	t.Run("no read returns it, sealed or not", func(t *testing.T) {
		readsNeverReturn(t, route, secret, storedPassword(route))
	})

	t.Run("a plain user reads none of it", func(t *testing.T) {
		if code, body := do(plain, http.MethodGet, "/api/v1/access/services/"+route+"/features", ""); code != http.StatusForbidden {
			t.Errorf("a plain user read the features: %d %s", code, body)
		}
	})

	t.Run("an enable that leaves it out keeps it for the same target", func(t *testing.T) {
		disable(route)
		enable(route, `{"guacamole_username":"ops"}`)
		if got := broker.last(t); got["password"] != secret {
			t.Fatalf("re-enabled for the same target, the broker was asked for %v", got)
		}
		mustBeSealed(route, secret)
	})

	t.Run("and not for another host", func(t *testing.T) {
		disable(route)
		enable(route, `{"guacamole_username":"ops","guacamole_host":"collector.example.net"}`)
		got := broker.last(t)
		if got["hostname"] != "collector.example.net" {
			t.Fatalf("the broker was asked for %v", got)
		}
		if pw, ok := got["password"]; ok {
			t.Errorf("the stored password went to a host the caller chose: %q", pw)
		}
	})

	// A row as an earlier release left it: the target it named, the password
	// in plaintext, the feature switched off.
	seedLegacy := func(route, host, password string) {
		t.Helper()
		legacy, _ := json.Marshal(FeatureConfig{
			GuacamoleProtocol: "ssh", GuacamoleHost: host, GuacamolePort: 22,
			GuacamoleUsername: "legacy", GuacamolePassword: password,
		})
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO service_features (id, route_id, org_id, feature_name, enabled, config, resource_ids, status, health_status)
			VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 'guacamole', false, $3::jsonb, '{}', 'disabled', 'unknown')`,
			route, org, string(legacy)); err != nil {
			t.Fatalf("seed legacy feature: %v", err)
		}
		if got := storedPassword(route); got != password {
			t.Fatalf("the legacy fixture stored %q", got)
		}
	}

	t.Run("a legacy plaintext password is never returned, still works, and is sealed by the next enable", func(t *testing.T) {
		legacyRoute := seedRoute("guac-legacy", "db2.internal.example")
		const legacySecret = "Legacy-Plain-1"
		seedLegacy(legacyRoute, "db2.internal.example", legacySecret)
		readsNeverReturn(t, legacyRoute, legacySecret)
		enable(legacyRoute, `{"guacamole_username":"legacy"}`)
		if got := broker.last(t); got["password"] != legacySecret || got["hostname"] != "db2.internal.example" {
			t.Fatalf("the legacy password did not reach the broker: %v", got)
		}
		mustBeSealed(legacyRoute, legacySecret)
	})

	// A key rotated out without cmd/rekey leaves a sealed value this service
	// cannot open. Sent to the broker, the ciphertext would be a wrong
	// credential that nothing reports.
	t.Run("a password sealed with a key the service does not hold is refused, and the broker is not asked", func(t *testing.T) {
		foreignRoute := seedRoute("guac-foreign", "db4.internal.example")
		other, err := secretcrypt.New("fedcba9876543210fedcba9876543210")
		if err != nil {
			t.Fatalf("cipher: %v", err)
		}
		foreign, err := other.Encrypt("Rotated-Out-1")
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		seedLegacy(foreignRoute, "db4.internal.example", foreign)
		readsNeverReturn(t, foreignRoute, foreign)

		asked := broker.count()
		code, body := do(admin, http.MethodPost, "/api/v1/access/services/"+foreignRoute+"/features/guacamole/enable", `{"guacamole_username":"legacy"}`)
		if code != http.StatusBadRequest || !strings.Contains(body, "cannot be decrypted") {
			t.Fatalf("an enable over a password the key cannot open: %d %s", code, body)
		}
		if strings.Contains(body, foreign) {
			t.Errorf("the refusal carries the sealed value: %s", body)
		}
		if broker.count() != asked {
			t.Fatalf("the broker was asked for a connection: %v", broker.last(t))
		}
		if got := storedPassword(foreignRoute); got != foreign {
			t.Fatalf("the refused enable rewrote the stored password to %q", got)
		}

		enable(foreignRoute, `{"guacamole_username":"legacy","guacamole_password":"Sent-Again-1"}`)
		if got := broker.last(t); got["password"] != "Sent-Again-1" || got["hostname"] != "db4.internal.example" {
			t.Fatalf("sent again, the broker was asked for %v", got)
		}
		mustBeSealed(foreignRoute, "Sent-Again-1")
	})

	t.Run("the startup sweep seals what is left, once", func(t *testing.T) {
		sweptRoute := seedRoute("guac-swept", "db3.internal.example")
		const sweptSecret = "Legacy-Plain-2"
		seedLegacy(sweptRoute, "db3.internal.example", sweptSecret)
		alreadySealed := storedPassword(route)

		keyless := NewFeatureManager(db, zap.NewNop())
		keyless.SetSecretCipher(secretcrypt.NewNoop())
		if n, err := keyless.SealStoredSecrets(context.Background()); err != nil || n != 0 {
			t.Fatalf("without a key the sweep sealed %d (%v); it has nothing to seal with", n, err)
		}
		if got := storedPassword(sweptRoute); got != sweptSecret {
			t.Fatalf("a keyless sweep rewrote the row to %q", got)
		}

		n, err := fm.SealStoredSecrets(context.Background())
		if err != nil || n != 1 {
			t.Fatalf("the sweep sealed %d (%v), want the one plaintext row", n, err)
		}
		mustBeSealed(sweptRoute, sweptSecret)
		if got := storedPassword(route); got != alreadySealed {
			t.Errorf("the sweep rewrote a row that was already sealed")
		}
		if n, err := fm.SealStoredSecrets(context.Background()); err != nil || n != 0 {
			t.Errorf("a second sweep sealed %d (%v), want 0", n, err)
		}
	})
}

// recordingGuacBroker answers the Guacamole REST calls a connection create
// makes and records the parameters of each connection it is asked for.
type recordingGuacBroker struct {
	*httptest.Server
	mu      sync.Mutex
	created []map[string]string
}

func newRecordingGuacBroker(t *testing.T) *recordingGuacBroker {
	t.Helper()
	b := &recordingGuacBroker{}
	b.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/tokens":
			_, _ = w.Write([]byte(`{"authToken":"broker-token","dataSource":"postgresql"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/session/data/postgresql/connections":
			var body struct {
				Parameters map[string]string `json:"parameters"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			b.mu.Lock()
			b.created = append(b.created, body.Parameters)
			id := len(b.created)
			b.mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"identifier":"%d"}`, id)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/session/data/postgresql/connections/"):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(b.Server.Close)
	return b
}

func (b *recordingGuacBroker) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.created)
}

func (b *recordingGuacBroker) last(t *testing.T) map[string]string {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.created) == 0 {
		t.Fatal("the broker was asked for no connection")
	}
	return b.created[len(b.created)-1]
}
