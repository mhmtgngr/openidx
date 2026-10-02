package access

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
	"github.com/openidx/openidx/internal/vault"
)

// Cloud JIT spends a broker credential only for a caller with a use grant on
// it, and never for longer than an hour.
//
// POST /pam/connect/cloud takes the broker credential's secret id from the
// request body. It decrypted that secret through vault Use, which checks no
// grant, so any member of the organization could name any of its secrets as
// the broker and assume any role the broker could, for up to twelve hours.
// STS credentials cannot be revoked, so those twelve hours outlived the kill
// switch too.
//
// The test drives the handler on the migrated schema with the production
// vault and a fake STS, and asks for credentials as each kind of caller. The
// requireFreshMFA step in front of the route is a separate control and is not
// mounted here.
func TestCloudJITFollowsTheBrokerCredentialGrant(t *testing.T) {
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
	const otherOrg = "00000000-0000-0000-0000-0000000000e3" // a second tenant
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
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
	admin := seedUser("cloud-admin")
	granted := seedUser("cloud-granted")
	revealOnly := seedUser("cloud-reveal-only")
	lapsed := seedUser("cloud-lapsed")
	stranger := seedUser("cloud-stranger")

	// The audit service: records the actions and outcomes the handler posts.
	type posted struct{ action, outcome, userID string }
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
		uid, _ := ev.Details["user_id"].(string)
		mu.Lock()
		events = append(events, posted{ev.Action, ev.Outcome, uid})
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(auditSrv.Close)

	logger := zap.NewNop()
	svc := &Service{db: db, config: &config.Config{}, logger: logger,
		auditService: NewUnifiedAuditService(db, logger), auditURL: auditSrv.URL}
	ring, err := vault.KeyringFromConfig(vault.KeyConfig{
		KEK: base64.StdEncoding.EncodeToString([]byte("cloud-jit-grant-test-kek-0123456")),
	})
	if err != nil {
		t.Fatalf("vault keyring: %v", err)
	}
	vaultSvc, err := vault.NewService(db, ring, nil, time.Minute, logger)
	if err != nil {
		t.Fatalf("vault service: %v", err)
	}
	svc.SetVaultService(vaultSvc)

	orgCtx := orgctx.With(ctx, orgctx.Org{ID: org})
	otherCtx := orgctx.With(ctx, orgctx.Org{ID: otherOrg})
	store := func(ctx context.Context, name string) string {
		t.Helper()
		meta, err := vaultSvc.Store(ctx, vault.StoreInput{
			Name: name + "-" + suffix, Type: "generic", CreatedBy: admin, OwnerID: admin,
			Value: []byte(`{"access_key_id":"AKIABROKER","secret_access_key":"broker-secret"}`),
		})
		if err != nil {
			t.Fatalf("store %s: %v", name, err)
		}
		return meta.ID
	}
	addGrant := func(ctx context.Context, secret, user string, actions []string, expires *time.Time) {
		t.Helper()
		if _, err := vaultSvc.AddGrant(ctx, vault.Grant{SecretID: secret, PrincipalType: "user",
			PrincipalID: user, Actions: actions, ExpiresAt: expires, GrantedBy: admin}); err != nil {
			t.Fatalf("grant %v on %s to %s: %v", actions, secret, user, err)
		}
	}
	broker := store(orgCtx, "aws-broker")
	foreign := store(otherCtx, "aws-broker-other-tenant")
	past := time.Now().Add(-time.Hour)
	addGrant(orgCtx, broker, granted, []string{"use"}, nil)
	addGrant(orgCtx, broker, revealOnly, []string{"reveal"}, nil)
	addGrant(orgCtx, broker, lapsed, []string{"use"}, &past)
	addGrant(otherCtx, foreign, granted, []string{"use"}, nil)

	fake := &fakeSTS{}
	oldClient := newAssumeRoleClient
	newAssumeRoleClient = func(region, accessKeyID, secretAccessKey string) assumeRoleAPI { return fake }
	t.Cleanup(func() { newAssumeRoleClient = oldClient })

	connect := func(userID, secret string, ttl int, roles ...string) (int, map[string]interface{}) {
		t.Helper()
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			c.Set("user_id", userID)
			c.Set("roles", append([]string{}, roles...))
			c.Next()
		})
		r.POST("/pam/connect/cloud", svc.handleCloudConnect)
		w := httptest.NewRecorder()
		body := `{"role_arn":"arn:aws:iam::111122223333:role/ops","secret_id":"` + secret +
			`","reason":"incident","ttl_minutes":` + strconv.Itoa(ttl) + `}`
		req := httptest.NewRequest(http.MethodPost, "/pam/connect/cloud", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	refusal := map[string]interface{}{"error": "broker credential unavailable", "code": "broker_credential_unavailable"}
	for _, tc := range []struct {
		name        string
		user        string
		roles       []string
		secret      string
		ttl         int
		wantSeconds int32 // 0 means refused
	}{
		{"a use grant gets credentials, capped at an hour", granted, nil, broker, 720, 3600},
		{"a short request gets STS's floor", granted, nil, broker, 5, 900},
		{"a request within the cap gets what it asked", granted, nil, broker, 30, 1800},
		{"a reveal-only grant is refused", revealOnly, nil, broker, 60, 0},
		{"a lapsed use grant is refused", lapsed, nil, broker, 60, 0},
		{"a member with no grant is refused", stranger, nil, broker, 60, 0},
		{"a secret id that does not exist is refused the same way", granted, nil, "00000000-0000-0000-0000-00000000dead", 60, 0},
		{"another tenant's secret and grant count for nothing here", granted, nil, foreign, 60, 0},
		{"an administrator uses the credential without a grant", admin, []string{"admin"}, broker, 720, 3600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake.lastInput = nil
			code, body := connect(tc.user, tc.secret, tc.ttl, tc.roles...)
			if tc.wantSeconds == 0 {
				if code != http.StatusForbidden || body["error"] != refusal["error"] || body["code"] != refusal["code"] {
					t.Fatalf("got %d %v, want 403 %v", code, body, refusal)
				}
				if fake.lastInput != nil {
					t.Fatal("a refused caller reached STS")
				}
				if _, leaked := body["secret_access_key"]; leaked {
					t.Fatal("a refusal carried credentials")
				}
				return
			}
			if code != http.StatusOK {
				t.Fatalf("got %d %v, want 200", code, body)
			}
			if fake.lastInput == nil {
				t.Fatal("STS was never asked")
			}
			if got := aws.ToInt32(fake.lastInput.DurationSeconds); got != tc.wantSeconds {
				t.Errorf("STS DurationSeconds = %d, want %d", got, tc.wantSeconds)
			}
			if body["access_key_id"] != "ASIAFAKE" {
				t.Errorf("response credentials: %v", body)
			}
		})
	}

	t.Run("a use is recorded against the person and a refusal leaves no session", func(t *testing.T) {
		var n int
		if err := db.Pool.QueryRow(ctx, `
			SELECT count(*) FROM vault_checkouts
			 WHERE secret_id = $1::uuid AND principal_id = $2::uuid AND mode = 'use' AND reason = 'incident'`,
			broker, granted).Scan(&n); err != nil {
			t.Fatalf("count checkouts: %v", err)
		}
		if n != 3 {
			t.Errorf("the granted user's uses in the checkout ledger = %d, want 3", n)
		}
		if err := db.Pool.QueryRow(ctx,
			`SELECT count(*) FROM brokered_sessions WHERE target_type = 'cloud' AND user_id = ANY($1::uuid[])`,
			[]string{revealOnly, lapsed, stranger}).Scan(&n); err != nil {
			t.Fatalf("count sessions: %v", err)
		}
		if n != 0 {
			t.Errorf("refused callers have %d cloud session(s), want 0", n)
		}

		deadline := time.Now().Add(3 * time.Second)
		var denied bool
		for time.Now().Before(deadline) && !denied {
			mu.Lock()
			for _, e := range events {
				if e.action == "pam.cloud_jit_denied" && e.outcome == "failure" && e.userID == stranger {
					denied = true
				}
			}
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}
		if !denied {
			t.Error("no pam.cloud_jit_denied event with outcome failure reached the audit service")
		}
	})
}
