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

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// The Device trust row of docs/evidence/display-equals-enforcement.md: "an
// untrusted device is denied the dial".
//
// The row runs through three parts:
//   - the device posture report, which grants or removes the device-trusted
//     attribute on the phone's Ziti identity (applyPostureDeviceTrust, under
//     POSTURE_DEVICE_TRUST_GATE=enforce);
//   - the Tier-2 Dial policies the reconciler writes for OpenIDX's own
//     management surfaces (reconcileDarkServices), which name #device-trusted;
//   - reachabilityForIdentity, the Dial matcher the access map shares.
//
// All three run here against a migrated Postgres and a fake controller that
// also keeps identities, so the attribute the report writes is the one the
// matcher reads. Both switches are off by default; this is the row with them
// on.
func TestPostureDecidesWhoDialsTheAdminPlane(t *testing.T) {
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const org = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	var userID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO users (org_id, username, email, enabled)
		VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
		org, "phone-owner-"+suffix, "phone-owner-"+suffix+"@example.test").Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	zitiID := "zid-" + suffix
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO ziti_identities (org_id, ziti_id, name, user_id, enrolled)
		VALUES ($1::uuid, $2, $3, $4::uuid, true)`, org, zitiID, "phone-"+suffix, userID); err != nil {
		t.Fatalf("seed ziti identity: %v", err)
	}
	agentID := "agent-" + suffix
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO enrolled_agents (agent_id, device_id, auth_token_hash, status, enrolled_by_user_id, org_id)
		VALUES ($1, $2, 'x', 'active', $3::uuid, $4::uuid)`, agentID, "device-"+suffix, userID, org); err != nil {
		t.Fatalf("seed enrolled agent: %v", err)
	}

	// The fake controller already has OpenIDX's surfaces, so the reconciler
	// goes straight to their policies.
	f := &fakeController{}
	var names []string
	for _, d := range defaultDarkServices() {
		f.services = append(f.services, ZitiServiceInfo{ID: "svc-" + d.name, Name: d.name})
		names = append(names, d.name)
	}
	ids := &fakeIdentityStore{attrs: map[string][]string{zitiID: {"enrolled-users"}}}
	srv := httptest.NewServer(ids.wrap(f.handler()))
	t.Cleanup(srv.Close)
	cfg := MockConfig(t)
	cfg.ZitiCtrlURL = srv.URL
	cfg.PostureDeviceTrustGate = "enforce"
	zm := &ZitiManager{cfg: cfg, logger: zap.NewNop(), db: db, mgmtToken: "t", mgmtClient: srv.Client()}

	rec := NewZitiReconciler(db, zap.NewNop(), nil, "")
	rec.EnableDefaultDarkServices()
	rec.reconcileDarkServices(ctx, zm)

	agents := &AgentAPIHandler{logger: zap.NewNop(), db: db, zm: zm}
	canDial := func(service string) bool {
		t.Helper()
		f.mu.Lock()
		var dial []zitiDialPolicy
		for _, p := range f.policies {
			if p.Type == "Dial" {
				dial = append(dial, zitiDialPolicy{Name: p.Name, IdentityRoles: p.IdentityRoles, ServiceRoles: p.ServiceRoles})
			}
		}
		f.mu.Unlock()
		_, reach := reachabilityForIdentity(dial, zitiID, ids.get(zitiID), zitiServiceIndex{all: names})
		for _, svc := range reach {
			if svc == service {
				return true
			}
		}
		return false
	}

	t.Run("an enrolled device that has not proven its posture reaches Tier 1 only", func(t *testing.T) {
		if !canDial("openidx-console") {
			t.Fatal("an enrolled user must reach the console")
		}
		if canDial("openidx-admin-api") {
			t.Fatal("a device with no trust must not dial the admin API")
		}
	})
	t.Run("a compliant report makes the device trusted and opens the admin plane", func(t *testing.T) {
		agents.applyPostureDeviceTrust(ctx, agentID, "compliant")
		if !canDial("openidx-admin-api") {
			t.Fatalf("a compliant device must dial the admin API; attributes %v", ids.get(zitiID))
		}
	})
	t.Run("a failing report takes the trust away and closes it again", func(t *testing.T) {
		agents.applyPostureDeviceTrust(ctx, agentID, "non_compliant")
		if canDial("openidx-admin-api") {
			t.Fatalf("an untrusted device must be denied the dial; attributes %v", ids.get(zitiID))
		}
		if !canDial("openidx-console") {
			t.Fatal("losing device trust must not take Tier 1 away")
		}
	})
	t.Run("in observe the report is recorded and nothing changes", func(t *testing.T) {
		cfg.PostureDeviceTrustGate = "observe"
		t.Cleanup(func() { cfg.PostureDeviceTrustGate = "enforce" })
		agents.applyPostureDeviceTrust(ctx, agentID, "compliant")
		if canDial("openidx-admin-api") {
			t.Fatal("observe must not grant device trust")
		}
	})
}

// fakeIdentityStore answers the controller's identity reads and attribute
// patches, and hands every other request to the fake controller.
type fakeIdentityStore struct {
	mu    sync.Mutex
	attrs map[string][]string
}

func (s *fakeIdentityStore) get(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.attrs[id]...)
}

func (s *fakeIdentityStore) wrap(next http.Handler) http.Handler {
	const prefix = "/edge/management/v1/identities/"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, prefix)
		if !strings.HasPrefix(r.URL.Path, prefix) || id == "" || strings.Contains(id, "/") {
			next.ServeHTTP(w, r)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		attrs, ok := s.attrs[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": id, "roleAttributes": attrs}})
		case http.MethodPatch:
			var body struct {
				RoleAttributes []string `json:"roleAttributes"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.attrs[id] = body.RoleAttributes
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}
