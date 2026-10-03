package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/resilience"
	"github.com/openidx/openidx/internal/migrations"
)

// connectionBroker is a Guacamole server holding named connections. It
// answers the connection list, connection deletes and user deletes, and
// records each delete. listFails makes the list answer 500.
type connectionBroker struct {
	*httptest.Server
	mu           sync.Mutex
	conns        map[string]string // identifier -> name
	deletedConns []string
	deletedUsers []string
	listFails    bool
}

func newConnectionBroker(t *testing.T, conns map[string]string) *connectionBroker {
	t.Helper()
	b := &connectionBroker{conns: conns}
	b.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		p := strings.TrimPrefix(r.URL.Path, "/api/session/data/postgresql")
		switch {
		case p == "/connections" && r.Method == http.MethodGet:
			if b.listFails {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			out := map[string]map[string]string{}
			for id, name := range b.conns {
				out[id] = map[string]string{"identifier": id, "name": name, "protocol": "ssh"}
			}
			_ = json.NewEncoder(w).Encode(out)
		case strings.HasPrefix(p, "/connections/") && r.Method == http.MethodDelete:
			id := strings.TrimPrefix(p, "/connections/")
			delete(b.conns, id)
			b.deletedConns = append(b.deletedConns, id)
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(p, "/users/") && r.Method == http.MethodDelete:
			b.deletedUsers = append(b.deletedUsers, strings.TrimPrefix(p, "/users/"))
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(b.Close)
	return b
}

func (b *connectionBroker) client() *GuacamoleClient {
	return &GuacamoleClient{
		baseURL: b.URL, publicBaseURL: b.URL, dataSource: "postgresql", authToken: "stub-token",
		httpClient: resilience.NewResilientHTTPClient(&http.Client{Timeout: 5 * time.Second}, guacBreaker("test", zap.NewNop())),
		logger:     zap.NewNop(), component: "guacamole",
	}
}

// An external user's launch runs on a broker connection of its own per entry,
// pam-<entry>-x-<user>, holding the credential injected for it. Nothing
// deleted it: the deprovision sweep deleted the user's broker account and left
// every such connection, credential included, on the broker for good.
//
// On the migrated schema, with a fake overlay broker: the sweep deletes a
// disabled user's own connections and then their account, and leaves the
// shared connection and another user's. When the broker cannot list its
// connections, the sweep deletes nothing and keeps the mapping, so the next
// tick retries.
func TestTheDeprovisionSweepDeletesAnExternalUsersOwnConnections(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	octx := orgctx.WithBypassRLS(ctx)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...any) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(octx, q, args...).Scan(&v); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
		return v
	}
	user := func(name string, enabled bool) string {
		return scalar(`INSERT INTO users (org_id, username, email, enabled) VALUES ($1, $2::text, $2::text || '@example.test', $3) RETURNING id::text`,
			org, name+"-"+suffix, enabled)
	}
	mapping := func(userID, guacUser string) string {
		return scalar(`INSERT INTO guacamole_users (org_id, user_id, broker, guac_username, guac_password_enc)
			VALUES ($1, $2, 'guacamole-ziti', $3, 'x') RETURNING id::text`, org, userID, guacUser)
	}
	mapped := func(rowID string) bool {
		var n int
		if err := db.Pool.QueryRow(octx, `SELECT count(*) FROM guacamole_users WHERE id = $1`, rowID).Scan(&n); err != nil {
			t.Fatalf("read the mapping: %v", err)
		}
		return n == 1
	}

	ended := user("ended-vendor", false)
	active := user("active-vendor", true)
	endedRow := mapping(ended, "oidx-ended-"+suffix)
	activeRow := mapping(active, "oidx-active-"+suffix)
	broker := newConnectionBroker(t, map[string]string{
		"1": "pam-entry-a-x-" + ended,
		"2": "pam-entry-b-x-" + ended,
		"3": "pam-entry-a",
		"4": "pam-entry-a-x-" + active,
	})
	svc := &Service{db: db, logger: zap.NewNop(), guacamoleZitiClient: broker.client()}

	// The broker cannot list its connections: nothing is deleted, and the
	// mapping stays for the next tick.
	broker.listFails = true
	svc.sweepDeprovisionGuacUsers(octx)
	if len(broker.deletedConns) != 0 || slices.Contains(broker.deletedUsers, "oidx-ended-"+suffix) || !mapped(endedRow) {
		t.Fatalf("with no connection list the sweep deleted connections %v and users %v, mapping kept %v; want nothing deleted and the mapping kept",
			broker.deletedConns, broker.deletedUsers, mapped(endedRow))
	}

	broker.listFails = false
	svc.sweepDeprovisionGuacUsers(octx)
	slices.Sort(broker.deletedConns)
	if !slices.Equal(broker.deletedConns, []string{"1", "2"}) {
		t.Errorf("the sweep deleted connections %v; want the ended user's own, 1 and 2", broker.deletedConns)
	}
	if !slices.Contains(broker.deletedUsers, "oidx-ended-"+suffix) || slices.Contains(broker.deletedUsers, "oidx-active-"+suffix) {
		t.Errorf("the sweep deleted broker users %v; want the ended user's, not the active user's", broker.deletedUsers)
	}
	if mapped(endedRow) {
		t.Error("the ended user's mapping is still there")
	}
	if !mapped(activeRow) {
		t.Error("the active user's mapping was deleted")
	}
}
