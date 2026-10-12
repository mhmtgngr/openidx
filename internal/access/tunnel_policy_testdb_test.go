package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// The tunnel policy a device receives and the one it reports applying, on the
// migrated schema: the defaults, the corporate ranges once the block is on,
// the version moving with them, the applied version stored by a report, and
// the applied/pending counts and per-device state the console reads.
func TestTunnelPolicyDeliveryAndRolloutOnTheMigratedSchema(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(bg, orgctx.Org{ID: org})

	// No row: the defaults, with no ranges.
	p, err := loadAgentNetworkPolicy(ctx, db, org)
	if err != nil {
		t.Fatalf("load default policy: %v", err)
	}
	if p.AlwaysOn || !p.SplitTunnel || p.BlockDirectCorporateCIDRs || len(p.CorporateCIDRs) != 0 || !isPolicyVersion(p.Version) {
		t.Fatalf("default policy = %+v", p)
	}
	defaultVersion := p.Version

	// Two network resources, one disabled; and a web app that is not one.
	var netApp, offApp string
	if err := db.Pool.QueryRow(ctx, `INSERT INTO applications (client_id, name, type, kind, org_id)
		VALUES ('net-tp', 'File servers', 'network', 'network', $1) RETURNING id::text`, org).Scan(&netApp); err != nil {
		t.Fatalf("seed network app: %v", err)
	}
	if err := db.Pool.QueryRow(ctx, `INSERT INTO applications (client_id, name, type, kind, org_id, enabled)
		VALUES ('net-off', 'Old lab', 'network', 'network', $1, false) RETURNING id::text`, org).Scan(&offApp); err != nil {
		t.Fatalf("seed disabled network app: %v", err)
	}
	for _, q := range []struct {
		id, cidrs, hosts string
	}{
		{netApp, `{10.0.0.0/16,10.0.5.0/24}`, `{fs1.corp.example,192.168.7.7}`},
		{offApp, `{172.16.0.0/12}`, `{}`},
	} {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO network_targets (application_id, org_id, hosts, cidrs)
			VALUES ($1, $2, $3::text[], $4::cidr[])`, q.id, org, q.hosts, q.cidrs); err != nil {
			t.Fatalf("seed target: %v", err)
		}
	}

	// The block off: the ranges are not sent and do not move the version.
	p, _ = loadAgentNetworkPolicy(ctx, db, org)
	if len(p.CorporateCIDRs) != 0 || p.Version != defaultVersion {
		t.Errorf("with the block off the policy carries %v, version %s (default %s)", p.CorporateCIDRs, p.Version, defaultVersion)
	}

	if _, err := db.Pool.Exec(ctx, `INSERT INTO org_network_policy (org_id, always_on, block_direct_corporate_cidrs)
		VALUES ($1, true, true)`, org); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	p, err = loadAgentNetworkPolicy(ctx, db, org)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if want := []string{"10.0.0.0/16", "192.168.7.7/32"}; !reflect.DeepEqual(p.CorporateCIDRs, want) {
		t.Errorf("corporate ranges = %v, want %v (enabled resources only, covered ranges folded)", p.CorporateCIDRs, want)
	}
	if !p.AlwaysOn || p.Version == defaultVersion {
		t.Errorf("policy = %+v", p)
	}
	current := p.Version

	// Three devices: one applied the current version, one an old one, one
	// reports no tunnel at all.
	for _, id := range []string{"agent-now", "agent-old", "agent-none"} {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO enrolled_agents (agent_id, device_id, auth_token_hash, status, org_id)
			VALUES ($1, $1, 'x', 'active', $2)`, id, org); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
	}
	h := NewAgentAPIHandler(zap.NewNop(), db, nil, &config.Config{})
	h.recordTunnelStatus(ctx, "agent-now", &agentTunnelStatus{State: "connected", Mode: "split", PolicyVersion: current})
	h.recordTunnelStatus(ctx, "agent-old", &agentTunnelStatus{State: "degraded", PolicyVersion: defaultVersion,
		PolicyGaps: []string{"block_direct"}, LastError: "nft: not installed"})

	var stored *string
	var appliedAtSet bool
	if err := db.Pool.QueryRow(ctx, `SELECT tunnel_policy_version, tunnel_policy_applied_at IS NOT NULL
		FROM enrolled_agents WHERE agent_id = 'agent-now' AND org_id = $1`, org).Scan(&stored, &appliedAtSet); err != nil {
		t.Fatalf("read applied version: %v", err)
	}
	if stored == nil || *stored != current || !appliedAtSet {
		t.Errorf("applied version stored as %v, applied_at set %v", stored, appliedAtSet)
	}

	d, err := countTunnelPolicyDevices(ctx, db, org, current)
	if err != nil || d != (tunnelPolicyDevices{Applied: 1, Pending: 1, Unreported: 1}) {
		t.Errorf("devices = %+v, %v", d, err)
	}

	// The console's two reads: the policy with its rollout, and the fleet.
	gin.SetMode(gin.TestMode)
	svc := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Next()
	})
	r.GET("/network-policy", svc.handleGetNetworkPolicy)
	r.GET("/agents", h.HandleListAgents)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/network-policy", nil))
	var pol networkPolicyView
	if err := json.Unmarshal(w.Body.Bytes(), &pol); err != nil || w.Code != http.StatusOK {
		t.Fatalf("network-policy answered %d: %s", w.Code, w.Body.String())
	}
	if pol.Version != current || pol.Devices == nil || pol.Devices.Applied != 1 || pol.Devices.Pending != 1 {
		t.Errorf("network-policy = %+v", pol)
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/agents", nil))
	var agents []agentRecord
	if err := json.Unmarshal(w.Body.Bytes(), &agents); err != nil || w.Code != http.StatusOK {
		t.Fatalf("agents answered %d: %s", w.Code, w.Body.String())
	}
	state := map[string]string{}
	for _, a := range agents {
		state[a.AgentID] = a.TunnelPolicyState
		if a.AgentID == "agent-old" && (a.TunnelStatus == nil || a.TunnelStatus.State != "down" ||
			a.TunnelStatus.LastError != "nft: not installed" || len(a.TunnelStatus.PolicyGaps) != 1) {
			t.Errorf("agent-old's tunnel status = %+v", a.TunnelStatus)
		}
	}
	if want := map[string]string{"agent-now": "applied", "agent-old": "pending", "agent-none": ""}; !reflect.DeepEqual(state, want) {
		t.Errorf("policy states = %v, want %v", state, want)
	}

	// A report without a version clears the applied version.
	h.recordTunnelStatus(ctx, "agent-now", &agentTunnelStatus{State: "off"})
	if err := db.Pool.QueryRow(ctx, `SELECT tunnel_policy_version, tunnel_policy_applied_at IS NOT NULL
		FROM enrolled_agents WHERE agent_id = 'agent-now' AND org_id = $1`, org).Scan(&stored, &appliedAtSet); err != nil {
		t.Fatalf("read applied version: %v", err)
	}
	if stored != nil || appliedAtSet {
		t.Errorf("after a report without a version: %v, applied_at set %v", stored, appliedAtSet)
	}
}
