package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/openidx/openidx/internal/common/database"
)

// THE ORGANIZATION'S TUNNEL POLICY, AS A DEVICE RECEIVES IT.
//
// org_network_policy (migration 232) is what an administrator sets on the
// Network Resources page: always on, split tunnel, block direct access to the
// corporate networks. Until this file nothing sent it anywhere, so the console
// setting changed nothing on a device. The agent already reads an
// org_network_policy object from /agent/config and from the response to its
// posture report (agent/internal/agent/tunnel.go); this builds that object.
//
// What a device is given:
//
//   - the three switches, with a missing row read as the defaults;
//   - corporate_cidrs, the ranges "block direct" refuses outside the tunnel:
//     every CIDR, and every host written as an IP address, of the
//     organization's enabled network resources. They are sent only while the
//     block is on; a DNS name cannot be blocked by address and is left out;
//   - version, a digest of all of the above. The agent echoes the version it
//     applied in its tunnel_status, and the console compares the two to show
//     whether a device has the current policy or is still pending it. A digest
//     rather than a counter, so a change to a resource's CIDRs while the block
//     is on moves the version too, and a save that changes nothing does not.

// agentNetworkPolicy is the org_network_policy object of /agent/config and of
// the /agent/report response.
type agentNetworkPolicy struct {
	AlwaysOn                  bool     `json:"always_on"`
	SplitTunnel               bool     `json:"split_tunnel"`
	BlockDirectCorporateCIDRs bool     `json:"block_direct_corporate_cidrs"`
	CorporateCIDRs            []string `json:"corporate_cidrs"`
	Version                   string   `json:"version"`
}

// maxCorporateCIDRs bounds what one policy carries to a device (and what the
// device puts in its firewall).
const maxCorporateCIDRs = 1024

// policyVersion is the digest the agent echoes back: 16 hex characters of a
// SHA-256 over every field a device acts on.
func policyVersion(p agentNetworkPolicy) string {
	h := sha256.New()
	fmt.Fprintf(h, "v1|%t|%t|%t|%s", p.AlwaysOn, p.SplitTunnel, p.BlockDirectCorporateCIDRs,
		strings.Join(p.CorporateCIDRs, ","))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// corporatePrefixes turns stored CIDRs and hosts into the canonical prefixes a
// device blocks: masked, deduplicated, without a prefix another one already
// covers, sorted, at most maxCorporateCIDRs. A host that is not an IP address
// (a name) is skipped, as is anything that does not parse.
func corporatePrefixes(cidrs, hosts []string) []string {
	var ps []netip.Prefix
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil {
			ps = append(ps, p.Masked())
		}
	}
	for _, h := range hosts {
		if a, err := netip.ParseAddr(strings.TrimSpace(h)); err == nil {
			a = a.Unmap()
			ps = append(ps, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Bits() != ps[j].Bits() {
			return ps[i].Bits() < ps[j].Bits()
		}
		return ps[i].Addr().Less(ps[j].Addr())
	})
	var kept []netip.Prefix
	for _, p := range ps {
		covered := false
		for _, k := range kept {
			if k.Addr().Is4() == p.Addr().Is4() && k.Bits() <= p.Bits() && k.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, p)
		}
	}
	out := make([]string, 0, len(kept))
	for _, p := range kept {
		out = append(out, p.String())
	}
	sort.Strings(out)
	if len(out) > maxCorporateCIDRs {
		out = out[:maxCorporateCIDRs]
	}
	return out
}

// loadAgentNetworkPolicy reads the organization's effective tunnel policy.
// ctx must carry the organization (the tables are under RLS).
func loadAgentNetworkPolicy(ctx context.Context, db *database.PostgresDB, orgID string) (*agentNetworkPolicy, error) {
	if db == nil || db.Pool == nil || orgID == "" {
		return nil, errors.New("no database or organization")
	}
	p := agentNetworkPolicy{SplitTunnel: true, CorporateCIDRs: []string{}}
	err := db.Pool.QueryRow(ctx,
		`SELECT always_on, split_tunnel, block_direct_corporate_cidrs
		   FROM org_network_policy WHERE org_id = $1`, orgID).
		Scan(&p.AlwaysOn, &p.SplitTunnel, &p.BlockDirectCorporateCIDRs)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if p.BlockDirectCorporateCIDRs {
		var cidrs, hosts []string
		err := db.Pool.QueryRow(ctx,
			`SELECT COALESCE(array_agg(DISTINCT c) FILTER (WHERE c IS NOT NULL), '{}'),
			        COALESCE(array_agg(DISTINCT h) FILTER (WHERE h IS NOT NULL), '{}')
			   FROM applications a
			   JOIN network_targets nt ON nt.application_id = a.id AND nt.org_id = a.org_id
			   LEFT JOIN LATERAL unnest(nt.cidrs::text[]) AS c ON true
			   LEFT JOIN LATERAL unnest(nt.hosts) AS h ON true
			  WHERE a.org_id = $1 AND a.kind = 'network' AND a.enabled = true`, orgID).
			Scan(&cidrs, &hosts)
		if err != nil {
			return nil, err
		}
		p.CorporateCIDRs = corporatePrefixes(cidrs, hosts)
	}
	p.Version = policyVersion(p)
	return &p, nil
}

// tunnelPolicyDevices counts the organization's active devices by whether
// they run the current policy: applied (the version they last reported is
// current), pending (they report a tunnel status, with another version or
// none), and unreported (no tunnel status at all: an agent older than the
// tunnel, or one that has not reported since).
type tunnelPolicyDevices struct {
	Applied    int `json:"applied"`
	Pending    int `json:"pending"`
	Unreported int `json:"unreported"`
}

func countTunnelPolicyDevices(ctx context.Context, db *database.PostgresDB, orgID, version string) (tunnelPolicyDevices, error) {
	var d tunnelPolicyDevices
	err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE tunnel_status IS NOT NULL AND tunnel_policy_version = $2),
		        count(*) FILTER (WHERE tunnel_status IS NOT NULL AND tunnel_policy_version IS DISTINCT FROM $2),
		        count(*) FILTER (WHERE tunnel_status IS NULL)
		   FROM enrolled_agents WHERE org_id = $1 AND status = 'active'`, orgID, version).
		Scan(&d.Applied, &d.Pending, &d.Unreported)
	return d, err
}

// tunnelPolicyState is one device's standing against the current version, for
// the Agent Fleet page: "applied", "pending", or "" when the device reports
// no tunnel status (or the current version is not known).
func tunnelPolicyState(reported *string, hasStatus bool, current string) string {
	if !hasStatus || current == "" {
		return ""
	}
	if reported != nil && *reported == current {
		return "applied"
	}
	return "pending"
}
