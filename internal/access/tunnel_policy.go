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
// org_network_policy (migrations 232, 256) is what an administrator sets on the
// Network Resources page: always on, split tunnel, block direct access to the
// corporate networks. Until this file nothing sent it anywhere, so the console
// setting changed nothing on a device. The agent already reads an
// org_network_policy object from /agent/config and from the response to its
// posture report (agent/internal/agent/tunnel.go); this builds that object.
//
// What a device is given:
//
//   - the three switches, with a missing row read as the defaults; always_on
//     is the device's own: tunnel_scope all, or tagged with one of the
//     device's tags in tunnel_tags;
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

// The tunnel scope (migration 256): who the tunnel turns on for.
const (
	tunnelScopeAll    = "all"
	tunnelScopeTagged = "tagged"
	tunnelScopeOff    = "off"
)

// maxTunnelTags bounds tunnel_tags.
const maxTunnelTags = 64

// orgTunnelPolicy is the organization's stored policy before it is made one
// device's: Base carries every field but AlwaysOn and Version, which depend on
// the device's tags.
type orgTunnelPolicy struct {
	Base  agentNetworkPolicy
	Scope string
	Tags  []string
}

// alwaysOnFor is a device's effective always_on: true for scope all, true for
// scope tagged when the device's tags intersect tunnel_tags, false otherwise.
func (o *orgTunnelPolicy) alwaysOnFor(deviceTags []string) bool {
	switch o.Scope {
	case tunnelScopeAll:
		return true
	case tunnelScopeTagged:
		for _, t := range deviceTags {
			for _, w := range o.Tags {
				if t == w {
					return true
				}
			}
		}
	}
	return false
}

// forDevice is the policy one device with these tags receives. The version
// covers the effective always_on, so retagging a device in or out of the
// scope moves its version.
func (o *orgTunnelPolicy) forDevice(deviceTags []string) *agentNetworkPolicy {
	p := o.Base
	p.AlwaysOn = o.alwaysOnFor(deviceTags)
	p.Version = policyVersion(p)
	return &p
}

// versions is the version a device gets with the tunnel on, and with it off.
func (o *orgTunnelPolicy) versions() (on, off string) {
	p := o.Base
	p.AlwaysOn = true
	on = policyVersion(p)
	p.AlwaysOn = false
	return on, policyVersion(p)
}

// loadOrgTunnelPolicy reads the organization's stored tunnel policy; a
// missing row is the defaults (scope tagged with no tags: off everywhere).
// ctx must carry the organization (the tables are under RLS).
func loadOrgTunnelPolicy(ctx context.Context, db *database.PostgresDB, orgID string) (*orgTunnelPolicy, error) {
	if db == nil || db.Pool == nil || orgID == "" {
		return nil, errors.New("no database or organization")
	}
	o := orgTunnelPolicy{Base: agentNetworkPolicy{SplitTunnel: true, CorporateCIDRs: []string{}}, Scope: tunnelScopeTagged, Tags: []string{}}
	err := db.Pool.QueryRow(ctx,
		`SELECT split_tunnel, block_direct_corporate_cidrs, tunnel_scope, tunnel_tags
		   FROM org_network_policy WHERE org_id = $1`, orgID).
		Scan(&o.Base.SplitTunnel, &o.Base.BlockDirectCorporateCIDRs, &o.Scope, &o.Tags)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if o.Base.BlockDirectCorporateCIDRs {
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
		o.Base.CorporateCIDRs = corporatePrefixes(cidrs, hosts)
	}
	return &o, nil
}

// loadAgentNetworkPolicy is the policy a device with no tags receives: for
// scope all the tunnel is on, otherwise off.
func loadAgentNetworkPolicy(ctx context.Context, db *database.PostgresDB, orgID string) (*agentNetworkPolicy, error) {
	o, err := loadOrgTunnelPolicy(ctx, db, orgID)
	if err != nil {
		return nil, err
	}
	return o.forDevice(nil), nil
}

// loadDeviceNetworkPolicy is the policy the device agentID receives, with
// always_on computed from its tags.
func loadDeviceNetworkPolicy(ctx context.Context, db *database.PostgresDB, orgID, agentID string) (*agentNetworkPolicy, error) {
	o, err := loadOrgTunnelPolicy(ctx, db, orgID)
	if err != nil {
		return nil, err
	}
	var tags []string
	if err := db.Pool.QueryRow(ctx,
		`SELECT COALESCE(tags, '{}') FROM enrolled_agents WHERE agent_id = $1 AND org_id = $2`,
		agentID, orgID).Scan(&tags); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return o.forDevice(tags), nil
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

// Each device is compared with its own current version: the one with the
// tunnel on when the scope covers it, the one with it off otherwise.
func countTunnelPolicyDevices(ctx context.Context, db *database.PostgresDB, orgID string, o *orgTunnelPolicy) (tunnelPolicyDevices, error) {
	var d tunnelPolicyDevices
	on, off := o.versions()
	err := db.Pool.QueryRow(ctx,
		`WITH a AS (
		   SELECT tunnel_status, tunnel_policy_version,
		          CASE WHEN $2 = 'all' OR ($2 = 'tagged' AND COALESCE(tags, '{}') && $3::text[])
		               THEN $4 ELSE $5 END AS want
		     FROM enrolled_agents WHERE org_id = $1 AND status = 'active')
		 SELECT count(*) FILTER (WHERE tunnel_status IS NOT NULL AND tunnel_policy_version = want),
		        count(*) FILTER (WHERE tunnel_status IS NOT NULL AND tunnel_policy_version IS DISTINCT FROM want),
		        count(*) FILTER (WHERE tunnel_status IS NULL)
		   FROM a`, orgID, o.Scope, o.Tags, on, off).
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
