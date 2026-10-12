package tunnel

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// BLOCKING DIRECT ACCESS TO THE CORPORATE NETWORKS.
//
// The organization's tunnel policy can say that the corporate networks are
// reachable only through the overlay (org_network_policy
// .block_direct_corporate_cidrs). The server sends the ranges that covers,
// the CIDRs and IP hosts of its network resources. While the tunnel is up the
// tunneler's routes already send those ranges into its TUN interface; the
// block is what keeps them from going out of the physical interface when it
// is down, or when a route the tunneler did not claim would have carried them.
//
// Linux only, and only when the agent runs as root: the agent loads an
// nftables table of its own, inet openidx_direct, whose output and forward
// chains reject traffic to the ranges unless it leaves through the tunneler's
// interface (ziti0, ziti1, ... ; ziti-tunnel-sdk-c names its TUN "ziti%d") or
// comes from a process running as root. Root is let through because the
// tunneler and the agent run as root and must reach the controller and the
// routers wherever they live (the tunneler excludes the routers' addresses
// from its own routes, so its overlay links leave through the physical
// interface, often into one of these very ranges), and because a process
// running as root could delete the table anyway: refusing it would only look
// stricter. The whole table is replaced in one nft transaction, so there is
// no moment with half a rule set, and it is removed when the policy no longer
// asks for it. It is deliberately left in place when the agent stops: the
// policy says the ranges are reachable only through the tunnel, and a stopped
// agent is no reason to open them (a reboot clears it, as nothing persists
// it).
//
// Elsewhere there is no hook yet and DirectBlockSupport says why; the agent
// reports the gap to the server ("block_direct" in policy_gaps) instead of
// claiming to enforce it. Windows would need a WFP filter with a per-app
// exemption for the tunneler (a Windows Firewall block rule beats every allow
// rule, so the firewall alone cannot express it); macOS would need a pf anchor
// and has no bundled tunneler yet.

// DirectBlockTable is the nftables table the block lives in.
const DirectBlockTable = "openidx_direct"

// tunnelerInterfaces matches the tunneler's TUN interfaces in nftables.
const tunnelerInterfaces = "ziti*"

// ErrDirectBlockUnsupported is wrapped by DirectBlockSupport's answer on a
// platform, or in a process, that cannot install the block.
var ErrDirectBlockUnsupported = errors.New("blocking direct corporate access is not supported here")

// DirectBlock installs and removes the block. Its methods are safe to call
// from any goroutine.
type DirectBlock struct {
	mu      sync.Mutex
	applied string // digest of the rule set last loaded; "" when none is
	run     func(script string) error
	support func() error
}

// NewDirectBlock returns a DirectBlock that loads rule sets with this
// platform's runner (nft on Linux).
func NewDirectBlock() *DirectBlock {
	return &DirectBlock{run: runNft, support: DirectBlockSupport}
}

// NewDirectBlockFunc returns a DirectBlock that loads rule sets with run and
// asks support whether it can; for callers that test what they ask of it.
func NewDirectBlockFunc(run func(script string) error, support func() error) *DirectBlock {
	return &DirectBlock{run: run, support: support}
}

// Supported says whether this DirectBlock can install the block here.
func (d *DirectBlock) Supported() error { return d.support() }

// Apply makes the block cover exactly cidrs. An unchanged set is not loaded
// again. An empty set removes the block.
func (d *DirectBlock) Apply(cidrs []string) error {
	if err := d.support(); err != nil {
		return err
	}
	v4, v6, err := splitPrefixes(cidrs)
	if err != nil {
		return err
	}
	if len(v4)+len(v6) == 0 {
		return d.Clear()
	}
	script := directBlockScript(v4, v6)
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(script)))
	d.mu.Lock()
	defer d.mu.Unlock()
	if sum == d.applied {
		return nil
	}
	if err := d.run(script); err != nil {
		return fmt.Errorf("loading the direct-access block: %w", err)
	}
	d.applied = sum
	return nil
}

// Clear removes the block. Removing a block that is not there is not an
// error, and Clear also removes a table an earlier run of the agent left.
func (d *DirectBlock) Clear() error {
	if err := d.support(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.run(clearScript()); err != nil {
		return fmt.Errorf("removing the direct-access block: %w", err)
	}
	d.applied = ""
	return nil
}

// Active reports whether a block is loaded by this DirectBlock.
func (d *DirectBlock) Active() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.applied != ""
}

// splitPrefixes parses and masks the ranges and sorts them into IPv4 and
// IPv6. A range that does not parse fails the whole set: a partial block is
// not what the policy asked for.
func splitPrefixes(cidrs []string) (v4, v6 []string, err error) {
	seen := map[netip.Prefix]bool{}
	for _, c := range cidrs {
		p, perr := netip.ParsePrefix(strings.TrimSpace(c))
		if perr != nil {
			return nil, nil, fmt.Errorf("corporate range %q: %w", c, perr)
		}
		p = p.Masked()
		if seen[p] {
			continue
		}
		seen[p] = true
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6, nil
}

// clearScript removes the table whether or not it exists: declaring an empty
// table first makes the delete always valid.
func clearScript() string {
	return "table inet " + DirectBlockTable + "\ndelete table inet " + DirectBlockTable + "\n"
}

// directBlockScript is the nft script that replaces the table with one
// rejecting the ranges outside the tunnel. The ranges are canonical prefixes
// (splitPrefixes), so they are safe to write into the script.
func directBlockScript(v4, v6 []string) string {
	var b strings.Builder
	b.WriteString(clearScript())
	b.WriteString("table inet " + DirectBlockTable + " {\n")
	if len(v4) > 0 {
		b.WriteString("\tset corp4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n")
		b.WriteString("\t\telements = { " + strings.Join(v4, ", ") + " }\n\t}\n")
	}
	if len(v6) > 0 {
		b.WriteString("\tset corp6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\tauto-merge\n")
		b.WriteString("\t\telements = { " + strings.Join(v6, ", ") + " }\n\t}\n")
	}
	rules := func(chain, hook string, local bool) {
		b.WriteString("\tchain " + chain + " {\n")
		b.WriteString("\t\ttype filter hook " + hook + " priority filter; policy accept;\n")
		b.WriteString("\t\toifname \"lo\" accept\n")
		b.WriteString("\t\toifname \"" + tunnelerInterfaces + "\" accept\n")
		if local {
			b.WriteString("\t\tmeta skuid 0 accept\n")
		}
		if len(v4) > 0 {
			b.WriteString("\t\tip daddr @corp4 reject with icmpx type admin-prohibited\n")
		}
		if len(v6) > 0 {
			b.WriteString("\t\tip6 daddr @corp6 reject with icmpx type admin-prohibited\n")
		}
		b.WriteString("\t}\n")
	}
	rules("output", "output", true)
	rules("forward", "forward", false)
	b.WriteString("}\n")
	return b.String()
}
