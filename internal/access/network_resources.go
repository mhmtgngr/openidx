package access

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// NETWORK SERVICES ARE RESOURCES.
//
// The VPN replacement bundles the OpenZiti tunneler (ziti-edge-tunnel) on each
// device. What a device's tunneler intercepts, and where the router hosting it
// forwards, is a network resource: an applications row of kind 'network'
// whose network_targets row lists the hosts, CIDRs and DNS names it covers,
// the port ranges and protocols, and optionally a fixed forward address.
//
// Who may reach it is the application's assignments, like any resource. The
// reconciler (network_reconciler.go) turns each row into one Ziti service:
//
//	intercept.v1  addresses = hosts + cidrs + dns_names, portRanges, protocols
//	host.v1       the fixed forward address/port, or "forward what was dialed"
//	              within the same allowed addresses, ports and protocols
//	Bind          #ziti-routers (the router in the target's network hosts it)
//	Dial          the device identities: networkDialPolicy
//
// The free-form "Add service" form in ziti_handlers.go still works and is
// deprecated in favour of this.

// networkServicePrefix names every service the reconciler converges for a
// network resource. The name is keyed by the application's id, never its
// name, so a rename changes nothing on the overlay; the prefix is reserved
// (reservedZitiServiceName), so no route or free-form service can take it.
const networkServicePrefix = "openidx-net-"

func networkServiceName(appID string) string { return networkServicePrefix + appID }

// PortRange is an inclusive port range, as intercept.v1 and host.v1 spell it.
type PortRange struct {
	Low  int `json:"low"`
	High int `json:"high"`
}

// NetworkTarget is what a network resource covers.
type NetworkTarget struct {
	ApplicationID  string      `json:"application_id"`
	Hosts          []string    `json:"hosts"`
	CIDRs          []string    `json:"cidrs"`
	DNSNames       []string    `json:"dns_names"`
	PortRanges     []PortRange `json:"port_ranges"`
	Protocols      []string    `json:"protocols"`
	ForwardAddress string      `json:"forward_address,omitempty"`
	ForwardPort    int         `json:"forward_port,omitempty"`
}

// hostLabel is one DNS label; a host name is one or more of them.
var hostLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func validHostName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if !hostLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// cleanList trims, drops empties and duplicates, keeping the first spelling.
func cleanList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[strings.ToLower(s)] {
			continue
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
	}
	return out
}

// appendUnique appends s unless the canonical list already holds it.
func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// normalizeNetworkTarget checks a target and returns it in the form it is
// stored and rendered in: lists cleaned, CIDRs canonical (192.0.2.77/24 becomes
// 192.0.2.0/24), port ranges sorted, protocols lower-case and defaulted to
// tcp+udp, an empty port list meaning every port.
func normalizeNetworkTarget(t NetworkTarget) (NetworkTarget, error) {
	var errs []string
	out := NetworkTarget{ApplicationID: t.ApplicationID}

	// Every address is canonicalised once (network_target_guard.go), and the
	// canonical form is what is checked, stored and written to Ziti, so the
	// guard and the router's parser read the same thing.
	for _, h := range cleanList(t.Hosts) {
		c, err := canonicalHost(h)
		if err != nil {
			errs = append(errs, "host "+err.Error())
			continue
		}
		out.Hosts = appendUnique(out.Hosts, c)
	}
	for _, c := range cleanList(t.CIDRs) {
		p, err := canonicalPrefix(c)
		if err != nil {
			errs = append(errs, "CIDR "+err.Error())
			continue
		}
		if p.Bits() == 0 {
			errs = append(errs, fmt.Sprintf("CIDR %q covers every address; a network resource names the networks it covers", c))
			continue
		}
		out.CIDRs = appendUnique(out.CIDRs, p.String())
	}
	for _, d := range cleanList(t.DNSNames) {
		c, err := canonicalDNSName(d)
		if err != nil {
			errs = append(errs, "DNS name "+err.Error())
			continue
		}
		out.DNSNames = appendUnique(out.DNSNames, c)
	}
	if len(out.Hosts)+len(out.CIDRs)+len(out.DNSNames) == 0 && len(errs) == 0 {
		errs = append(errs, "at least one host, CIDR or DNS name is required")
	}

	for _, r := range t.PortRanges {
		if r.High == 0 {
			r.High = r.Low
		}
		if r.Low < 1 || r.High > 65535 || r.Low > r.High {
			errs = append(errs, fmt.Sprintf("port range %d-%d is not within 1-65535 with low <= high", r.Low, r.High))
			continue
		}
		out.PortRanges = append(out.PortRanges, r)
	}
	if len(out.PortRanges) == 0 && len(t.PortRanges) == 0 {
		out.PortRanges = []PortRange{{Low: 1, High: 65535}}
	}
	sort.Slice(out.PortRanges, func(i, j int) bool {
		if out.PortRanges[i].Low != out.PortRanges[j].Low {
			return out.PortRanges[i].Low < out.PortRanges[j].Low
		}
		return out.PortRanges[i].High < out.PortRanges[j].High
	})

	protoSeen := map[string]bool{}
	for _, p := range t.Protocols {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || protoSeen[p] {
			continue
		}
		if p != "tcp" && p != "udp" {
			errs = append(errs, fmt.Sprintf("protocol %q is not tcp or udp", p))
			continue
		}
		protoSeen[p] = true
	}
	for _, p := range []string{"tcp", "udp"} {
		if protoSeen[p] {
			out.Protocols = append(out.Protocols, p)
		}
	}
	if len(out.Protocols) == 0 && len(t.Protocols) == 0 {
		out.Protocols = []string{"tcp", "udp"}
	}

	if fa := strings.TrimSpace(t.ForwardAddress); fa != "" {
		c, err := canonicalHost(fa)
		if err != nil {
			errs = append(errs, "forward address "+err.Error())
		}
		out.ForwardAddress = c
	}
	if t.ForwardPort != 0 && (t.ForwardPort < 1 || t.ForwardPort > 65535) {
		errs = append(errs, fmt.Sprintf("forward port %d is not within 1-65535", t.ForwardPort))
	}
	out.ForwardPort = t.ForwardPort

	if len(errs) == 0 {
		// Well-formed; now refuse what points at the platform itself
		// (network_target_guard.go).
		errs = guardEmittedConfigs(interceptV1Data(out), hostV1Data(out))
	}
	if len(errs) > 0 {
		return NetworkTarget{}, errors.New(strings.Join(errs, "; "))
	}
	return out, nil
}

// interceptAddresses is everything the tunneler captures for the resource.
func (t NetworkTarget) interceptAddresses() []string {
	out := make([]string, 0, len(t.Hosts)+len(t.CIDRs)+len(t.DNSNames))
	out = append(out, t.Hosts...)
	out = append(out, t.CIDRs...)
	out = append(out, t.DNSNames...)
	return out
}

func portRangesData(rs []PortRange) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(rs))
	for _, r := range rs {
		out = append(out, map[string]interface{}{"low": r.Low, "high": r.High})
	}
	return out
}

// interceptV1Data is the intercept.v1 config the device's tunneler reads:
// which addresses, ports and protocols it captures off its tun device and
// carries over the overlay to this service.
func interceptV1Data(t NetworkTarget) map[string]interface{} {
	return map[string]interface{}{
		"protocols":  t.Protocols,
		"addresses":  t.interceptAddresses(),
		"portRanges": portRangesData(t.PortRanges),
	}
}

// hostV1Data is the host.v1 config the hosting router reads: where a dial
// lands. With a forward address and port the router always dials that one
// place (a jump host, a load balancer). Without them it dials what the device
// dialed -- forwardAddress/forwardPort/forwardProtocol -- restricted to the
// resource's own addresses, ports and protocols (allowedAddresses accepts IPs,
// CIDRs, host names and *.domain wildcards), so the service is no wider than
// what the tunneler intercepts for it.
func hostV1Data(t NetworkTarget) map[string]interface{} {
	d := map[string]interface{}{}
	if len(t.Protocols) == 1 {
		d["protocol"] = t.Protocols[0]
	} else {
		d["forwardProtocol"] = true
		d["allowedProtocols"] = t.Protocols
	}
	if t.ForwardAddress != "" {
		d["address"] = t.ForwardAddress
	} else {
		d["forwardAddress"] = true
		d["allowedAddresses"] = t.interceptAddresses()
	}
	if t.ForwardPort != 0 {
		d["port"] = t.ForwardPort
	} else {
		d["forwardPort"] = true
		d["allowedPortRanges"] = portRangesData(t.PortRanges)
	}
	return d
}

// networkDialPolicy decides who may dial a network resource's service. It is
// dialPolicyFor with the blanket grant #openidx-agent -- every enrolled
// device -- because a network resource is reached through the device's
// tunneler, never clientless. Under assignment enforcement the policy is
// AllOf and names #openidx-agent beside the application's marker (and
// #device-trusted when the resource requires a trusted device): the user's own
// identity carries #app-<id> too, for BrowZer, and must not dial a network
// service. In observe mode the per-app marker sits beside the blanket grant,
// as it does for every other kind.
func networkDialPolicy(applicationID string, enforce, requireDeviceTrust bool) (roles []string, semantic string) {
	roles, semantic = dialPolicyFor("#openidx-agent", applicationID, enforce, requireDeviceTrust)
	if !enforce || applicationID == "" {
		return roles, semantic
	}
	for _, r := range roles {
		if r == "#openidx-agent" {
			return roles, "AllOf"
		}
	}
	return append(roles, "#openidx-agent"), "AllOf"
}
