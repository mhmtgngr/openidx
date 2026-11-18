package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// WHO ANSWERS THE NAMES OF TUNNELED APPLICATIONS.
//
// The tunneler answers DNS for the services its identity may dial, and Windows
// is told to ask it by an NRPT rule per name (-> 100.64.0.2). A VPN client that
// enforces its own DNS answers every UDP/53 question on the machine before the
// tunneler can hear it (measured: GlobalProtect, a fake NXDOMAIN whatever the
// address), and the names never resolve.
//
// With name_resolution "agent" the server gives every single-name network
// resource a pin (a stable overlay address the service also intercepts) and
// tells this device the pairs. Names does what that needs, on loopback, where
// the client does not reach (measured on the same machine, through the system
// resolver): it listens on 127.64.0.2:53 (Responder: pinned names only, REFUSED
// for everything else), points the NRPT at it for those names, and removes the
// tunneler's rule for them. Three safeguards, because it touches name
// resolution:
//
//   - It never claims a name before proving the path: a probe name is routed to
//     the responder and resolved the way an application would resolve it. If the
//     answer does not come from this process (a client that blocks loopback DNS
//     too), nothing else is touched and the state says why.
//   - It answers a pin only while the tunneler lists the pin's service among
//     those this device may dial. A service the server refused, or one this
//     device cannot dial, is left to whatever resolves the name today.
//   - It undoes itself: when the tunnel goes down or the setting goes off the
//     rules are removed (and the tunneler's put back while it is up); a marker
//     file lets the next start remove what a crash left.

const (
	// NamesAddr is the loopback address the agent's resolver listens on. Every
	// 127.x address is loopback on Windows; this one is the agent's alone.
	NamesAddr = "127.64.0.2"
	// tunnelerDNS is where the tunneler answers by default (the second address
	// of its 100.64.0.0/10 range).
	tunnelerDNS = "100.64.0.2"
	// selfTestName is a reserved name (RFC 6761) that nothing else answers.
	selfTestName = "openidx-selftest.invalid"
	// maxNamePins bounds one device's table, and with it the script size.
	maxNamePins = 200

	reconcileEvery = 15 * time.Second
	reapplyEvery   = 2 * time.Minute
	reverifyEvery  = 5 * time.Minute
	retryEvery     = 2 * time.Minute
)

var (
	selfTestAddr = [4]byte{100, 127, 255, 254}
	pinPool      = netip.MustParsePrefix("100.127.0.0/16")
)

// NamePin is one name this device answers, the overlay address it answers with,
// and the overlay service behind it.
type NamePin struct{ Name, IP, Service string }

// NamesState is where name resolution by the agent stands.
type NamesState string

const (
	NamesOff      NamesState = "off"      // not asked for, or nothing to answer yet
	NamesActive   NamesState = "active"   // answering
	NamesDegraded NamesState = "degraded" // asked for and not working: see Detail
)

// NamesStatus is Names' state for the report and the doctor.
type NamesStatus struct {
	// Wanted: the organization's policy asks the agent to answer names.
	Wanted bool
	State  NamesState
	// Requested is how many pins the policy delivered; Pins is how many of them
	// are being answered now (the rest are not well formed, or their service is
	// not listed by the tunneler).
	Requested int
	Pins      int
	Detail    string
}

// nameRules is the operating system's side: the NRPT.
type nameRules interface {
	Supported() error
	// Apply makes exactly names (among the agent's rules) point at server and
	// removes the tunneler's rule for each.
	Apply(names []string, server string) error
	// Clear removes the agent's rules and writes the tunneler's rule back for
	// each name in restore.
	Clear(restore []string) error
}

// Names runs name resolution by the agent. Zero value is not usable; use NewNames.
type Names struct {
	rules   nameRules
	resp    *Responder
	listen  func(*Responder) (io.Closer, error)
	resolve func(ctx context.Context, host string) ([]string, error)
	now     func() time.Time
	logger  *zap.Logger
	marker  string          // a file that exists while rules may be applied
	protect map[string]bool // names never answered (the agent's own server)

	wake chan struct{}

	stateMu sync.Mutex
	wanted  bool
	pins    []NamePin
	status  NamesStatus

	workMu     sync.Mutex // serializes reconcile and stop; held across a PowerShell run
	closer     io.Closer
	verified   bool
	lastVerify time.Time
	retryAt    time.Time
	appliedKey string
	svcKey     string
	lastApply  time.Time
	displaced  []string
	touched    bool
}

// NewNames builds the manager over the real operating system. marker is a path
// in the agent's own directory; protect are names that must never be answered
// (the server the agent talks to).
func NewNames(logger *zap.Logger, marker string, protect ...string) *Names {
	n := &Names{
		rules: newNameRules(), resp: &Responder{}, listen: listenNames,
		resolve: net.DefaultResolver.LookupHost, now: time.Now,
		logger: logger, marker: marker, protect: map[string]bool{},
		wake: make(chan struct{}, 1),
	}
	for _, p := range protect {
		if p = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p), ".")); p != "" {
			n.protect[p] = true
		}
	}
	n.status = NamesStatus{State: NamesOff}
	return n
}

// listenNames binds the responder's UDP and TCP sockets on NamesAddr:53.
func listenNames(r *Responder) (io.Closer, error) {
	pc, err := net.ListenPacket("udp", net.JoinHostPort(NamesAddr, "53"))
	if err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp", net.JoinHostPort(NamesAddr, "53"))
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	go r.ServeUDP(pc)
	go r.ServeTCP(l)
	return multiCloser{pc, l}, nil
}

type multiCloser []io.Closer

func (m multiCloser) Close() error {
	var first error
	for _, c := range m {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// SetWanted records what the organization's policy asks for. It returns at once;
// the work happens in Run.
func (n *Names) SetWanted(on bool, pins []NamePin) {
	n.stateMu.Lock()
	changed := on != n.wanted || !samePins(pins, n.pins)
	n.wanted, n.pins = on, append([]NamePin(nil), pins...)
	n.status.Wanted, n.status.Requested = on, len(pins)
	n.stateMu.Unlock()
	if changed {
		select {
		case n.wake <- struct{}{}:
		default:
		}
	}
}

func samePins(a, b []NamePin) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Status is the current state.
func (n *Names) Status() NamesStatus {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	return n.status
}

func (n *Names) setStatus(state NamesState, pins int, detail string) {
	n.stateMu.Lock()
	prev := n.status
	n.status.State, n.status.Pins, n.status.Detail = state, pins, detail
	cur := n.status
	n.stateMu.Unlock()
	if prev.State == cur.State && prev.Detail == cur.Detail && prev.Pins == cur.Pins {
		return
	}
	switch {
	case cur.State == NamesDegraded:
		n.logger.Warn("name resolution by the agent is not working", zap.String("detail", cur.Detail))
	case cur.State == NamesActive:
		n.logger.Info("the agent answers the names of tunneled applications", zap.Int("names", cur.Pins))
	case prev.State != cur.State:
		n.logger.Info("the agent does not answer names", zap.String("detail", cur.Detail))
	}
}

// Run keeps the state right until ctx ends: every reconcileEvery, and at once
// when the policy changes. view says whether the tunnel is connected and which
// overlay services it lists as dialable by this device.
func (n *Names) Run(ctx context.Context, view func() (connected bool, services []string)) {
	n.cleanOrphans()
	t := time.NewTicker(reconcileEvery)
	defer t.Stop()
	for {
		connected, services := view()
		n.reconcile(ctx, connected, services)
		select {
		case <-ctx.Done():
			n.workMu.Lock()
			n.stop(false)
			n.workMu.Unlock()
			return
		case <-t.C:
		case <-n.wake:
		}
	}
}

// cleanOrphans removes what an earlier run left if it died with rules applied.
func (n *Names) cleanOrphans() {
	if n.marker == "" {
		return
	}
	if _, err := os.Stat(n.marker); err != nil {
		return
	}
	if err := n.rules.Supported(); err != nil {
		_ = os.Remove(n.marker)
		return
	}
	if err := n.rules.Clear(nil); err != nil {
		n.logger.Warn("could not remove name resolution rules a previous run left", zap.Error(err))
		return
	}
	_ = os.Remove(n.marker)
}

// effective is the table to answer: the pins that are well formed, inside the
// pin pool, not protected, and whose service the tunneler lists. skipped says
// why the others are not.
func (n *Names) effective(pins []NamePin, services []string) (table map[string][4]byte, names []string, skipped []string) {
	visible := make(map[string]bool, len(services))
	for _, s := range services {
		visible[s] = true
	}
	table = map[string][4]byte{}
	sorted := append([]NamePin(nil), pins...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, p := range sorted {
		name := strings.ToLower(strings.TrimSuffix(p.Name, "."))
		addr, err := netip.ParseAddr(p.IP)
		switch {
		case len(name) > maxDNSName || !nameRE.MatchString(name) || net.ParseIP(name) != nil:
			skipped = append(skipped, fmt.Sprintf("%q is not a plain DNS name", p.Name))
		case n.protect[name]:
			skipped = append(skipped, name+" is the server this agent talks to")
		case err != nil || !addr.Is4() || !pinPool.Contains(addr):
			skipped = append(skipped, fmt.Sprintf("%s: %q is not an address of %s", name, p.IP, pinPool))
		case p.Service != "" && !visible[p.Service]:
			skipped = append(skipped, name+": its service is not listed by the tunneler")
		case len(names) >= maxNamePins:
			skipped = append(skipped, name+": over the limit of "+fmt.Sprint(maxNamePins)+" names")
		default:
			table[name] = addr.As4()
			names = append(names, name)
		}
	}
	return table, names, skipped
}

func (n *Names) reconcile(ctx context.Context, connected bool, services []string) {
	n.workMu.Lock()
	defer n.workMu.Unlock()
	n.stateMu.Lock()
	wanted, pins := n.wanted, append([]NamePin(nil), n.pins...)
	n.stateMu.Unlock()

	if !wanted {
		n.stop(connected)
		n.setStatus(NamesOff, 0, "the organization does not ask the agent to answer names")
		return
	}
	if err := n.rules.Supported(); err != nil {
		n.setStatus(NamesDegraded, 0, err.Error())
		return
	}
	if !connected {
		n.stop(false)
		n.setStatus(NamesOff, 0, "the tunnel is not connected")
		return
	}
	table, names, skipped := n.effective(pins, services)
	if len(names) == 0 {
		n.stop(true)
		detail := "no pinned service is listed by the tunneler yet"
		if len(pins) == 0 {
			detail = "the server sent no pins for this device"
		}
		n.setStatus(NamesOff, 0, detail)
		return
	}
	if len(skipped) > 0 {
		n.logger.Info("some pinned names are not answered", zap.Strings("skipped", skipped))
	}

	now := n.now()
	if n.closer == nil {
		c, err := n.listen(n.resp)
		if err != nil {
			n.setStatus(NamesDegraded, 0, fmt.Sprintf("cannot listen on %s:53: %v", NamesAddr, err))
			return
		}
		n.closer = c
	}
	withProbe := make(map[string][4]byte, len(table)+1)
	for k, v := range table {
		withProbe[k] = v
	}
	withProbe[selfTestName] = selfTestAddr
	n.resp.SetTable(withProbe)

	if !n.verified {
		if now.Before(n.retryAt) {
			return // keep what the last attempt said
		}
		if err := n.verify(ctx, true); err != nil {
			n.failVerify(err, now, false)
			return
		}
		n.verified, n.lastVerify = true, now
	}

	key, svcKey := strings.Join(names, ","), strings.Join(sortedCopy(services), ",")
	if key != n.appliedKey || svcKey != n.svcKey || now.Sub(n.lastApply) >= reapplyEvery {
		n.touch()
		if err := n.rules.Apply(append(append([]string(nil), names...), selfTestName), NamesAddr); err != nil {
			n.setStatus(NamesDegraded, 0, err.Error())
			return
		}
		n.appliedKey, n.svcKey, n.lastApply = key, svcKey, now
		n.displaced = names
	}
	if now.Sub(n.lastVerify) >= reverifyEvery {
		if err := n.verify(ctx, false); err != nil {
			n.failVerify(err, now, true)
			return
		}
		n.lastVerify = now
	}
	n.setStatus(NamesActive, len(names), "")
}

// verify proves that a lookup routed to the responder reaches this process the
// way an application's lookup would. applyProbe adds the probe name's rule
// first (nothing else is touched yet); on a re-check the rule is already there.
func (n *Names) verify(ctx context.Context, applyProbe bool) error {
	if applyProbe {
		n.touch()
		if err := n.rules.Apply([]string{selfTestName}, NamesAddr); err != nil {
			return err
		}
	}
	before := n.resp.Answered()
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := n.resolve(cctx, selfTestName)
	if err != nil {
		return fmt.Errorf("a lookup routed to %s did not get an answer (is another program blocking local DNS?): %w", NamesAddr, err)
	}
	want := netip.AddrFrom4(selfTestAddr).String()
	found := false
	for _, a := range addrs {
		if a == want {
			found = true
		}
	}
	if !found || n.resp.Answered() == before {
		return fmt.Errorf("a lookup routed to %s was answered by something other than the agent", NamesAddr)
	}
	return nil
}

// failVerify gives up the path: what was applied is removed (the tunneler's own
// rules back, as it is still up) and the next try waits.
func (n *Names) failVerify(err error, now time.Time, restore bool) {
	n.stop(restore)
	n.retryAt = now.Add(retryEvery)
	n.setStatus(NamesDegraded, 0, err.Error())
}

func (n *Names) touch() {
	if n.touched {
		return
	}
	n.touched = true
	if n.marker != "" {
		_ = os.WriteFile(n.marker, []byte("name resolution rules may be applied\n"), 0o600)
	}
}

// stop undoes everything applied. restore puts the tunneler's rules back for
// the names that were replaced (right when the tunnel is still up). Idempotent,
// and a no-op when nothing was ever applied.
func (n *Names) stop(restore bool) {
	if n.closer != nil {
		_ = n.closer.Close()
		n.closer = nil
	}
	if n.touched {
		var back []string
		if restore {
			back = n.displaced
		}
		if err := n.rules.Clear(back); err != nil {
			n.logger.Warn("could not remove the agent's name resolution rules", zap.Error(err))
		} else {
			n.touched = false
			if n.marker != "" {
				_ = os.Remove(n.marker)
			}
		}
	}
	n.verified, n.appliedKey, n.svcKey, n.displaced = false, "", "", nil
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
