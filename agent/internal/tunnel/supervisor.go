package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// Mode says who owns the tunneler process.
type Mode string

const (
	// ModeAuto runs the tunneler as a child when this process is privileged
	// enough to (always on Windows, root on Unix), and as External otherwise.
	ModeAuto Mode = "auto"
	// ModeChild: the supervisor starts, restarts and stops the tunneler.
	ModeChild Mode = "child"
	// ModeExternal: something else runs the tunneler (openidx-tunnel.service
	// on Linux); the supervisor only writes its identity and reads its status.
	ModeExternal Mode = "external"
)

// Config is how a Supervisor is set up. Zero durations take the defaults.
type Config struct {
	Logger *zap.Logger

	// AgentID names the device identity file (dev-<agent_id>.json).
	AgentID string
	// IdentitySource is the agent's enrolled ziti-identity.json.
	IdentitySource string
	// IdentityDir is the directory the tunneler loads identities from.
	IdentityDir string
	// BinaryPath is an explicit tunneler path; "" finds the bundled one.
	BinaryPath string
	// AgentExe is the agent binary the bundled tunneler sits next to; ""
	// means os.Executable().
	AgentExe string
	// Mode is child, external or auto (the default).
	Mode Mode
	// ProbeAddress, when set, is a host:port reachable only through the
	// tunnel. It is dialled when the tunneler's IPC does not answer, and a
	// connection counts as healthy.
	ProbeAddress string
	// LogFile receives the child tunneler's output; "" discards it.
	LogFile string
	// Pipe is the tunneler's IPC discriminator; "" means IPCDiscriminator.
	Pipe string

	// MinBackoff is the wait before the first restart after a crash; it
	// doubles with each crash in a row up to MaxBackoff. A run that lasted
	// StableAfter resets the count.
	MinBackoff  time.Duration
	MaxBackoff  time.Duration
	StableAfter time.Duration
	// PollInterval is how often the tunneler's health is read.
	PollInterval time.Duration
	// CommandTimeout bounds each tunnel_status / version / probe call.
	CommandTimeout time.Duration
	// StopGrace is how long a stopping tunneler has after SIGTERM before it
	// is killed (Unix; Windows kills at once).
	StopGrace time.Duration
}

func (c *Config) defaults() {
	if c.Logger == nil {
		c.Logger = zap.NewNop()
	}
	if c.Mode == "" {
		c.Mode = ModeAuto
	}
	if c.Pipe == "" {
		c.Pipe = IPCDiscriminator
	}
	set := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	set(&c.MinBackoff, 2*time.Second)
	set(&c.MaxBackoff, 2*time.Minute)
	set(&c.StableAfter, 2*time.Minute)
	set(&c.PollInterval, 15*time.Second)
	set(&c.CommandTimeout, 5*time.Second)
	set(&c.StopGrace, 10*time.Second)
}

// maxLogBytes is the size at which the tunneler log is rotated to .1 when the
// tunneler is next started.
const maxLogBytes = 10 << 20

// Supervisor keeps the tunneler running while it is enabled and reports its
// state. Its methods are safe to call from any goroutine; Run is called once.
type Supervisor struct {
	cfg  Config
	log  *zap.Logger
	mode Mode
	ids  *Provisioner // used only by Run's goroutine

	enabled atomic.Bool
	wake    chan struct{}

	mu     sync.Mutex
	status Status
	detail string
	starts int // child starts, for tests and the log
}

// New returns a Supervisor, disabled until SetEnabled(true).
func New(cfg Config) *Supervisor {
	cfg.defaults()
	mode := cfg.Mode
	if mode != ModeChild && mode != ModeExternal {
		mode = ModeExternal
		if defaultPrivileged() {
			mode = ModeChild
		}
	}
	return &Supervisor{
		cfg:    cfg,
		log:    cfg.Logger.Named("tunnel"),
		mode:   mode,
		ids:    &Provisioner{Source: cfg.IdentitySource, Dir: cfg.IdentityDir, AgentID: cfg.AgentID},
		wake:   make(chan struct{}, 1),
		status: Status{State: StateOff, Services: []string{}},
	}
}

// Mode is the resolved mode: child or external.
func (s *Supervisor) Mode() Mode { return s.mode }

// SetEnabled turns the tunnel on or off. The change takes effect at once.
func (s *Supervisor) SetEnabled(on bool) {
	if s.enabled.Swap(on) != on {
		s.log.Info("tunnel enablement changed", zap.Bool("enabled", on))
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

// Enabled reports whether the tunnel is meant to be on.
func (s *Supervisor) Enabled() bool { return s.enabled.Load() }

// Status is the tunnel's latest state, for the report and the tray.
func (s *Supervisor) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status.clone()
}

// Detail says why the state is what it is ("" when connected or off), for
// the tray and the log. It is not part of the report.
func (s *Supervisor) Detail() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.detail
}

func (s *Supervisor) startCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.starts
}

// update records a new state. version "" keeps the known one; services nil
// clears them. LastSeen moves only when seen is true.
func (s *Supervisor) update(state State, detail, version string, services []string, seen bool) {
	s.mu.Lock()
	prev, prevDetail := s.status.State, s.detail
	s.status.State = state
	s.detail = detail
	if version != "" {
		s.status.Version = version
	}
	if services == nil {
		services = []string{}
	}
	s.status.Services = services
	if seen {
		now := time.Now().UTC()
		s.status.LastSeen = &now
	}
	s.mu.Unlock()
	if prev != state || prevDetail != detail {
		s.log.Info("tunnel state", zap.String("state", string(state)), zap.String("detail", detail))
	}
}

// child is one run of the tunneler.
type child struct {
	cmd     *exec.Cmd
	started time.Time
	done    chan struct{}
	err     error
}

// loop is the Run loop's state between iterations.
type loop struct {
	child      *child
	failures   int
	nextStart  time.Time
	lastFail   string      // why the tunneler last stopped, while a restart is pending
	bin        *heldBinary // opened, checked and held (binary.go)
	version    string
	wasEnabled bool
	guard      *processGuard
}

// Run supervises the tunneler until ctx is cancelled, then stops it.
func (s *Supervisor) Run(ctx context.Context) error {
	l := &loop{}
	if s.mode == ModeChild {
		g, err := newProcessGuard()
		if err != nil {
			s.log.Warn("tunnel: the tunneler will not be tied to this process's lifetime", zap.Error(err))
		}
		l.guard = g
	}
	defer func() {
		s.stopChild(l)
		l.bin.close()
		l.guard.close()
	}()
	for {
		wait := s.step(ctx, l)
		var exited <-chan struct{}
		if l.child != nil {
			exited = l.child.done
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-s.wake:
		case <-exited:
			s.childExited(l)
		case <-timer.C:
		}
		timer.Stop()
	}
}

// step does one round of supervision and returns how long to wait before the
// next one.
func (s *Supervisor) step(ctx context.Context, l *loop) time.Duration {
	poll := s.cfg.PollInterval
	if !s.enabled.Load() {
		s.stopChild(l)
		l.failures, l.nextStart = 0, time.Time{}
		if l.wasEnabled {
			// The tunneler's copy of the private key is not left behind on a
			// device whose tunnel is off. In external mode this is also how
			// the tunnel is turned off: the unit's tunneler has nothing to
			// load the next time it starts.
			if _, err := s.ids.Forget(); err != nil {
				s.log.Warn("tunnel: removing the identity copy", zap.Error(err))
			}
			l.wasEnabled = false
		}
		s.update(StateOff, "", "", nil, false)
		return poll
	}
	l.wasEnabled = true

	path, err := Locate(s.cfg.BinaryPath, s.cfg.AgentExe)
	if err != nil {
		s.stopChild(l)
		s.dropBinary(l)
		state := StateNotInstalled
		if !errors.Is(err, ErrNotInstalled) {
			state = StateDegraded // there is a tunneler, and it is not safe to run
		}
		s.update(state, err.Error(), "", nil, false)
		return poll
	}
	if l.bin == nil || l.bin.path != path || !l.bin.stillCurrent() {
		// A different or replaced file: open and check the new one. A child
		// started from the old one keeps running until it next restarts.
		h, err := openBinary(path)
		if err != nil {
			s.stopChild(l)
			s.dropBinary(l)
			s.update(StateDegraded, err.Error(), "", nil, false)
			return poll
		}
		s.dropBinary(l)
		l.bin = h
		l.version = queryVersion(ctx, h, s.cfg.CommandTimeout)
		s.log.Info("tunnel: using tunneler", zap.String("path", path), zap.String("sha256", h.sum),
			zap.String("version", l.version))
	}

	changed, err := s.ids.Provision()
	if err != nil {
		s.update(StateDegraded, err.Error(), l.version, nil, false)
		return poll
	}

	if s.mode == ModeExternal {
		s.observe(ctx, l)
		return poll
	}

	if changed && l.child != nil {
		// A new identity (the device was enrolled again) is read at start.
		s.log.Info("tunnel: device identity changed; restarting the tunneler")
		s.stopChild(l)
		l.nextStart = time.Time{}
	}
	if l.child == nil {
		if wait := time.Until(l.nextStart); wait > 0 {
			s.update(StateDegraded, l.lastFail+"; waiting to restart it", l.version, nil, false)
			if wait < poll {
				return wait
			}
			return poll
		}
		if err := s.startChild(l); err != nil {
			s.scheduleRestart(l, err.Error())
			return minDuration(poll, time.Until(l.nextStart))
		}
		s.update(StateDegraded, "the tunneler is starting", l.version, nil, false)
		return poll
	}
	s.observe(ctx, l)
	return poll
}

// observe reads the tunneler's health: its IPC first, the dial probe second.
func (s *Supervisor) observe(ctx context.Context, l *loop) {
	reading, err := queryIPC(ctx, l.bin, s.cfg.Pipe, s.cfg.CommandTimeout)
	if err == nil {
		version := reading.Version
		if version == "" {
			version = l.version
		}
		s.update(reading.State, reading.Detail, version, reading.Services, true)
		return
	}
	if s.cfg.ProbeAddress != "" {
		d := net.Dialer{Timeout: s.cfg.CommandTimeout}
		if conn, derr := d.DialContext(ctx, "tcp", s.cfg.ProbeAddress); derr == nil {
			_ = conn.Close()
			s.update(StateConnected, "", l.version, nil, true)
			return
		}
	}
	detail := "the tunneler's IPC does not answer: " + err.Error()
	if s.mode == ModeExternal {
		detail = "the tunneler (openidx-tunnel.service) does not answer: " + err.Error()
	}
	s.update(StateDegraded, detail, l.version, nil, false)
}

// dropBinary releases the held binary. On Windows a running child keeps its
// own image open, so it is not affected.
func (s *Supervisor) dropBinary(l *loop) {
	l.bin.close()
	l.bin = nil
}

func (s *Supervisor) startChild(l *loop) error {
	// The held file is hashed again before every start: it is the one that
	// was checked, and it still matches the build's pin.
	if err := l.bin.verifyPin(); err != nil {
		return err
	}
	args := []string{"run", "--identity-dir", s.cfg.IdentityDir, "-P", s.cfg.Pipe}
	cmd := l.bin.command(nil, args...)
	configureChild(cmd)
	var logf *os.File
	if s.cfg.LogFile != "" {
		f, err := openLog(s.cfg.LogFile)
		if err != nil {
			s.log.Warn("tunnel: cannot open the tunneler log; its output is discarded", zap.Error(err))
		} else {
			logf = f
			cmd.Stdout, cmd.Stderr = f, f
		}
	}
	if err := cmd.Start(); err != nil {
		if logf != nil {
			_ = logf.Close()
		}
		return fmt.Errorf("starting the tunneler: %w", err)
	}
	if err := l.guard.adopt(cmd.Process); err != nil {
		s.log.Warn("tunnel: the tunneler will outlive a crash of this process", zap.Error(err))
	}
	c := &child{cmd: cmd, started: time.Now(), done: make(chan struct{})}
	go func() {
		c.err = cmd.Wait()
		if logf != nil {
			_ = logf.Close()
		}
		close(c.done)
	}()
	l.child = c
	s.mu.Lock()
	s.starts++
	n := s.starts
	s.mu.Unlock()
	s.log.Info("tunnel: tunneler started", zap.Int("pid", cmd.Process.Pid), zap.Int("start", n),
		zap.String("identity_dir", s.cfg.IdentityDir))
	return nil
}

// childExited handles a tunneler that stopped on its own.
func (s *Supervisor) childExited(l *loop) {
	c := l.child
	if c == nil {
		return
	}
	l.child = nil
	ran := time.Since(c.started)
	reason := "the tunneler exited"
	if c.err != nil {
		reason = "the tunneler exited: " + c.err.Error()
	}
	if ran >= s.cfg.StableAfter {
		l.failures = 0 // it ran for a while: this is a new problem, not a crash loop
	}
	s.scheduleRestart(l, reason)
}

func (s *Supervisor) scheduleRestart(l *loop, reason string) {
	l.failures++
	delay := backoff(l.failures, s.cfg.MinBackoff, s.cfg.MaxBackoff)
	l.nextStart = time.Now().Add(delay)
	l.lastFail = reason
	s.log.Warn("tunnel: restarting the tunneler after a delay", zap.String("reason", reason),
		zap.Int("failures_in_a_row", l.failures), zap.Duration("delay", delay))
	s.update(StateDegraded, reason+"; waiting to restart it", l.version, nil, false)
}

func (s *Supervisor) stopChild(l *loop) {
	c := l.child
	if c == nil {
		return
	}
	l.child = nil
	terminate(c.cmd.Process, c.done, s.cfg.StopGrace)
	s.log.Info("tunnel: tunneler stopped")
}

// backoff is the wait before restart number n (1-based): min doubled for each
// failure in a row, at most max.
func backoff(n int, min, max time.Duration) time.Duration {
	d := min
	for i := 1; i < n && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	return d
}

func minDuration(a, b time.Duration) time.Duration {
	if b < a {
		if b < 0 {
			return 0
		}
		return b
	}
	return a
}

// openLog opens the tunneler log for appending, rotating it to .1 once it
// has grown past maxLogBytes.
func openLog(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxLogBytes {
		_ = os.Remove(path + ".1")
		if err := os.Rename(path, path+".1"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}
