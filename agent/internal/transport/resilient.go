package transport

import (
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// errNoZiti mirrors the plain-HTTPS transport's DialServiceConn error so
// remote-support's existing "fall back to public WSS" check still triggers when
// the resilient transport has no Ziti path.
var errNoZiti = errors.New("ziti service dial not supported on HTTPS transport")

// ResilientTransport prefers a Ziti-backed transport but automatically falls
// back to a plain HTTPS transport when the overlay is unreachable. This keeps
// the agent working through Ziti control-plane hiccups (no edge routers online,
// controller restart, transient network loss) without ever crashing the run
// loop or requiring a re-enroll. Once the overlay recovers, calls transparently
// resume over Ziti after a short cooldown.
//
// The design goal is operational simplicity: an operator never has to reason
// about "is it on Ziti or HTTPS right now" for basic connectivity. The agent
// always reaches the server by the best available path, and remote-support
// signaling still prefers the overlay via DialServiceConn.
type ResilientTransport struct {
	ziti   Transport // Ziti-backed; may be nil if identity/context failed to load
	https  Transport // always-available public fallback
	logger *zap.Logger

	mu            sync.Mutex
	zitiCooldown  time.Time // don't retry Ziti until after this instant
	lastOnZiti    bool      // for edge-triggered logging
	loggedInitial bool
}

// cooldownWindow is how long to stick with HTTPS after a Ziti failure before
// probing the overlay again. Short enough to recover quickly, long enough to
// avoid hammering a dead controller on every poll.
const cooldownWindow = 60 * time.Second

// NewResilientTransport wraps a Ziti transport with an HTTPS fallback. If ziti
// is nil it behaves exactly like the HTTPS transport.
func NewResilientTransport(ziti, https Transport, logger *zap.Logger) *ResilientTransport {
	return &ResilientTransport{ziti: ziti, https: https, logger: logger}
}

// isOverlayUnreachable reports whether an error indicates the Ziti overlay is
// unreachable (as opposed to a genuine application error from the server, which
// we must NOT mask by retrying over HTTPS with different semantics). We only
// fall back on transport/dial-level failures.
func isOverlayUnreachable(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "NO_EDGE_ROUTERS_AVAILABLE"),
		strings.Contains(s, "unable to dial service"),
		strings.Contains(s, "ziti context not initialised"),
		strings.Contains(s, "no edge routers"),
		strings.Contains(s, "connection refused"),
		strings.Contains(s, "controller is not leader"),
		strings.Contains(s, "context deadline exceeded"),
		strings.Contains(s, "i/o timeout"),
		strings.Contains(s, "dial tcp"),
		strings.Contains(s, "EOF"):
		return true
	}
	return false
}

// useZiti reports whether we should attempt the Ziti path right now.
func (r *ResilientTransport) useZiti() bool {
	if r.ziti == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return time.Now().After(r.zitiCooldown)
}

// tripCooldown records a Ziti failure and starts the HTTPS-fallback window.
func (r *ResilientTransport) tripCooldown() {
	r.mu.Lock()
	r.zitiCooldown = time.Now().Add(cooldownWindow)
	wasOnZiti := r.lastOnZiti
	r.lastOnZiti = false
	r.mu.Unlock()
	if wasOnZiti || !r.loggedInitial {
		r.loggedInitial = true
		r.logger.Warn("overlay unreachable; falling back to HTTPS transport",
			zap.Duration("retry_in", cooldownWindow))
	}
}

// markZitiOK records a successful Ziti call (edge-triggered log on recovery).
func (r *ResilientTransport) markZitiOK() {
	r.mu.Lock()
	wasOnZiti := r.lastOnZiti
	r.lastOnZiti = true
	r.loggedInitial = true
	r.mu.Unlock()
	if !wasOnZiti {
		r.logger.Info("using Ziti overlay transport")
	}
}

// run executes fn over Ziti when available, falling back to HTTPS on overlay
// failures. Application errors from Ziti are returned as-is (not masked).
func runResilient[T any](r *ResilientTransport, zitiFn, httpsFn func(Transport) (T, error)) (T, error) {
	if r.useZiti() {
		v, err := zitiFn(r.ziti)
		if err == nil {
			r.markZitiOK()
			return v, nil
		}
		if isOverlayUnreachable(err) {
			r.tripCooldown()
			// fall through to HTTPS
		} else {
			// Genuine server/application error; surface it.
			return v, err
		}
	}
	return httpsFn(r.https)
}

// Enroll enrolls over the best available path.
func (r *ResilientTransport) Enroll(token string) (*EnrollResponse, error) {
	return runResilient(r,
		func(t Transport) (*EnrollResponse, error) { return t.Enroll(token) },
		func(t Transport) (*EnrollResponse, error) { return t.Enroll(token) })
}

// ReportResults reports posture over the best available path.
func (r *ResilientTransport) ReportResults(data []byte) error {
	_, err := runResilient(r,
		func(t Transport) (struct{}, error) { return struct{}{}, t.ReportResults(data) },
		func(t Transport) (struct{}, error) { return struct{}{}, t.ReportResults(data) })
	return err
}

// GetConfig fetches server config over the best available path.
func (r *ResilientTransport) GetConfig() ([]byte, error) {
	return runResilient(r,
		func(t Transport) ([]byte, error) { return t.GetConfig() },
		func(t Transport) ([]byte, error) { return t.GetConfig() })
}

// SendConsent relays a consent decision over the best available path.
func (r *ResilientTransport) SendConsent(sessionID, decision string) error {
	_, err := runResilient(r,
		func(t Transport) (struct{}, error) { return struct{}{}, t.SendConsent(sessionID, decision) },
		func(t Transport) (struct{}, error) { return struct{}{}, t.SendConsent(sessionID, decision) })
	return err
}

// DialServiceConn opens a raw overlay connection. This is Ziti-only by nature
// (there is no HTTPS equivalent of an overlay service dial); callers already
// handle the error by falling back to a public WSS dial, so we return the Ziti
// error directly when the overlay path is unavailable.
func (r *ResilientTransport) DialServiceConn(serviceName string) (net.Conn, error) {
	if r.ziti == nil {
		return nil, errNoZiti
	}
	conn, err := r.ziti.DialServiceConn(serviceName)
	if err != nil && isOverlayUnreachable(err) {
		r.tripCooldown()
	}
	return conn, err
}
