package access

import (
	"context"
	"sync"
	"sync/atomic"
)

// managerSlot pairs a live ZitiManager with the cancel func for the context that
// drives its background monitors. Close() alone does not stop the monitors — the
// per-manager context does — so the slot must carry both.
type managerSlot struct {
	mgr    *ZitiManager
	cancel context.CancelFunc
}

// ZitiProvider holds the current *ZitiManager behind an atomic pointer so the
// admin panel can connect / reconnect / disconnect at runtime while the ~145
// call sites across the access package read it lock-free. nil (no slot, or a
// slot whose mgr is nil) preserves the existing "Ziti not configured" semantics
// that every call site already nil-checks.
//
// opMu serializes connect/disconnect operations (building a manager does network
// I/O and takes seconds) so two admins can't race two managers into existence.
// Reads via Get() never take opMu.
type ZitiProvider struct {
	v    atomic.Pointer[managerSlot]
	opMu sync.Mutex
}

// NewZitiProvider returns an empty (disconnected) provider.
func NewZitiProvider() *ZitiProvider { return &ZitiProvider{} }

// newZitiProviderWith returns a provider already holding mgr (nil → disconnected).
func newZitiProviderWith(mgr *ZitiManager) *ZitiProvider {
	p := NewZitiProvider()
	if mgr != nil {
		p.Store(mgr)
	}
	return p
}

// Get returns the live manager, or nil when disconnected. Lock-free.
func (p *ZitiProvider) Get() *ZitiManager {
	if p == nil {
		return nil
	}
	if s := p.v.Load(); s != nil {
		return s.mgr
	}
	return nil
}

// Lock/Unlock guard a connect/disconnect critical section.
func (p *ZitiProvider) Lock()   { p.opMu.Lock() }
func (p *ZitiProvider) Unlock() { p.opMu.Unlock() }

// Swap installs mgr (may be nil for disconnect) with its monitor-cancel, and
// tears the previous manager down: cancel its monitor context first (stops the
// monitor goroutines, which all honor ctx.Done()), then Close() (stops hosted
// listeners + closes the SDK context). Order matters — cancel before Close so a
// monitor isn't mid-flight touching a closed SDK context.
func (p *ZitiProvider) Swap(mgr *ZitiManager, cancel context.CancelFunc) {
	old := p.v.Swap(&managerSlot{mgr: mgr, cancel: cancel})
	if old != nil {
		if old.cancel != nil {
			old.cancel()
		}
		if old.mgr != nil {
			old.mgr.Close()
		}
	}
}

// Store installs mgr without tearing down any previous slot (boot/test path
// where there is nothing to close). Use Swap for runtime reconnects.
func (p *ZitiProvider) Store(mgr *ZitiManager) {
	p.v.Store(&managerSlot{mgr: mgr})
}
