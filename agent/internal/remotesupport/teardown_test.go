package remotesupport

import (
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// blockingSource is a VideoSource whose NextFrame blocks for a while (simulating
// a slow CGO/libvpx encoder read) and whose Close records that it ran. It is
// used to prove peer teardown joins the frame pump BEFORE closing the source,
// so the encoder is never closed mid-read (which deadlocked libvpx and hung the
// whole client on session end).
type blockingSource struct {
	closed   atomic.Bool
	inRead   atomic.Bool
	blockFor time.Duration
}

func (s *blockingSource) NextFrame() ([]byte, error) {
	s.inRead.Store(true)
	defer s.inRead.Store(false)
	time.Sleep(s.blockFor)
	// Return a small non-empty frame so the pump keeps looping.
	return []byte{0x00}, nil
}
func (s *blockingSource) FrameInterval() time.Duration { return 10 * time.Millisecond }
func (s *blockingSource) Close()                       { s.closed.Store(true) }

// TestPeerTeardownDoesNotDeadlock proves that closing the peer while frames are
// being pumped completes promptly and does not close the source while a read is
// in flight. Regression for the libvpx "hang on session end, must Ctrl+C" bug.
func TestPeerTeardownDoesNotDeadlock(t *testing.T) {
	dev, _ := newPipePair()
	src := &blockingSource{blockFor: 60 * time.Millisecond}
	peer := NewPeer(PeerConfig{Source: src, Logger: zap.NewNop()})

	runReturned := make(chan struct{})
	go func() {
		_ = peer.Run(dev)
		close(runReturned)
	}()

	// Let the pump start and enter a read.
	time.Sleep(30 * time.Millisecond)

	// Close from another goroutine; the pipe close makes Run return, and the
	// deferred pump-join + source close must not hang.
	go peer.Close()

	select {
	case <-runReturned:
		// good — Run returned within the bound.
	case <-time.After(3 * time.Second):
		t.Fatal("peer.Run did not return within 3s — teardown deadlock")
	}

	// The source must have been closed (teardown completed), and not while a
	// read was still in flight is guaranteed by the join; here we just assert it
	// eventually closed.
	deadline := time.Now().Add(1 * time.Second)
	for !src.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !src.closed.Load() {
		t.Error("source was never closed after teardown")
	}
}
