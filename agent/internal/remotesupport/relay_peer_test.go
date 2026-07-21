package remotesupport

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// fakeRelayConn is an in-memory RelayConn: it captures binary writes (video) and
// lets the test feed text (input) to the read loop.
type fakeRelayConn struct {
	mu      sync.Mutex
	binary  [][]byte
	textIn  chan []byte
	closed  bool
	closeCh chan struct{}
}

func newFakeRelayConn() *fakeRelayConn {
	return &fakeRelayConn{textIn: make(chan []byte, 8), closeCh: make(chan struct{})}
}
func (c *fakeRelayConn) WriteBinary(b []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]byte, len(b))
	copy(cp, b)
	c.binary = append(c.binary, cp)
	return nil
}
func (c *fakeRelayConn) WriteText([]byte) error { return nil }
func (c *fakeRelayConn) ReadText() ([]byte, error) {
	select {
	case t := <-c.textIn:
		return t, nil
	case <-c.closeCh:
		return nil, errClosed
	}
}
func (c *fakeRelayConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.closeCh)
	}
	return nil
}
func (c *fakeRelayConn) frameCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.binary)
}

type errString string

func (e errString) Error() string { return string(e) }

const errClosed = errString("closed")

// countingSink records Apply + control_state.
type countingSink struct {
	mu       sync.Mutex
	applied  int
	controls []bool
}

func (s *countingSink) Apply(InputEvent) { s.mu.Lock(); s.applied++; s.mu.Unlock() }
func (s *countingSink) SetControlActive(a bool) {
	s.mu.Lock()
	s.controls = append(s.controls, a)
	s.mu.Unlock()
}

// TestRelayPeerStreamsAndAppliesInput proves the relay peer writes VP8 frames as
// binary messages and applies inbound input JSON (control_state + events).
func TestRelayPeerStreamsAndAppliesInput(t *testing.T) {
	conn := newFakeRelayConn()
	// A synthetic source yielding a keyframe-looking VP8 byte (bit0=0).
	src := NewSyntheticSource(10*time.Millisecond, []byte{0x00, 0xAA})
	sink := &countingSink{}
	peer := NewRelayPeer(RelayConfig{Source: src, Input: sink, Logger: zap.NewNop()})

	done := make(chan error, 1)
	go func() { done <- peer.Run(conn) }()

	// Feed control_state:true then a tap; give the pump time to emit frames.
	conn.textIn <- mustJSON(InputEvent{Event: "control_state", Active: boolPtrT(true)})
	conn.textIn <- mustJSON(InputEvent{Event: "tap", X: 100, Y: 200})
	time.Sleep(80 * time.Millisecond)

	if conn.frameCount() == 0 {
		t.Error("relay peer wrote no video frames")
	}
	// First byte of each frame is the header; the keyframe flag must be set for
	// our bit0=0 payload.
	conn.mu.Lock()
	if len(conn.binary) > 0 && conn.binary[0][0]&relayFlagKeyFrame == 0 {
		t.Error("expected keyframe flag on the keyframe payload")
	}
	conn.mu.Unlock()

	sink.mu.Lock()
	gotControl := len(sink.controls) > 0 && sink.controls[0]
	gotApply := sink.applied > 0
	sink.mu.Unlock()
	if !gotControl {
		t.Error("control_state:true was not applied to the sink")
	}
	if !gotApply {
		t.Error("tap input was not applied to the sink")
	}

	conn.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay peer did not stop after conn close")
	}
	peer.Close()
}

func mustJSON(v interface{}) []byte { b, _ := json.Marshal(v); return b }
func boolPtrT(b bool) *bool         { return &b }
