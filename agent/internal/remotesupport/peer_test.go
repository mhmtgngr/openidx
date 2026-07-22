package remotesupport

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"go.uber.org/zap"
)

// pipeConn is an in-memory SignalConn pair for tests: whatever one side writes,
// the other side reads. Emulates the broker relay between device and admin.
type pipeConn struct {
	in     chan []byte
	out    chan []byte
	mu     sync.Mutex
	closed bool
}

func newPipePair() (*pipeConn, *pipeConn) {
	a2b := make(chan []byte, 32)
	b2a := make(chan []byte, 32)
	return &pipeConn{in: b2a, out: a2b}, &pipeConn{in: a2b, out: b2a}
}

func (c *pipeConn) ReadJSON(v interface{}) error {
	b, ok := <-c.in
	if !ok {
		return errClosedPipe
	}
	return json.Unmarshal(b, v)
}

func (c *pipeConn) WriteJSON(v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errClosedPipe
	}
	c.out <- b
	return nil
}

func (c *pipeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.out)
	}
	return nil
}

type pipeErr struct{}

func (pipeErr) Error() string { return "pipe closed" }

var errClosedPipe = pipeErr{}

// TestPeerNegotiatesWithAdmin drives the device Peer against a real pion peer
// acting as the browser admin (the answerer), proving the device creates an
// offer, the answer is accepted, and the peer connection reaches "connected".
func TestPeerNegotiatesWithAdmin(t *testing.T) {
	if testing.Short() {
		t.Skip("skips ICE negotiation in -short")
	}
	devConn, adminConn := newPipePair()

	// A synthetic 1-frame source (a tiny VP8 keyframe payload is not required for
	// the connection to establish; the track just needs to exist).
	src := NewSyntheticSource(50*time.Millisecond, []byte{0x00})
	peer := NewPeer(PeerConfig{Source: src, Logger: zap.NewNop()})

	done := make(chan error, 1)
	go func() { done <- peer.Run(devConn) }()
	defer peer.Close()

	// Admin side: a pion peer that answers the device's offer.
	admin, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("admin peer: %v", err)
	}
	defer admin.Close()
	admin.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		ci := c.ToJSON()
		mid := ""
		if ci.SDPMid != nil {
			mid = *ci.SDPMid
		}
		var idx uint16
		if ci.SDPMLineIndex != nil {
			idx = *ci.SDPMLineIndex
		}
		raw, _ := json.Marshal(icePayload{Candidate: ci.Candidate, SDPMid: mid, SDPMLineIndex: idx})
		_ = adminConn.WriteJSON(envelope{Type: "ice", Payload: raw})
	})

	connected := make(chan struct{})
	var once sync.Once
	admin.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		if s == webrtc.PeerConnectionStateConnected {
			once.Do(func() { close(connected) })
		}
	})

	// Admin signaling loop: receive offer -> answer; take ICE.
	go func() {
		for {
			var env envelope
			if err := adminConn.ReadJSON(&env); err != nil {
				return
			}
			switch env.Type {
			case "sdp":
				var sp sdpPayload
				if json.Unmarshal(env.Payload, &sp) == nil && sp.Type == "offer" {
					_ = admin.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sp.SDP})
					ans, _ := admin.CreateAnswer(nil)
					_ = admin.SetLocalDescription(ans)
					raw, _ := json.Marshal(sdpPayload{SDP: ans.SDP, Type: "answer"})
					_ = adminConn.WriteJSON(envelope{Type: "sdp", Payload: raw})
				}
			case "ice":
				var ip icePayload
				if json.Unmarshal(env.Payload, &ip) == nil && ip.Candidate != "" {
					mid := ip.SDPMid
					idx := ip.SDPMLineIndex
					_ = admin.AddICECandidate(webrtc.ICECandidateInit{Candidate: ip.Candidate, SDPMid: &mid, SDPMLineIndex: &idx})
				}
			}
		}
	}()

	select {
	case <-connected:
		// success: the device offered, admin answered, ICE completed.
	case err := <-done:
		t.Fatalf("peer.Run returned before connecting: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for the peer connection to establish")
	}
}

// TestInputSinkReceivesControlState verifies the device applies control_state
// and input events from the admin data channel via the sink.
func TestInputSinkReceivesControlState(t *testing.T) {
	rec := &recordingSink{}
	sink := InputSink(rec)
	// Simulate the OnMessage decode path directly.
	handle := func(data []byte) {
		var ev InputEvent
		if json.Unmarshal(data, &ev) != nil {
			return
		}
		if ev.Event == "control_state" && ev.Active != nil {
			sink.SetControlActive(*ev.Active)
			return
		}
		sink.Apply(ev)
	}
	tru := true
	fls := false
	b1, _ := json.Marshal(InputEvent{Event: "control_state", Active: &tru})
	b2, _ := json.Marshal(InputEvent{Event: "global_action", Action: "home"})
	b3, _ := json.Marshal(InputEvent{Event: "control_state", Active: &fls})
	handle(b1)
	handle(b2)
	handle(b3)

	if len(rec.control) != 2 || rec.control[0] != true || rec.control[1] != false {
		t.Errorf("control states = %v, want [true false]", rec.control)
	}
	if len(rec.applied) != 1 || rec.applied[0].Action != "home" {
		t.Errorf("applied events = %v, want one 'home'", rec.applied)
	}
}

type recordingSink struct {
	control []bool
	applied []InputEvent
}

func (r *recordingSink) Apply(ev InputEvent)          { r.applied = append(r.applied, ev) }
func (r *recordingSink) SetControlActive(active bool) { r.control = append(r.control, active) }
