package remotesupport

import (
	"encoding/json"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RelayConn is the minimal transport the relay peer needs: a WebSocket that can
// send binary video frames and text input, and read text messages. The agent's
// wsSignalConn is adapted to this.
type RelayConn interface {
	WriteBinary(b []byte) error
	WriteText(b []byte) error
	ReadText() ([]byte, error)
	Close() error
}

// RelayConfig configures a server-relayed media peer.
type RelayConfig struct {
	Source VideoSource
	Input  InputSink
	Logger *zap.Logger
}

// RelayPeer streams the screen to the admin via the broker instead of a WebRTC
// peer connection: VP8 frames go out as binary WebSocket messages (1-byte
// header: bit0 = keyframe), and admin input arrives as text JSON on the same
// socket. No STUN/ICE/P2P — all media transits the broker, so the device leg
// can ride the Ziti overlay end to end. Mirrors the WebRTC Peer's input +
// control_state + keyframe-on-connect/PLI semantics.
type RelayPeer struct {
	cfg    RelayConfig
	logger *zap.Logger

	mu     sync.Mutex
	closed bool
}

// NewRelayPeer builds a relay peer.
func NewRelayPeer(cfg RelayConfig) *RelayPeer {
	lg := cfg.Logger
	if lg == nil {
		lg = zap.NewNop()
	}
	return &RelayPeer{cfg: cfg, logger: lg}
}

// relay frame header bits.
const relayFlagKeyFrame = 0x01

// Run pumps frames to the admin over conn and applies inbound input until the
// connection closes or an error occurs. Blocks for the session's lifetime.
func (p *RelayPeer) Run(conn RelayConn) error {
	// Force a keyframe up front so the admin paints immediately (like the
	// WebRTC path's keyframe-on-connect). Best effort.
	p.forceKeyFrame()

	stop := make(chan struct{})
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		p.pump(conn, stop)
	}()

	// Read loop: admin input + control_state + keyframe requests (text JSON).
	err := p.readLoop(conn)

	close(stop)
	// Bound the pump join so a wedged encoder read can't hang teardown (mirrors
	// the WebRTC peer's libvpx-safe teardown).
	select {
	case <-pumpDone:
	case <-time.After(2 * time.Second):
		p.logger.Warn("relay: frame pump did not stop in time")
	}
	return err
}

// pump reads encoded VP8 frames and writes them as binary WS messages.
func (p *RelayPeer) pump(conn RelayConn, stop <-chan struct{}) {
	src := p.cfg.Source
	interval := src.FrameInterval()
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			frame, err := src.NextFrame()
			if err != nil || len(frame) == 0 {
				continue
			}
			// Prepend a 1-byte header carrying the keyframe flag so the browser
			// decoder can wait for / recover with a keyframe.
			hdr := byte(0)
			if isVP8KeyFrame(frame) {
				hdr = relayFlagKeyFrame
			}
			msg := make([]byte, 0, len(frame)+1)
			msg = append(msg, hdr)
			msg = append(msg, frame...)
			if werr := conn.WriteBinary(msg); werr != nil {
				p.logger.Info("relay: frame write failed; ending", zap.Error(werr))
				return
			}
		}
	}
}

// readLoop applies inbound admin messages.
func (p *RelayPeer) readLoop(conn RelayConn) error {
	sink := p.cfg.Input
	for {
		data, err := conn.ReadText()
		if err != nil {
			return err
		}
		var ev InputEvent
		if json.Unmarshal(data, &ev) != nil {
			continue
		}
		switch {
		case ev.Event == "control_state" && ev.Active != nil:
			if sink != nil {
				sink.SetControlActive(*ev.Active)
			}
		case ev.Event == "request_keyframe":
			p.forceKeyFrame()
		default:
			if sink != nil {
				sink.Apply(ev)
			}
		}
	}
}

// forceKeyFrame asks the encoder to emit a keyframe next (if it supports it).
func (p *RelayPeer) forceKeyFrame() {
	if kf, ok := p.cfg.Source.(interface{ ForceKeyFrame() }); ok {
		kf.ForceKeyFrame()
	}
}

// Close releases the source.
func (p *RelayPeer) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	if p.cfg.Source != nil {
		p.cfg.Source.Close()
	}
}

// isVP8KeyFrame reports whether a raw VP8 frame is a keyframe. The VP8 payload
// header's first byte bit0 (P) is 0 for a keyframe (RFC 6386 §9.1).
func isVP8KeyFrame(frame []byte) bool {
	if len(frame) == 0 {
		return false
	}
	return frame[0]&0x01 == 0
}
