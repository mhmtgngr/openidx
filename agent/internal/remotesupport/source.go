package remotesupport

import (
	"sync"
	"time"
)

// VideoSource produces encoded VP8 frames. Implementations:
//   - realVideoSource (capture_screenshare.go, build tag `screenshare`, CGO):
//     captures the primary display and VP8-encodes each frame.
//   - stubVideoSource (capture_stub.go, default): returns no frames, so the
//     agent builds and negotiates everywhere without a capture stack.
//   - SyntheticSource (below): emits pre-encoded frames for tests.
type VideoSource interface {
	// NextFrame returns one encoded VP8 frame (a full media sample). An empty
	// frame or error is skipped by the pump.
	NextFrame() ([]byte, error)
	// FrameInterval is the pacing between frames (e.g. 100ms for 10fps).
	FrameInterval() time.Duration
	// Close releases capture/encoder resources.
	Close()
}

// SyntheticSource is a deterministic VideoSource for tests: it hands back the
// frames it was given, in order, then repeats the last one. No OS or codec deps.
type SyntheticSource struct {
	frames   [][]byte
	interval time.Duration
	mu       sync.Mutex
	idx      int
}

// NewSyntheticSource builds a test source from a fixed set of frames.
func NewSyntheticSource(interval time.Duration, frames ...[]byte) *SyntheticSource {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	return &SyntheticSource{frames: frames, interval: interval}
}

func (s *SyntheticSource) NextFrame() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.frames) == 0 {
		return nil, nil
	}
	f := s.frames[s.idx]
	if s.idx < len(s.frames)-1 {
		s.idx++
	}
	return f, nil
}

func (s *SyntheticSource) FrameInterval() time.Duration { return s.interval }
func (s *SyntheticSource) Close()                       {}
