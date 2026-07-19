//go:build screenshare

// Real screen capture + VP8 encode. Compiled only with `-tags screenshare`
// (needs CGO + libvpx). The packaged Windows build sets this tag; the default
// cross-platform build uses capture_stub.go so the agent stays pure Go.
package remotesupport

import (
	"fmt"
	"image"
	"time"

	"github.com/kbinani/screenshot"
	"github.com/pion/mediadevices/pkg/codec"
	"github.com/pion/mediadevices/pkg/codec/vpx"
	"github.com/pion/mediadevices/pkg/io/video"
	"github.com/pion/mediadevices/pkg/prop"
)

// NewScreenSource captures the primary display at fps and VP8-encodes frames.
func NewScreenSource(fps int) (VideoSource, error) {
	if fps <= 0 {
		fps = 10
	}
	if screenshot.NumActiveDisplays() == 0 {
		return nil, fmt.Errorf("no active display to capture")
	}
	bounds := screenshot.GetDisplayBounds(0)
	w, h := bounds.Dx(), bounds.Dy()

	// A video.Reader that grabs the primary display each Read.
	reader := video.ReaderFunc(func() (image.Image, func(), error) {
		img, err := screenshot.CaptureRect(bounds)
		if err != nil {
			return nil, func() {}, err
		}
		return img, func() {}, nil
	})

	params, err := vpx.NewVP8Params()
	if err != nil {
		return nil, fmt.Errorf("vp8 params: %w", err)
	}
	params.BitRate = 1_500_000 // ~1.5 Mbps; tune for the link
	enc, err := params.BuildVideoEncoder(reader, prop.Media{
		Video: prop.Video{Width: w, Height: h, FrameRate: float32(fps)},
	})
	if err != nil {
		return nil, fmt.Errorf("build vp8 encoder: %w", err)
	}

	return &realVideoSource{
		enc:      enc,
		interval: time.Second / time.Duration(fps),
	}, nil
}

type realVideoSource struct {
	enc      codec.ReadCloser
	interval time.Duration
}

func (s *realVideoSource) NextFrame() ([]byte, error) {
	data, release, err := s.enc.Read()
	if err != nil {
		return nil, err
	}
	// Copy before releasing the encoder's buffer back.
	out := make([]byte, len(data))
	copy(out, data)
	release()
	return out, nil
}

func (s *realVideoSource) FrameInterval() time.Duration { return s.interval }

func (s *realVideoSource) Close() {
	if s.enc != nil {
		_ = s.enc.Close()
	}
}
