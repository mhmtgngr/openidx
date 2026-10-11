package access

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// vp8Keyframe is a minimal VP8 keyframe header for w x h: the frame tag (bit
// 0 clear), the start code and the 14-bit sizes, then a payload byte.
func vp8Keyframe(w, h uint16) []byte {
	f := []byte{0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a, 0, 0, 0, 0, 0xAB}
	binary.LittleEndian.PutUint16(f[6:8], w)
	binary.LittleEndian.PutUint16(f[8:10], h)
	return f
}

func TestTheBrokerReadsAKeyframesSize(t *testing.T) {
	w, h, ok := vp8KeyframeSize(vp8Keyframe(1920, 1080))
	if !ok || w != 1920 || h != 1080 {
		t.Fatalf("keyframe size = %dx%d ok=%v, want 1920x1080", w, h, ok)
	}
	inter := vp8Keyframe(1920, 1080)
	inter[0] |= 0x01
	if _, _, ok := vp8KeyframeSize(inter); ok {
		t.Error("an interframe is not a keyframe")
	}
	if _, _, ok := vp8KeyframeSize([]byte{0x00, 0x01}); ok {
		t.Error("a truncated frame is not a keyframe")
	}
}

// The recording is a well-formed IVF file: nothing before the first
// keyframe, then one file header carrying that keyframe's size, then each
// frame with its own 12-byte header and the VP8 bytes as the relay carried
// them (the relay's flags byte stripped). A recorder resumed with bytes
// already stored writes no second file header.
func TestTheBrokerWritesTheRelayFramesAsIVF(t *testing.T) {
	r := &ivfRecorder{start: time.Now()}
	var buf bytes.Buffer
	inter := append([]byte{0x00}, 0x11, 0x00, 0x00, 0xCD)
	r.add(&buf, inter)
	if buf.Len() != 0 {
		t.Fatalf("frames before the first keyframe should be skipped, wrote %d bytes", buf.Len())
	}
	key := append([]byte{0x01}, vp8Keyframe(640, 480)...)
	r.add(&buf, key)
	r.add(&buf, inter)
	b := buf.Bytes()
	if string(b[0:4]) != "DKIF" || string(b[8:12]) != "VP80" {
		t.Fatalf("file header = %q", b[0:12])
	}
	if binary.LittleEndian.Uint16(b[6:8]) != 32 || binary.LittleEndian.Uint16(b[12:14]) != 640 || binary.LittleEndian.Uint16(b[14:16]) != 480 {
		t.Fatalf("file header fields = %x", b[0:32])
	}
	if binary.LittleEndian.Uint32(b[16:20]) != 1000 || binary.LittleEndian.Uint32(b[20:24]) != 1 {
		t.Fatal("the timebase should be milliseconds")
	}
	off := 32
	for i, want := range [][]byte{key[1:], inter[1:]} {
		size := int(binary.LittleEndian.Uint32(b[off : off+4]))
		if size != len(want) {
			t.Fatalf("frame %d size = %d, want %d", i, size, len(want))
		}
		if got := b[off+12 : off+12+size]; !bytes.Equal(got, want) {
			t.Fatalf("frame %d bytes = %x, want %x", i, got, want)
		}
		off += 12 + size
	}
	if off != len(b) {
		t.Fatalf("%d trailing bytes", len(b)-off)
	}

	resumed := &ivfRecorder{start: time.Now(), headed: true}
	var more bytes.Buffer
	resumed.add(&more, inter)
	if more.Len() != 12+len(inter)-1 || bytes.HasPrefix(more.Bytes(), []byte("DKIF")) {
		t.Fatalf("a resumed recording should append frames only, wrote %x", more.Bytes())
	}
}
