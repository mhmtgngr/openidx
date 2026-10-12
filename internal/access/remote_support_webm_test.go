package access

import (
	"bytes"
	"encoding/binary"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// testIVFFrame is a frame to write into a test IVF: its IVF timestamp and
// payload.
type testIVFFrame struct {
	pts  uint64
	data []byte
}

func vp8Key(w, h uint16, fill byte, n int) []byte {
	f := make([]byte, 10+n)
	f[0] = 0x10 // bit 0 clear: a keyframe
	f[3], f[4], f[5] = 0x9d, 0x01, 0x2a
	binary.LittleEndian.PutUint16(f[6:8], w)
	binary.LittleEndian.PutUint16(f[8:10], h)
	for i := 10; i < len(f); i++ {
		f[i] = fill
	}
	return f
}

func vp8Inter(fill byte, n int) []byte {
	f := bytes.Repeat([]byte{fill}, n)
	f[0] = 0x01 // bit 0 set: an interframe
	return f
}

func buildIVF(header []byte, frames []testIVFFrame) []byte {
	var b bytes.Buffer
	b.Write(header)
	for _, f := range frames {
		var fh [12]byte
		binary.LittleEndian.PutUint32(fh[0:4], uint32(len(f.data)))
		binary.LittleEndian.PutUint64(fh[4:12], f.pts)
		b.Write(fh[:])
		b.Write(f.data)
	}
	return b.Bytes()
}

// ---- a minimal EBML reader, enough to read the muxer's output back ----

type ebmlElem struct {
	id      uint32
	payload []byte
	at      int // offset of the element's first byte in the buffer it was read from
}

func readID(t *testing.T, b []byte) (uint32, int) {
	t.Helper()
	l := 1
	for l <= 4 && b[0]&(0x80>>(l-1)) == 0 {
		l++
	}
	if l > 4 || len(b) < l {
		t.Fatalf("bad element id at % x", b[:min(len(b), 4)])
	}
	var id uint32
	for i := 0; i < l; i++ {
		id = id<<8 | uint32(b[i])
	}
	return id, l
}

func readSize(t *testing.T, b []byte) (uint64, int) {
	t.Helper()
	l := 1
	for l <= 8 && b[0]&(0x80>>(l-1)) == 0 {
		l++
	}
	if l > 8 || len(b) < l {
		t.Fatalf("bad size vint at % x", b[:min(len(b), 8)])
	}
	n := uint64(b[0] & (0xff >> l))
	for i := 1; i < l; i++ {
		n = n<<8 | uint64(b[i])
	}
	return n, l
}

func children(t *testing.T, b []byte) []ebmlElem {
	t.Helper()
	var out []ebmlElem
	for off := 0; off < len(b); {
		id, il := readID(t, b[off:])
		size, sl := readSize(t, b[off+il:])
		start := off + il + sl
		if start+int(size) > len(b) {
			t.Fatalf("element %x at %d claims %d bytes, only %d left", id, off, size, len(b)-start)
		}
		out = append(out, ebmlElem{id: id, payload: b[start : start+int(size)], at: off})
		off = start + int(size)
	}
	return out
}

func child(t *testing.T, b []byte, id uint32) []byte {
	t.Helper()
	for _, e := range children(t, b) {
		if e.id == id {
			return e.payload
		}
	}
	t.Fatalf("no element %x", id)
	return nil
}

func uintOf(b []byte) uint64 {
	var n uint64
	for _, c := range b {
		n = n<<8 | uint64(c)
	}
	return n
}

type readBlock struct {
	ms   uint64
	key  bool
	data []byte
}

func TestIVFRemuxesToAWebMThatReadsBack(t *testing.T) {
	key1 := vp8Key(640, 480, 0xaa, 300)
	key2 := vp8Key(640, 480, 0xbb, 200)
	frames := []testIVFFrame{
		{5000, key1},                // the first keyframe, five seconds into the session
		{5033, vp8Inter(0x11, 40)},  //
		{5066, vp8Inter(0x22, 50)},  //
		{45066, vp8Inter(0x33, 60)}, // 40s later and no keyframe: past a block's 16-bit offset
		{45100, key2},               //
	}
	ivf := buildIVF(ivfFileHeader(640, 480), frames)
	// A frame cut short at the end, as a recording still being written leaves.
	ivf = append(ivf, 0xff, 0x00, 0x00, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9)

	ix, err := scanIVF(bytes.NewReader(ivf))
	if err != nil {
		t.Fatal(err)
	}
	if len(ix.frames) != len(frames) || ix.width != 640 || ix.height != 480 {
		t.Fatalf("index = %d frames %dx%d, want %d frames 640x480", len(ix.frames), ix.width, ix.height, len(frames))
	}
	wantMS := []uint64{0, 33, 66, 40066, 40100}
	for i, f := range ix.frames {
		if f.ms != wantMS[i] || f.key != (i == 0 || i == 4) || f.size != uint32(len(frames[i].data)) {
			t.Fatalf("frame %d = %+v, want ms %d", i, f, wantMS[i])
		}
	}

	layout := newWebMLayout(ix)
	var out bytes.Buffer
	if err := layout.writeTo(&out, bytes.NewReader(ivf)); err != nil {
		t.Fatal(err)
	}
	if int64(out.Len()) != layout.size {
		t.Fatalf("wrote %d bytes, the layout (and the Content-Length) said %d", out.Len(), layout.size)
	}

	top := children(t, out.Bytes())
	if len(top) != 2 || top[0].id != ebmlHeaderID || top[1].id != mkvSegmentID {
		t.Fatalf("top level = %+v, want EBML header then Segment", top)
	}
	if dt := string(child(t, top[0].payload, ebmlDocTypeID)); dt != "webm" {
		t.Fatalf("doctype = %q", dt)
	}
	seg := top[1].payload
	segStart := len(out.Bytes()) - len(seg)

	info := child(t, seg, mkvInfoID)
	if s := uintOf(child(t, info, mkvTimecodeScaleID)); s != 1_000_000 {
		t.Fatalf("timecode scale = %d", s)
	}
	if d := math.Float64frombits(binary.BigEndian.Uint64(child(t, info, mkvDurationID))); d != 40100 {
		t.Fatalf("duration = %v ms, want 40100", d)
	}
	track := child(t, child(t, seg, mkvTracksID), mkvTrackEntryID)
	if c := string(child(t, track, mkvCodecID)); c != "V_VP8" {
		t.Fatalf("codec = %q", c)
	}
	video := child(t, track, mkvVideoID)
	if w, h := uintOf(child(t, video, mkvPixelWidthID)), uintOf(child(t, video, mkvPixelHeightID)); w != 640 || h != 480 {
		t.Fatalf("pixels = %dx%d", w, h)
	}

	var blocks []readBlock
	clusterAt := map[int]uint64{} // offset in the segment payload -> cluster timecode
	var order []uint32
	for _, e := range children(t, seg) {
		order = append(order, e.id)
		if e.id != mkvClusterID {
			continue
		}
		var tc uint64
		for _, ce := range children(t, e.payload) {
			switch ce.id {
			case mkvTimecodeID:
				tc = uintOf(ce.payload)
				clusterAt[e.at] = tc
			case mkvSimpleBlockID:
				p := ce.payload
				if p[0] != 0x81 {
					t.Fatalf("block track = %x, want track 1", p[0])
				}
				rel := int16(binary.BigEndian.Uint16(p[1:3]))
				blocks = append(blocks, readBlock{ms: uint64(int64(tc) + int64(rel)), key: p[3]&0x80 != 0, data: p[4:]})
			}
		}
	}
	if order[0] != mkvInfoID || order[1] != mkvTracksID || order[2] != mkvCuesID {
		t.Fatalf("segment order = %x, want Info, Tracks, Cues before the clusters", order)
	}
	if len(blocks) != len(frames) {
		t.Fatalf("read back %d blocks, want %d", len(blocks), len(frames))
	}
	for i, b := range blocks {
		if b.ms != wantMS[i] || b.key != ix.frames[i].key || !bytes.Equal(b.data, frames[i].data) {
			t.Fatalf("block %d = ms %d key %v %d bytes; want ms %d key %v and the frame's bytes unchanged",
				i, b.ms, b.key, len(b.data), wantMS[i], ix.frames[i].key)
		}
	}
	// Three clusters: the first keyframe, the frame past the 16-bit offset,
	// the second keyframe. Two of them start with a keyframe and are cued.
	if len(clusterAt) != 3 {
		t.Fatalf("clusters = %d, want 3", len(clusterAt))
	}
	cues := children(t, child(t, seg, mkvCuesID))
	if len(cues) != 2 {
		t.Fatalf("cue points = %d, want 2", len(cues))
	}
	wantCue := []uint64{0, 40100}
	for i, cp := range cues {
		ms := uintOf(child(t, cp.payload, mkvCueTimeID))
		pos := uintOf(child(t, child(t, cp.payload, mkvCueTrackPosID), mkvCueClusterPosID))
		tc, ok := clusterAt[int(pos)]
		if ms != wantCue[i] || !ok || tc != ms {
			t.Fatalf("cue %d = %d ms at %d (cluster there: %v, tc %d)", i, ms, pos, ok, tc)
		}
		if id, _ := readID(t, out.Bytes()[segStart+int(pos):]); id != mkvClusterID {
			t.Fatalf("cue %d points at element %x, not a cluster", i, id)
		}
	}
}

func TestIVFTimeBaseIsHonoured(t *testing.T) {
	hdr := ivfFileHeader(320, 240)
	binary.LittleEndian.PutUint32(hdr[16:20], 30) // 30 frames a second
	binary.LittleEndian.PutUint32(hdr[20:24], 1)
	ix, err := scanIVF(bytes.NewReader(buildIVF(hdr, []testIVFFrame{
		{0, vp8Key(320, 240, 1, 10)}, {1, vp8Inter(2, 10)}, {30, vp8Inter(3, 10)},
	})))
	if err != nil {
		t.Fatal(err)
	}
	if got := []uint64{ix.frames[0].ms, ix.frames[1].ms, ix.frames[2].ms}; got[0] != 0 || got[1] != 33 || got[2] != 1000 {
		t.Fatalf("ms = %v, want [0 33 1000]", got)
	}
}

func TestIVFScanRefusesWhatItCannotRemux(t *testing.T) {
	if _, err := scanIVF(bytes.NewReader([]byte("not an ivf file at all, really not one"))); err == nil {
		t.Fatal("a non-IVF stream was indexed")
	}
	if _, err := scanIVF(bytes.NewReader(ivfFileHeader(640, 480))); err != errIVFEmpty {
		t.Fatalf("a header with no frames = %v, want errIVFEmpty", err)
	}
	vp9 := ivfFileHeader(640, 480)
	copy(vp9[8:12], "VP90")
	if _, err := scanIVF(bytes.NewReader(buildIVF(vp9, []testIVFFrame{{0, vp8Key(640, 480, 1, 10)}}))); err == nil {
		t.Fatal("a VP9 IVF was indexed as VP8")
	}
}

// The download path serves the remux with an exact Content-Length, and a
// recording it cannot index is left to the caller to serve as stored.
func TestServeIVFAsWebM(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store, err := newFilesystemRecordingStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewRemoteSupportHandler(zap.NewNop(), nil, nil)
	h.SetRecordingStore(store)
	ivf := buildIVF(ivfFileHeader(64, 48), []testIVFFrame{{0, vp8Key(64, 48, 7, 20)}, {40, vp8Inter(8, 20)}})
	if _, err := store.Append("s-good", 0, bytes.NewReader(ivf)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append("s-bad", 0, bytes.NewReader([]byte("garbage that is not IVF, long enough to read"))); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if !h.serveIVFAsWebM(c, "s-good") {
		t.Fatal("a good IVF was not served as WebM")
	}
	if ct := w.Header().Get("Content-Type"); ct != "video/webm" {
		t.Fatalf("content type = %q", ct)
	}
	if cl := w.Header().Get("Content-Length"); cl == "" || cl != strconv.Itoa(w.Body.Len()) {
		t.Fatalf("Content-Length %q for a %d-byte body", cl, w.Body.Len())
	}
	if !bytes.HasPrefix(w.Body.Bytes(), []byte{0x1A, 0x45, 0xDF, 0xA3}) {
		t.Fatalf("body does not start with an EBML header: % x", w.Body.Bytes()[:4])
	}

	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if h.serveIVFAsWebM(c, "s-bad") || w.Body.Len() != 0 {
		t.Fatalf("an unreadable recording was answered (%d bytes) instead of being left to the original", w.Body.Len())
	}
}
