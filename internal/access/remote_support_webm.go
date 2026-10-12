package access

// IVF -> WebM, so a vendor session's recording plays in a browser.
//
// The broker records a vendor session as IVF (ivfRecorder): the VP8 frames the
// relay carried, each behind a 12-byte header. IVF is the format a recorder can
// append to forever without going back to fix up a size, which is why the
// stored original stays IVF; but no browser plays it. WebM (Matroska with a VP8
// track) carries the same frames, so serving one is a remux, not a re-encode:
// every frame's bytes go out exactly as recorded, wrapped in SimpleBlocks.
//
// It is done in two passes over the stored IVF, because the stores hand out a
// stream, not a seekable file. The first (scanIVF) reads only the frame headers
// and each frame's first byte (the VP8 keyframe bit) into an index; from that,
// newWebMLayout knows every element's size before writing a byte, so the
// response carries a Content-Length, and the Cues -- which a player needs to
// seek -- go before the clusters with their positions already known. The second
// (webmLayout.writeTo) streams the frames through.
//
// The output is deliberately the smallest WebM a player accepts: EBML header,
// Segment { Info (with Duration), Tracks (one VP8 video track), Cues, Clusters }.
// A cluster starts at every keyframe, and wherever the next frame would be
// beyond the 16-bit block timecode, so every cue points at a cluster that
// starts with a keyframe.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// ivfFrame is one frame of an IVF file, as the index sees it: its size, its
// time in milliseconds from the first frame, and whether it is a keyframe.
type ivfFrame struct {
	size uint32
	ms   uint64
	key  bool
}

// ivfIndex is what the first pass learns about an IVF file.
type ivfIndex struct {
	headerLen     int // bytes of file header before the first frame
	width, height uint16
	frames        []ivfFrame
}

var errIVFEmpty = errors.New("ivf: the recording holds no frames")

// maxIVFFrame bounds a frame header's claimed size, so a corrupt header cannot
// make a reader allocate or skip gigabytes before noticing.
const maxIVFFrame = 64 << 20

// scanIVF reads an IVF stream's file header and frame headers. Timestamps are
// converted to milliseconds with the header's time base, rebased so the first
// frame is at 0 (the broker's timeline starts at the session's start, and the
// first keyframe can come seconds later), and held non-decreasing. A frame cut
// short at the end -- a recording still being written, or a crash mid-flush --
// ends the index rather than failing it: everything before it is good.
func scanIVF(r io.Reader) (*ivfIndex, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var hdr [32]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, fmt.Errorf("ivf: short file header: %w", err)
	}
	if string(hdr[0:4]) != "DKIF" {
		return nil, errors.New("ivf: not an IVF file")
	}
	if string(hdr[8:12]) != "VP80" {
		return nil, fmt.Errorf("ivf: codec %q is not VP8", hdr[8:12])
	}
	ix := &ivfIndex{
		headerLen: int(binary.LittleEndian.Uint16(hdr[6:8])),
		width:     binary.LittleEndian.Uint16(hdr[12:14]),
		height:    binary.LittleEndian.Uint16(hdr[14:16]),
	}
	rate := uint64(binary.LittleEndian.Uint32(hdr[16:20]))  // time base denominator
	scale := uint64(binary.LittleEndian.Uint32(hdr[20:24])) // time base numerator
	if rate == 0 || scale == 0 {
		return nil, errors.New("ivf: zero time base")
	}
	if ix.headerLen < 32 {
		return nil, errors.New("ivf: header length below 32")
	}
	if _, err := br.Discard(ix.headerLen - 32); err != nil {
		return nil, fmt.Errorf("ivf: short file header: %w", err)
	}
	var first, last uint64
	for {
		var fh [12]byte
		if _, err := io.ReadFull(br, fh[:]); err != nil {
			break // end of stream, or a header cut short
		}
		size := binary.LittleEndian.Uint32(fh[0:4])
		if size == 0 || size > maxIVFFrame {
			break
		}
		lead, err := br.ReadByte()
		if err != nil {
			break
		}
		if n, _ := br.Discard(int(size) - 1); n != int(size)-1 {
			break
		}
		ms := binary.LittleEndian.Uint64(fh[4:12]) * scale * 1000 / rate
		if len(ix.frames) == 0 {
			first = ms
		}
		ms -= min(ms, first)
		ms = max(ms, last)
		last = ms
		ix.frames = append(ix.frames, ivfFrame{size: size, ms: ms, key: lead&0x01 == 0})
	}
	if len(ix.frames) == 0 {
		return nil, errIVFEmpty
	}
	return ix, nil
}

// ---- EBML ----

// Matroska element IDs used here. An ID carries its own length marker, so it
// is written as its bytes.
const (
	ebmlHeaderID         = 0x1A45DFA3
	ebmlVersionID        = 0x4286
	ebmlReadVersionID    = 0x42F7
	ebmlMaxIDLengthID    = 0x42F2
	ebmlMaxSizeLengthID  = 0x42F3
	ebmlDocTypeID        = 0x4282
	ebmlDocTypeVerID     = 0x4287
	ebmlDocTypeReadVerID = 0x4285

	mkvSegmentID       = 0x18538067
	mkvInfoID          = 0x1549A966
	mkvTimecodeScaleID = 0x2AD7B1
	mkvMuxingAppID     = 0x4D80
	mkvWritingAppID    = 0x5741
	mkvDurationID      = 0x4489
	mkvTracksID        = 0x1654AE6B
	mkvTrackEntryID    = 0xAE
	mkvTrackNumberID   = 0xD7
	mkvTrackUIDID      = 0x73C5
	mkvTrackTypeID     = 0x83
	mkvFlagLacingID    = 0x9C
	mkvCodecID         = 0x86
	mkvVideoID         = 0xE0
	mkvPixelWidthID    = 0xB0
	mkvPixelHeightID   = 0xBA
	mkvCuesID          = 0x1C53BB6B
	mkvCuePointID      = 0xBB
	mkvCueTimeID       = 0xB3
	mkvCueTrackPosID   = 0xB7
	mkvCueTrackID      = 0xF7
	mkvCueClusterPosID = 0xF1
	mkvClusterID       = 0x1F43B675
	mkvTimecodeID      = 0xE7
	mkvSimpleBlockID   = 0xA3
)

// webmTrack is the one track's number; its SimpleBlocks lead with it as a
// one-byte vint.
const webmTrack = 1

func ebmlIDLen(id uint32) int {
	switch {
	case id >= 1<<24:
		return 4
	case id >= 1<<16:
		return 3
	case id >= 1<<8:
		return 2
	}
	return 1
}

func appendEBMLID(b []byte, id uint32) []byte {
	for i := ebmlIDLen(id) - 1; i >= 0; i-- {
		b = append(b, byte(id>>(8*i)))
	}
	return b
}

// vintLen is the bytes a data size n takes. The all-ones value of each length
// means "unknown size", so it is skipped.
func vintLen(n uint64) int {
	for l := 1; l < 8; l++ {
		if n < 1<<(7*l)-1 {
			return l
		}
	}
	return 8
}

func appendVint(b []byte, n uint64) []byte {
	l := vintLen(n)
	n |= 1 << (7 * l)
	for i := l - 1; i >= 0; i-- {
		b = append(b, byte(n>>(8*i)))
	}
	return b
}

// elemLen is the bytes an element with a payload of n bytes takes.
func elemLen(id uint32, n uint64) uint64 {
	return uint64(ebmlIDLen(id)+vintLen(n)) + n
}

func appendElem(b []byte, id uint32, payload []byte) []byte {
	b = appendEBMLID(b, id)
	b = appendVint(b, uint64(len(payload)))
	return append(b, payload...)
}

// appendUintN writes an unsigned element in exactly width bytes. Fixed widths
// keep the Cues' size independent of the positions they hold.
func appendUintN(b []byte, id uint32, v uint64, width int) []byte {
	var p [8]byte
	binary.BigEndian.PutUint64(p[:], v)
	return appendElem(b, id, p[8-width:])
}

func appendUint(b []byte, id uint32, v uint64) []byte {
	width := 1
	for width < 8 && v>>(8*width) != 0 {
		width++
	}
	return appendUintN(b, id, v, width)
}

func appendFloat(b []byte, id uint32, f float64) []byte {
	var p [8]byte
	binary.BigEndian.PutUint64(p[:], math.Float64bits(f))
	return appendElem(b, id, p[:])
}

// ---- Layout ----

// webmCluster is a run of frames [first, end) under one cluster timecode.
type webmCluster struct {
	first, end int
	timecode   uint64
	payload    uint64
}

// webmLayout is the WebM for an index, with every size known.
type webmLayout struct {
	ix       *ivfIndex
	head     []byte // EBML header, Segment header, Info, Tracks and Cues
	clusters []webmCluster
	size     int64
}

// maxBlockOffset is the furthest a block's timecode may sit past its
// cluster's: block timecodes are signed 16-bit milliseconds.
const maxBlockOffset = math.MaxInt16

func simpleBlockLen(frame uint32) uint64 {
	return elemLen(mkvSimpleBlockID, 4+uint64(frame)) // track vint, int16 timecode, flags
}

// cuePointLen is the size of one CuePoint as appendCuePoint writes it.
var cuePointLen = uint64(len(appendCuePoint(nil, 0, 0)))

func appendCuePoint(b []byte, ms, clusterPos uint64) []byte {
	var pos []byte
	pos = appendUint(pos, mkvCueTrackID, webmTrack)
	pos = appendUintN(pos, mkvCueClusterPosID, clusterPos, 8)
	var cp []byte
	cp = appendUintN(cp, mkvCueTimeID, ms, 8)
	cp = appendElem(cp, mkvCueTrackPosID, pos)
	return appendElem(b, mkvCuePointID, cp)
}

func newWebMLayout(ix *ivfIndex) *webmLayout {
	l := &webmLayout{ix: ix}
	for i, f := range ix.frames {
		n := len(l.clusters)
		if n == 0 || f.key || f.ms-l.clusters[n-1].timecode > maxBlockOffset {
			l.clusters = append(l.clusters, webmCluster{first: i, timecode: f.ms})
			n++
		}
		c := &l.clusters[n-1]
		c.end = i + 1
		c.payload += simpleBlockLen(f.size)
	}
	for i := range l.clusters {
		c := &l.clusters[i]
		c.payload += uint64(len(appendUint(nil, mkvTimecodeID, c.timecode)))
	}

	var ebml []byte
	ebml = appendUint(ebml, ebmlVersionID, 1)
	ebml = appendUint(ebml, ebmlReadVersionID, 1)
	ebml = appendUint(ebml, ebmlMaxIDLengthID, 4)
	ebml = appendUint(ebml, ebmlMaxSizeLengthID, 8)
	ebml = appendElem(ebml, ebmlDocTypeID, []byte("webm"))
	ebml = appendUint(ebml, ebmlDocTypeVerID, 2)
	ebml = appendUint(ebml, ebmlDocTypeReadVerID, 2)

	last := ix.frames[len(ix.frames)-1].ms
	var info []byte
	info = appendUint(info, mkvTimecodeScaleID, 1_000_000) // block times in milliseconds
	info = appendElem(info, mkvMuxingAppID, []byte("openidx"))
	info = appendElem(info, mkvWritingAppID, []byte("openidx"))
	info = appendFloat(info, mkvDurationID, float64(max(last, 1)))

	var video []byte
	video = appendUint(video, mkvPixelWidthID, uint64(ix.width))
	video = appendUint(video, mkvPixelHeightID, uint64(ix.height))
	var track []byte
	track = appendUint(track, mkvTrackNumberID, webmTrack)
	track = appendUint(track, mkvTrackUIDID, 1)
	track = appendUint(track, mkvTrackTypeID, 1) // video
	track = appendUint(track, mkvFlagLacingID, 0)
	track = appendElem(track, mkvCodecID, []byte("V_VP8"))
	track = appendElem(track, mkvVideoID, video)
	var tracks []byte
	tracks = appendElem(tracks, mkvTrackEntryID, track)

	infoElem := appendElem(nil, mkvInfoID, info)
	tracksElem := appendElem(nil, mkvTracksID, tracks)

	cued := 0
	for _, c := range l.clusters {
		if ix.frames[c.first].key {
			cued++
		}
	}
	var cuesLen uint64
	if cued > 0 {
		cuesLen = elemLen(mkvCuesID, uint64(cued)*cuePointLen)
	}
	// Cluster positions are relative to the start of the Segment's payload.
	pos := uint64(len(infoElem)+len(tracksElem)) + cuesLen
	var cues []byte
	var clustersLen uint64
	for _, c := range l.clusters {
		if ix.frames[c.first].key {
			cues = appendCuePoint(cues, c.timecode, pos+clustersLen)
		}
		clustersLen += elemLen(mkvClusterID, c.payload)
	}

	segPayload := pos + clustersLen
	l.head = appendElem(nil, ebmlHeaderID, ebml)
	l.head = appendEBMLID(l.head, mkvSegmentID)
	l.head = appendVint(l.head, segPayload)
	l.head = append(l.head, infoElem...)
	l.head = append(l.head, tracksElem...)
	if cued > 0 {
		l.head = appendElem(l.head, mkvCuesID, cues)
	}
	l.size = int64(len(l.head)) + int64(clustersLen)
	return l
}

// writeTo writes the WebM to w, reading the frames from ivf: the same IVF the
// index was made from, from its start. Only the indexed frames are written,
// so a recording that grew between the two passes is cut where the index
// ends, and a frame whose size no longer matches the index fails the write
// rather than producing a file whose sizes lie.
func (l *webmLayout) writeTo(w io.Writer, ivf io.Reader) error {
	br := bufio.NewReaderSize(ivf, 64<<10)
	if _, err := br.Discard(l.ix.headerLen); err != nil {
		return fmt.Errorf("ivf: short file header: %w", err)
	}
	bw := bufio.NewWriterSize(w, 64<<10)
	if _, err := bw.Write(l.head); err != nil {
		return err
	}
	var hdr []byte
	for _, c := range l.clusters {
		hdr = appendEBMLID(hdr[:0], mkvClusterID)
		hdr = appendVint(hdr, c.payload)
		hdr = appendUint(hdr, mkvTimecodeID, c.timecode)
		if _, err := bw.Write(hdr); err != nil {
			return err
		}
		for i := c.first; i < c.end; i++ {
			f := l.ix.frames[i]
			var fh [12]byte
			if _, err := io.ReadFull(br, fh[:]); err != nil {
				return fmt.Errorf("ivf: frame %d header: %w", i, err)
			}
			if got := binary.LittleEndian.Uint32(fh[0:4]); got != f.size {
				return fmt.Errorf("ivf: frame %d is %d bytes, the index says %d", i, got, f.size)
			}
			flags := byte(0)
			if f.key {
				flags = 0x80
			}
			hdr = appendEBMLID(hdr[:0], mkvSimpleBlockID)
			hdr = appendVint(hdr, 4+uint64(f.size))
			hdr = append(hdr, 0x80|webmTrack, 0, 0, flags)
			binary.BigEndian.PutUint16(hdr[len(hdr)-3:], uint16(int16(f.ms-c.timecode)))
			if _, err := bw.Write(hdr); err != nil {
				return err
			}
			if _, err := io.CopyN(bw, br, int64(f.size)); err != nil {
				return fmt.Errorf("ivf: frame %d: %w", i, err)
			}
		}
	}
	return bw.Flush()
}
