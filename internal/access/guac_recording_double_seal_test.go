package access

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// SEALING A RECORDING TWICE DESTROYS IT, AND NOTHING ON THE ROW SAYS SO.
//
// sealOneGuacRecording rewrites the recording in place, and the sweep's
// candidate query selects on `recording_sealed_at IS NULL` with no claim. Two
// replicas running the same tick both see the same unsealed row, both stat the
// same file, and both seal it -- the second reading the first's ciphertext as
// if it were plaintext. The bytes on disk are then doubly encrypted and
// recording_sha256 holds the digest of the ciphertext the second sealer saw,
// so one decrypt pass yields ciphertext rather than the session. On a product
// that records privileged sessions for compliance, that is evidence destroyed
// silently: the row looks sealed, the file looks sealed, and playback is gone.
//
// The sweep's own comment already named this for a different path -- a crash
// between the rename and the metadata write leaves ciphertext with the row
// still unsealed, so the next tick re-seals it -- and accepted it as a risk to
// be reconciled by hand. It is the same corruption either way.
//
// So the sealer refuses ciphertext. The refusal is a PROOF, not a guess: the
// probe decrypts the first frame, and AES-GCM authenticates it.
func TestSealingAnAlreadySealedRecordingIsRefused(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "sess-double")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	recPath := filepath.Join(dir, "recording")

	plaintext := make([]byte, 64*1024)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recPath, plaintext, 0o644); err != nil {
		t.Fatal(err)
	}

	h := &RemoteSupportHandler{
		logger:             zap.NewNop(),
		guacRecordingRing:  makeTestRing(t),
		guacRecordingsRoot: root,
	}

	if _, _, err := h.sealOneGuacRecording(recPath); err != nil {
		t.Fatalf("first seal: %v", err)
	}

	// The second replica's attempt. Before the refusal this returned a digest
	// and a nil error, having encrypted the ciphertext.
	_, _, err := h.sealOneGuacRecording(recPath)
	if !errors.Is(err, errAlreadySealed) {
		t.Fatalf("second seal was allowed (err=%v); the recording on disk is now doubly encrypted "+
			"and one decrypt pass no longer reproduces the session", err)
	}

	// And the file is still a recording: one decrypt pass reproduces the
	// original bytes exactly. This is the assertion that would fail if the
	// refusal ever stopped working, whatever the error type said.
	sealed, err := os.Open(recPath)
	if err != nil {
		t.Fatal(err)
	}
	defer sealed.Close()
	var got bytes.Buffer
	if _, err := got.ReadFrom(newDecryptingReader(sealed, h.guacRecordingRing, guacRecordingSessionKey(recPath))); err != nil {
		t.Fatalf("decrypt the sealed recording: %v", err)
	}
	if !bytes.Equal(got.Bytes(), plaintext) {
		t.Fatalf("the sealed recording no longer decrypts to the session: got %d bytes, want %d",
			got.Len(), len(plaintext))
	}
}

// The other direction, and the one that would make the refusal a denial of
// service if it were a guess rather than a proof: a plaintext recording must
// never be mistaken for a sealed one, or recordings would silently stop being
// encrypted at rest. Random bytes are the hardest case -- a guacd recording is
// mostly ASCII, so an accidental match would need a random first byte to be a
// live key id AND the frame to authenticate under a key it was never sealed
// with.
func TestAPlaintextRecordingIsNeverMistakenForSealed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "sess-plain")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	h := &RemoteSupportHandler{
		logger:             zap.NewNop(),
		guacRecordingRing:  makeTestRing(t),
		guacRecordingsRoot: root,
	}

	for name, body := range map[string][]byte{
		"guacd-native": []byte("4.size,4.1024,3.768;5.audio,1.1;6.cursor,2.32;"),
		"random":       mustRandom(t, 4096),
		"empty":        {},
	} {
		recPath := filepath.Join(dir, name)
		if err := os.WriteFile(recPath, body, 0o644); err != nil {
			t.Fatal(err)
		}
		if h.alreadySealed(recPath) {
			t.Errorf("%s: a plaintext recording read as sealed; it would never be encrypted at rest", name)
		}
	}
}

func mustRandom(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// A FRAME LENGTH IS FOUR BYTES FROM THE FILE, AND THE READER USED TO BELIEVE
// THEM. ctLen is a uint32, so a header claiming four gigabytes made the reader
// allocate four gigabytes before authenticating anything -- on the playback
// path, for any file that is not a sealed recording.
//
// This was not reasoned out; it was measured. The plaintext probe above took
// 12.7 seconds to read three small files, which is Go zeroing those
// allocations. With the bound it is under a tenth of a second.
func TestAnOversizedFrameLengthIsRejectedRatherThanAllocated(t *testing.T) {
	// keyID 0, then a big-endian length of 4 GiB - 1, then whatever.
	hdr := []byte{0, 0xFF, 0xFF, 0xFF, 0xFF}
	r := newDecryptingReader(bytes.NewReader(append(hdr, make([]byte, 64)...)), makeTestRing(t), "sess/recording")

	var buf [1]byte
	_, err := r.Read(buf[:])
	if err == nil {
		t.Fatal("a frame claiming four gigabytes was accepted")
	}
	if !strings.Contains(err.Error(), "exceeds the maximum") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
}

// assertDecryptsTo is the assertion both seal tests end on: whatever happened
// to the file, one decrypt pass still reproduces the session exactly.
func assertDecryptsTo(t *testing.T, h *RemoteSupportHandler, path string, want []byte) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var got bytes.Buffer
	if _, err := got.ReadFrom(newDecryptingReader(f, h.guacRecordingRing, guacRecordingSessionKey(path))); err != nil {
		t.Fatalf("decrypt the sealed recording: %v", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("the sealed recording no longer decrypts to the session: got %d bytes, want %d", got.Len(), len(want))
	}
}
