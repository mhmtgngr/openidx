package access

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// THE INTERLEAVING THAT DOUBLY ENCRYPTED RECORDINGS, DRIVEN BY HAND.
//
// TestTwoConcurrentSealersAnnounceTheSealOnce races two replicas and failed in
// 1 of 60 runs on main with "got 32801 bytes, want 32768": one seal envelope
// too many. The race is not reproduced here by racing -- that is how it went
// unfound -- but by holding each side still at the moment that mattered.
//
// The old sealer asked "is this path plaintext?" and then opened the path.
// Two lookups of one name. If the other replica's rename landed between them,
// the second lookup resolved the other replica's ciphertext, and the sealer,
// holding a "plaintext" answer about an inode that was no longer there,
// encrypted ciphertext. The fix binds the proof to the descriptor: what the
// probe authenticated is what gets encrypted, whatever the directory entry does
// meanwhile.

func sealHandler(t *testing.T) (*RemoteSupportHandler, string, []byte) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "sess-interleave")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "recording")
	plaintext := make([]byte, 32*1024)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, plaintext, 0o644); err != nil {
		t.Fatal(err)
	}
	h := &RemoteSupportHandler{
		logger:             zap.NewNop(),
		guacRecordingRing:  makeTestRing(t),
		guacRecordingsRoot: root,
	}
	return h, path, plaintext
}

// Replica B opens the plaintext and is held. Replica A seals to completion and
// renames. B then seals from the descriptor it held. The file must be ONE
// envelope over the session, and B's digest must be the plaintext's -- B saw
// the old inode throughout.
func TestASealerThatOpenedPlaintextBeforeAnotherReplicaRenamedProducesOneEnvelope(t *testing.T) {
	h, path, plaintext := sealHandler(t)

	held, err := h.openUnsealedRecording(path) // B, before A moves
	if err != nil {
		t.Fatalf("B open: %v", err)
	}
	defer held.Close()

	if _, _, err := h.sealOneGuacRecording(path); err != nil { // A, start to finish
		t.Fatalf("A seal: %v", err)
	}

	sum, _, err := h.sealFrom(held, path) // B, from the descriptor it held
	if err != nil {
		t.Fatalf("B seal from held descriptor: %v", err)
	}

	assertDecryptsTo(t, h, path, plaintext)

	want := sha256.Sum256(plaintext)
	if sum != hex.EncodeToString(want[:]) {
		t.Fatalf("B's digest is not the session's: it hashed what it encrypted, so it encrypted something other than the plaintext it was opened on")
	}
	if left, _ := filepath.Glob(path + ".sealing*"); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
}

// WHY the fix is where it is. The path-based probe is not wrong about the
// path at the instant it runs; it is wrong to trust that answer a moment later.
// This shows the window as two steps: a path answer of "plaintext", then a
// fresh open that yields ciphertext -- the exact pair of facts the old sealer
// acted on. And it shows the new API cannot be in that position: an open after
// the rename refuses.
func TestTheProbeAndTheEncryptShareOneInode(t *testing.T) {
	h, path, _ := sealHandler(t)

	if h.alreadySealed(path) {
		t.Fatal("fresh plaintext reported as sealed")
	}
	// The other replica lands between the probe and the open.
	if _, _, err := h.sealOneGuacRecording(path); err != nil {
		t.Fatalf("A seal: %v", err)
	}
	// A second, independent open of the same name now sees ciphertext. The old
	// sealer took this descriptor and encrypted it, holding the answer above.
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if !h.sealedFile(f, path) {
		t.Fatal("after A's rename the name should resolve to ciphertext; the window this test is about does not exist here")
	}

	// The new API asks and opens in one step, on one descriptor, so it cannot
	// carry a stale answer across the rename.
	if _, err := h.openUnsealedRecording(path); !errors.Is(err, errAlreadySealed) {
		t.Fatalf("openUnsealedRecording after the rename returned %v; it must refuse ciphertext", err)
	}
}

// Two sealers used to write the SAME temp name with O_TRUNC, each wiping the
// other's frames mid-write. Each sealer now gets its own inode beside the
// recording, so the only shared step is the atomic rename.
func TestConcurrentSealersNeverShareATempFile(t *testing.T) {
	_, path, _ := sealHandler(t)

	a, err := newSealTemp(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close(); _ = os.Remove(a.Name()) }()
	b, err := newSealTemp(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close(); _ = os.Remove(b.Name()) }()

	if a.Name() == b.Name() {
		t.Fatalf("two sealers were handed the same temp file %s; the second O_TRUNCs the first mid-write", a.Name())
	}
	for _, f := range []*os.File{a, b} {
		if filepath.Dir(f.Name()) != filepath.Dir(path) {
			t.Errorf("temp %s is not beside the recording; rename across directories is not atomic", f.Name())
		}
		if !strings.HasPrefix(filepath.Base(f.Name()), filepath.Base(path)+".sealing-") {
			t.Errorf("temp %s does not carry the recording's name; a crash leaves an orphan nobody can attribute", f.Name())
		}
		if f.Name() == path+".sealing" {
			t.Errorf("temp is the old shared name %s", f.Name())
		}
	}
}
