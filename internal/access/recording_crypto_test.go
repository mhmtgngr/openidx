package access

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freshMasterKey returns 32 random bytes suitable for newRecordingAEAD.
func freshMasterKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, recordingMasterKeyLen)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func freshMasterKeyB64(t *testing.T) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(freshMasterKey(t))
}

// singleKeyRing builds a ring with one key at id 0 (mirrors the
// single-key config path) for tests that don't care about rotation.
func singleKeyRing(t *testing.T) *recordingKeyring {
	t.Helper()
	ring, err := newRecordingKeyring("", 0, freshMasterKeyB64(t))
	require.NoError(t, err)
	require.NotNil(t, ring)
	return ring
}

func TestRecordingAEAD_RejectsWrongKeyLength(t *testing.T) {
	_, err := newRecordingAEAD(make([]byte, 16), "session-1")
	require.Error(t, err, "16-byte key should be rejected (AES-256 requires 32 bytes)")
}

func TestRecordingAEAD_EncryptDecryptRoundTrip(t *testing.T) {
	ring := singleKeyRing(t)
	master, _ := ring.masterFor(0)
	aead, err := newRecordingAEAD(master, "session-rt")
	require.NoError(t, err)

	chunks := [][]byte{
		[]byte("webm-chunk-1 with some bytes"),
		bytes.Repeat([]byte{0xab}, 4096),
		[]byte(""), // empty chunk — corner case from MediaRecorder timeslice 0
	}
	var encrypted bytes.Buffer
	for _, c := range chunks {
		frame, err := aead.encryptChunk(0, c)
		require.NoError(t, err)
		_, _ = encrypted.Write(frame)
	}

	dec := newDecryptingReader(&encrypted, ring, "session-rt")
	plaintext, err := io.ReadAll(dec)
	require.NoError(t, err)

	var expected bytes.Buffer
	for _, c := range chunks {
		expected.Write(c)
	}
	assert.Equal(t, expected.Bytes(), plaintext)
}

func TestRecordingAEAD_TamperDetection(t *testing.T) {
	ring := singleKeyRing(t)
	master, _ := ring.masterFor(0)
	aead, err := newRecordingAEAD(master, "session-tamper")
	require.NoError(t, err)

	frame, err := aead.encryptChunk(0, []byte("payload that must not be modifiable"))
	require.NoError(t, err)
	// Flip a byte in the ciphertext region (skip keyID + length + nonce).
	tamperIdx := frameKeyIDPrefix + frameLengthPrefix + frameNonceLen + 2
	frame[tamperIdx] ^= 0x01

	_, err = io.ReadAll(newDecryptingReader(bytes.NewReader(frame), ring, "session-tamper"))
	require.Error(t, err, "tampered ciphertext must fail GCM authentication")
}

func TestRecordingAEAD_TruncatedFinalFrameIsCleanEOF(t *testing.T) {
	ring := singleKeyRing(t)
	master, _ := ring.masterFor(0)
	aead, err := newRecordingAEAD(master, "session-trunc")
	require.NoError(t, err)
	good, err := aead.encryptChunk(0, []byte("first chunk — recoverable"))
	require.NoError(t, err)
	bad, err := aead.encryptChunk(0, []byte("second chunk — gets truncated"))
	require.NoError(t, err)
	truncated := append([]byte(nil), good...)
	truncated = append(truncated, bad[:len(bad)/2]...)

	out, err := io.ReadAll(newDecryptingReader(bytes.NewReader(truncated), ring, "session-trunc"))
	require.NoError(t, err)
	assert.Equal(t, []byte("first chunk — recoverable"), out)
}

// --- keyring construction ---

func TestNewRecordingKeyring_DisabledWhenEmpty(t *testing.T) {
	ring, err := newRecordingKeyring("", 0, "")
	require.NoError(t, err)
	assert.Nil(t, ring, "no keys configured → nil ring (encryption disabled)")
}

func TestNewRecordingKeyring_SingleKeyMapsToIDZero(t *testing.T) {
	ring, err := newRecordingKeyring("", 0, freshMasterKeyB64(t))
	require.NoError(t, err)
	require.NotNil(t, ring)
	assert.True(t, ring.Enabled())
	assert.Equal(t, byte(0), ring.ActiveID())
	_, err = ring.masterFor(0)
	assert.NoError(t, err)
}

func TestNewRecordingKeyring_MultiKeyParsesAndSelectsActive(t *testing.T) {
	k1 := freshMasterKeyB64(t)
	k2 := freshMasterKeyB64(t)
	ring, err := newRecordingKeyring("1:"+k1+",2:"+k2, 2, "")
	require.NoError(t, err)
	require.NotNil(t, ring)
	assert.Equal(t, byte(2), ring.ActiveID())
	_, err = ring.masterFor(1)
	assert.NoError(t, err)
	_, err = ring.masterFor(2)
	assert.NoError(t, err)
}

func TestNewRecordingKeyring_ActiveIDMustExist(t *testing.T) {
	ring, err := newRecordingKeyring("1:"+freshMasterKeyB64(t), 9, "")
	require.Error(t, err, "active id not in the key set must be rejected")
	assert.Nil(t, ring)
}

func TestNewRecordingKeyring_RejectsBadEntry(t *testing.T) {
	_, err := newRecordingKeyring("notanint:"+freshMasterKeyB64(t), 0, "")
	require.Error(t, err)
	_, err = newRecordingKeyring("1:not-base64!!", 1, "")
	require.Error(t, err)
}

// --- rotation behavior ---

// TestKeyRotation_OldRecordingStillDecrypts is the core rotation test:
// write a recording under key id 1, then rotate so id 2 is active but
// id 1 is retained, and confirm the old recording still reads. Then
// retire id 1 and confirm the old recording now fails with a clear
// error.
func TestKeyRotation_OldRecordingStillDecrypts(t *testing.T) {
	root := t.TempDir()
	k1 := freshMasterKeyB64(t)
	k2 := freshMasterKeyB64(t)

	// Phase 1: only key 1 exists, active.
	ringV1, err := newRecordingKeyring("1:"+k1, 1, "")
	require.NoError(t, err)
	storeV1, err := newFilesystemRecordingStore(root, ringV1)
	require.NoError(t, err)

	payload := []byte("\x1a\x45\xdf\xa3 recorded under key 1")
	_, err = storeV1.Append("session-old", 0, bytes.NewReader(payload))
	require.NoError(t, err)

	// Phase 2: rotate — key 2 added and active, key 1 RETAINED for reads.
	ringV2, err := newRecordingKeyring("1:"+k1+",2:"+k2, 2, "")
	require.NoError(t, err)
	storeV2, err := newFilesystemRecordingStore(root, ringV2)
	require.NoError(t, err)

	// The old recording (key 1) still decrypts under the rotated ring.
	reader, _, err := storeV2.Open("session-old")
	require.NoError(t, err)
	out, err := io.ReadAll(reader)
	reader.Close()
	require.NoError(t, err)
	assert.Equal(t, payload, out)

	// A new recording lands under the active key (2) and also reads back.
	newPayload := []byte("recorded under key 2 after rotation")
	_, err = storeV2.Append("session-new", 0, bytes.NewReader(newPayload))
	require.NoError(t, err)
	r2, _, err := storeV2.Open("session-new")
	require.NoError(t, err)
	out2, err := io.ReadAll(r2)
	r2.Close()
	require.NoError(t, err)
	assert.Equal(t, newPayload, out2)

	// Phase 3: RETIRE key 1 — only key 2 remains. The old recording can
	// no longer be decrypted, and the error names the missing key id.
	ringV3, err := newRecordingKeyring("2:"+k2, 2, "")
	require.NoError(t, err)
	storeV3, err := newFilesystemRecordingStore(root, ringV3)
	require.NoError(t, err)
	r3, _, err := storeV3.Open("session-old")
	require.NoError(t, err)
	_, err = io.ReadAll(r3)
	r3.Close()
	require.Error(t, err, "recording under a retired key must fail to decrypt")
}

// --- store integration (encrypted + plaintext) ---

func TestFilesystemRecordingStore_EncryptedRoundTrip(t *testing.T) {
	root := t.TempDir()
	ring := singleKeyRing(t)
	store, err := newFilesystemRecordingStore(root, ring)
	require.NoError(t, err)

	sessionID := "session-fs"
	chunks := [][]byte{
		[]byte("\x1a\x45\xdf\xa3 webm-magic-start..."),
		bytes.Repeat([]byte{0xff}, 1024),
	}
	for i, c := range chunks {
		n, err := store.Append(sessionID, i, bytes.NewReader(c))
		require.NoError(t, err)
		assert.Equal(t, int64(len(c)), n,
			"Append should return the plaintext length, not the on-disk encrypted length")
	}

	rawPath := filepath.Join(root, sessionID, "recording.webm")
	rawBytes, err := os.ReadFile(rawPath)
	require.NoError(t, err)
	for i, c := range chunks {
		assert.False(t, bytes.Contains(rawBytes, c),
			"chunk %d plaintext leaked into on-disk file", i)
	}

	reader, _, err := store.Open(sessionID)
	require.NoError(t, err)
	defer reader.Close()
	out, err := io.ReadAll(reader)
	require.NoError(t, err)

	var expected bytes.Buffer
	for _, c := range chunks {
		expected.Write(c)
	}
	assert.Equal(t, expected.Bytes(), out)
}

func TestFilesystemRecordingStore_PlaintextModeBackCompat(t *testing.T) {
	root := t.TempDir()
	store, err := newFilesystemRecordingStore(root, nil)
	require.NoError(t, err)

	sessionID := "session-plain"
	payload := []byte("\x1a\x45\xdf\xa3 plaintext-magic")
	_, err = store.Append(sessionID, 0, bytes.NewReader(payload))
	require.NoError(t, err)

	rawBytes, err := os.ReadFile(filepath.Join(root, sessionID, "recording.webm"))
	require.NoError(t, err)
	assert.Equal(t, payload, rawBytes,
		"without a keyring, on-disk bytes must equal plaintext")
}
