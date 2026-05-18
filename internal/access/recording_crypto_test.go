package access

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freshMasterKey returns 32 random bytes suitable for newRecordingAEAD.
// Each test gets its own so a leak in one can't cross-contaminate another.
func freshMasterKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, recordingMasterKeyLen)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func TestRecordingAEAD_RejectsWrongKeyLength(t *testing.T) {
	_, err := newRecordingAEAD(make([]byte, 16), "session-1")
	require.Error(t, err, "16-byte key should be rejected (AES-256 requires 32 bytes)")
}

// TestRecordingAEAD_EncryptDecryptRoundTrip exercises the framing /
// nonce / decryption pipeline end-to-end with realistic chunk-sized
// payloads.
func TestRecordingAEAD_EncryptDecryptRoundTrip(t *testing.T) {
	key := freshMasterKey(t)
	aead, err := newRecordingAEAD(key, "session-rt")
	require.NoError(t, err)

	chunks := [][]byte{
		[]byte("webm-chunk-1 with some bytes"),
		bytes.Repeat([]byte{0xab}, 4096),
		[]byte(""), // empty chunk — corner case from MediaRecorder timeslice 0
	}
	var encrypted bytes.Buffer
	for _, c := range chunks {
		frame, err := aead.encryptChunk(c)
		require.NoError(t, err)
		_, _ = encrypted.Write(frame)
	}

	// Decrypt by streaming through the reader; concatenated plaintext
	// should be the byte-for-byte concatenation of the inputs.
	dec := newDecryptingReader(&encrypted, aead)
	plaintext, err := io.ReadAll(dec)
	require.NoError(t, err)

	var expected bytes.Buffer
	for _, c := range chunks {
		expected.Write(c)
	}
	assert.Equal(t, expected.Bytes(), plaintext)
}

// TestRecordingAEAD_TamperDetection mutates one byte of the on-disk
// ciphertext and confirms the GCM tag fails the decrypt. If this test
// stops passing, the integrity guarantee is gone — an attacker with
// disk access could substitute frames.
func TestRecordingAEAD_TamperDetection(t *testing.T) {
	key := freshMasterKey(t)
	aead, err := newRecordingAEAD(key, "session-tamper")
	require.NoError(t, err)

	frame, err := aead.encryptChunk([]byte("payload that must not be modifiable"))
	require.NoError(t, err)
	// Flip a byte in the ciphertext region (skip the 4-byte length +
	// 12-byte nonce prefix so we know we're modifying actual ciphertext).
	tamperIdx := frameLengthPrefix + frameNonceLen + 2
	frame[tamperIdx] ^= 0x01

	_, err = io.ReadAll(newDecryptingReader(bytes.NewReader(frame), aead))
	require.Error(t, err, "tampered ciphertext must fail GCM authentication")
}

// TestRecordingAEAD_DistinctSessionsHaveDistinctCiphertexts confirms
// the HKDF derivation actually mixes the session ID in. Two sessions
// with the same plaintext + master key + same nonce randomness window
// must still produce different ciphertexts because the keys differ.
func TestRecordingAEAD_DistinctSessionsHaveDistinctCiphertexts(t *testing.T) {
	key := freshMasterKey(t)
	a, err := newRecordingAEAD(key, "session-A")
	require.NoError(t, err)
	b, err := newRecordingAEAD(key, "session-B")
	require.NoError(t, err)

	plaintext := []byte("the same plaintext")
	frameA, err := a.encryptChunk(plaintext)
	require.NoError(t, err)
	frameB, err := b.encryptChunk(plaintext)
	require.NoError(t, err)
	// The 12-byte nonces will differ randomly anyway; we care that the
	// ciphertext+tag region (the encrypted payload) is also different
	// when both keys + nonces differ. Compare beyond the nonce.
	ctA := frameA[frameLengthPrefix+frameNonceLen:]
	ctB := frameB[frameLengthPrefix+frameNonceLen:]
	assert.NotEqual(t, ctA, ctB)

	// And cross-decryption must fail (session A's key can't decrypt B's
	// ciphertext).
	_, err = io.ReadAll(newDecryptingReader(bytes.NewReader(frameB), a))
	require.Error(t, err, "session-A AEAD must reject session-B's frame")
}

// TestRecordingAEAD_TruncatedFinalFrameIsCleanEOF simulates a crash
// mid-write that leaves an incomplete final frame on disk. The reader
// should return whatever frames were complete and treat the truncation
// as EOF rather than an error.
func TestRecordingAEAD_TruncatedFinalFrameIsCleanEOF(t *testing.T) {
	key := freshMasterKey(t)
	aead, err := newRecordingAEAD(key, "session-trunc")
	require.NoError(t, err)
	good, err := aead.encryptChunk([]byte("first chunk — recoverable"))
	require.NoError(t, err)
	bad, err := aead.encryptChunk([]byte("second chunk — gets truncated"))
	require.NoError(t, err)
	// Truncate the second frame to half its size, simulating a crash
	// during the write of that frame.
	truncated := append([]byte(nil), good...)
	truncated = append(truncated, bad[:len(bad)/2]...)

	out, err := io.ReadAll(newDecryptingReader(bytes.NewReader(truncated), aead))
	require.NoError(t, err)
	assert.Equal(t, []byte("first chunk — recoverable"), out,
		"reader must surface the recoverable frame and treat the truncated tail as EOF")
}

// TestFilesystemRecordingStore_EncryptedRoundTrip is the integration
// test for the public path: write chunks through the store with a
// master key, then read them back via Open and confirm the bytes
// match. Also confirms the on-disk file is NOT plaintext.
func TestFilesystemRecordingStore_EncryptedRoundTrip(t *testing.T) {
	root := t.TempDir()
	key := freshMasterKey(t)
	store, err := newFilesystemRecordingStore(root, key)
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

	// Raw on-disk bytes must NOT contain the plaintext (otherwise the
	// "encryption at rest" claim is fraudulent).
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

// TestFilesystemRecordingStore_PlaintextModeBackCompat confirms the
// default no-key path is unchanged: chunks land on disk plaintext for
// dev / migration scenarios.
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
		"without a master key, on-disk bytes must equal plaintext")
}

func TestNewFilesystemRecordingStore_RejectsBadKeyLength(t *testing.T) {
	root := t.TempDir()
	_, err := newFilesystemRecordingStore(root, make([]byte, 7))
	require.Error(t, err)
}
