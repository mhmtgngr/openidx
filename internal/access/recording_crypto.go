// Package access — encryption at rest for the filesystem recording
// backend.
//
// Threat model: a filesystem-level compromise (backup leak, stolen
// disk, accidentally-public path) gives the attacker raw on-disk
// bytes. Without encryption that's a playable WebM of the user's
// screen. With this package wired and a master key configured, each
// chunk is AES-256-GCM encrypted under a per-session key derived from
// the master via HKDF-SHA256, so the attacker also needs the master
// key (kept in the service's config / secrets manager, never on the
// recording disk).
//
// Wire framing on disk:
//
//   for each MediaRecorder chunk Append() receives:
//     [4-byte big-endian uint32 ciphertext length C]
//     [12-byte AES-GCM nonce]
//     [C-byte AES-GCM ciphertext + 16-byte tag]
//
// The 4-byte length prefix means a crash mid-write leaves a truncated
// final frame, which the read path detects and stops at instead of
// failing the whole recording. The 12-byte nonce per frame is freshly
// random — GCM nonce-reuse with a fixed key is catastrophic, so we
// never derive the nonce from a counter.
package access

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// recordingMasterKeyLen is the byte length of the configured master
// key. Locked to 32 bytes so a config typo can't downgrade the cipher.
const recordingMasterKeyLen = 32

// frameNonceLen + frameLengthPrefix are exposed so tests can assert
// on the on-disk framing without re-deriving the constants.
const (
	frameLengthPrefix = 4  // 4-byte big-endian uint32
	frameNonceLen     = 12 // AES-GCM standard nonce length
	frameTagLen       = 16 // AES-GCM authentication tag
)

// recordingAEAD wraps the cipher.AEAD primitive with a small bit of
// session-scoping. Constructed via newRecordingAEAD per session.
type recordingAEAD struct {
	gcm cipher.AEAD
}

// newRecordingAEAD derives a per-session key from the master key and
// returns an AEAD wrapper. masterKey must be exactly 32 bytes; the
// caller (service.go startup) is responsible for length-checking.
//
// HKDF salt is empty (acceptable when the IKM is already uniformly
// random); the info string includes a version tag so we can rotate
// the derivation scheme without re-encrypting old recordings.
func newRecordingAEAD(masterKey []byte, sessionID string) (*recordingAEAD, error) {
	if len(masterKey) != recordingMasterKeyLen {
		return nil, fmt.Errorf("recording master key must be %d bytes, got %d",
			recordingMasterKeyLen, len(masterKey))
	}
	info := []byte("openidx-recording-v1:" + sessionID)
	kdf := hkdf.New(sha256.New, masterKey, nil, info)
	derived := make([]byte, 32)
	if _, err := io.ReadFull(kdf, derived); err != nil {
		return nil, fmt.Errorf("hkdf read: %w", err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm wrap: %w", err)
	}
	return &recordingAEAD{gcm: gcm}, nil
}

// encryptChunk produces a single self-contained framed unit ready to
// append to disk: length(4) | nonce(12) | ciphertext+tag.
func (a *recordingAEAD) encryptChunk(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, frameNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce random: %w", err)
	}
	ciphertext := a.gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, frameLengthPrefix+frameNonceLen+len(ciphertext))
	binary.BigEndian.PutUint32(out[:frameLengthPrefix], uint32(len(ciphertext)))
	copy(out[frameLengthPrefix:frameLengthPrefix+frameNonceLen], nonce)
	copy(out[frameLengthPrefix+frameNonceLen:], ciphertext)
	return out, nil
}

// decryptingReader wraps a frame-stream and returns plaintext bytes
// transparently. Truncated final frames (interrupted writes) are
// treated as a clean EOF so a crashed session still plays back the
// chunks that did land cleanly.
type decryptingReader struct {
	src     io.Reader
	aead    *recordingAEAD
	pending []byte // plaintext buffered from the current frame
	done    bool
}

func newDecryptingReader(src io.Reader, aead *recordingAEAD) *decryptingReader {
	return &decryptingReader{src: src, aead: aead}
}

func (r *decryptingReader) Read(p []byte) (int, error) {
	if len(r.pending) == 0 && !r.done {
		if err := r.nextFrame(); err != nil {
			if errors.Is(err, io.EOF) {
				r.done = true
				return 0, io.EOF
			}
			return 0, err
		}
	}
	if r.done && len(r.pending) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func (r *decryptingReader) nextFrame() error {
	var lenBuf [frameLengthPrefix]byte
	if _, err := io.ReadFull(r.src, lenBuf[:]); err != nil {
		// EOF here means we've consumed every frame cleanly.
		return err
	}
	ctLen := int(binary.BigEndian.Uint32(lenBuf[:]))
	if ctLen < frameTagLen {
		return errors.New("recording frame ciphertext too short for GCM tag")
	}
	frame := make([]byte, frameNonceLen+ctLen)
	if _, err := io.ReadFull(r.src, frame); err != nil {
		// Truncated tail — likely a crash mid-write. Treat as EOF so the
		// rest of the recording still plays.
		return io.EOF
	}
	nonce := frame[:frameNonceLen]
	ciphertext := frame[frameNonceLen:]
	plaintext, err := r.aead.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decrypt frame: %w", err)
	}
	r.pending = plaintext
	return nil
}

