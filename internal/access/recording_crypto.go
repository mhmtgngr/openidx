// Package access — encryption at rest for the filesystem recording
// backend, with master-key rotation.
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
// Wire framing on disk, per MediaRecorder chunk Append() receives:
//
//	[1-byte key-id]
//	[4-byte big-endian uint32 ciphertext length C]
//	[12-byte AES-GCM nonce]
//	[C-byte AES-GCM ciphertext + 16-byte tag]
//
// The key-id identifies which master key in the keyring protected the
// frame, so rotation works: new writes use the active key's id, old
// recordings still carry their original id and decrypt as long as that
// key remains in the ring. Retire an old key once every recording it
// protected has been purged.
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
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// recordingMasterKeyLen is the byte length of each configured master
// key. Locked to 32 bytes so a config typo can't downgrade the cipher.
const recordingMasterKeyLen = 32

const (
	frameKeyIDPrefix  = 1  // 1-byte key id
	frameLengthPrefix = 4  // 4-byte big-endian uint32
	frameNonceLen     = 12 // AES-GCM standard nonce length
	frameTagLen       = 16 // AES-GCM authentication tag
)

// recordingAEAD wraps the cipher.AEAD primitive with a small bit of
// session-scoping. Constructed via newRecordingAEAD per (master key,
// session) pair.
type recordingAEAD struct {
	gcm cipher.AEAD
}

// newRecordingAEAD derives a per-session key from the master key and
// returns an AEAD wrapper. masterKey must be exactly 32 bytes.
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

// encryptChunk produces a self-contained framed unit ready to append
// to disk: keyID(1) | length(4) | nonce(12) | ciphertext+tag.
func (a *recordingAEAD) encryptChunk(keyID byte, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, frameNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce random: %w", err)
	}
	ciphertext := a.gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, frameKeyIDPrefix+frameLengthPrefix+frameNonceLen+len(ciphertext))
	out[0] = keyID
	binary.BigEndian.PutUint32(out[frameKeyIDPrefix:frameKeyIDPrefix+frameLengthPrefix], uint32(len(ciphertext)))
	copy(out[frameKeyIDPrefix+frameLengthPrefix:frameKeyIDPrefix+frameLengthPrefix+frameNonceLen], nonce)
	copy(out[frameKeyIDPrefix+frameLengthPrefix+frameNonceLen:], ciphertext)
	return out, nil
}

// recordingKeyring holds the master keys available for recording
// encryption: an active key (used for writes) and any number of
// previous keys (kept around so older recordings still decrypt).
type recordingKeyring struct {
	keys     map[byte][]byte // id -> 32-byte master key
	activeID byte
}

// Enabled reports whether the ring has at least the active key wired.
func (r *recordingKeyring) Enabled() bool {
	return r != nil && len(r.keys) > 0
}

// ActiveID returns the id new recordings encrypt under.
func (r *recordingKeyring) ActiveID() byte { return r.activeID }

// masterFor returns the master key for the supplied id, or an error
// when the ring doesn't carry it (a recording protected by a retired
// key, say).
func (r *recordingKeyring) masterFor(id byte) ([]byte, error) {
	k, ok := r.keys[id]
	if !ok {
		return nil, fmt.Errorf("recording key id %d not in keyring (retired or never configured)", id)
	}
	return k, nil
}

// newRecordingKeyring builds a ring from config. When multiForm is
// non-empty it's parsed as comma-separated "id:base64key" entries and
// activeID selects the write key. Otherwise singleKey (if non-empty)
// is loaded as id 0 active. Returns (nil, nil) when neither is set so
// callers can treat the ring as "encryption disabled".
func newRecordingKeyring(multiForm string, activeID int, singleKey string) (*recordingKeyring, error) {
	multiForm = strings.TrimSpace(multiForm)
	if multiForm == "" {
		if strings.TrimSpace(singleKey) == "" {
			return nil, nil // encryption disabled
		}
		raw, err := decodeMasterKey(singleKey)
		if err != nil {
			return nil, fmt.Errorf("recordings_encryption_key: %w", err)
		}
		return &recordingKeyring{keys: map[byte][]byte{0: raw}, activeID: 0}, nil
	}

	ring := &recordingKeyring{keys: make(map[byte][]byte)}
	for _, entry := range strings.Split(multiForm, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		idStr, keyStr, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("recordings_encryption_keys: entry %q is not id:base64key", entry)
		}
		id, err := strconv.Atoi(strings.TrimSpace(idStr))
		if err != nil || id < 0 || id > 255 {
			return nil, fmt.Errorf("recordings_encryption_keys: id %q must be 0-255", idStr)
		}
		raw, err := decodeMasterKey(keyStr)
		if err != nil {
			return nil, fmt.Errorf("recordings_encryption_keys: id %d: %w", id, err)
		}
		ring.keys[byte(id)] = raw
	}
	if len(ring.keys) == 0 {
		return nil, errors.New("recordings_encryption_keys: no valid entries")
	}
	if activeID < 0 || activeID > 255 {
		return nil, fmt.Errorf("recordings_encryption_active_key_id %d must be 0-255", activeID)
	}
	if _, ok := ring.keys[byte(activeID)]; !ok {
		return nil, fmt.Errorf("recordings_encryption_active_key_id %d not present in recordings_encryption_keys", activeID)
	}
	ring.activeID = byte(activeID)
	return ring, nil
}

// decodeMasterKey base64-decodes a key and enforces the 32-byte length.
func decodeMasterKey(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}
	if len(raw) != recordingMasterKeyLen {
		return nil, fmt.Errorf("must decode to %d bytes, got %d", recordingMasterKeyLen, len(raw))
	}
	return raw, nil
}

// decryptingReader wraps a frame-stream and returns plaintext bytes
// transparently. It resolves each frame's key by id through the
// keyring and caches the derived per-session AEAD so a multi-thousand-
// frame recording does at most one HKDF per distinct key id.
//
// Truncated final frames (interrupted writes) are treated as a clean
// EOF so a crashed session still plays back the chunks that landed.
type decryptingReader struct {
	src       io.Reader
	ring      *recordingKeyring
	sessionID string
	cache     map[byte]*recordingAEAD
	pending   []byte
	done      bool
}

func newDecryptingReader(src io.Reader, ring *recordingKeyring, sessionID string) *decryptingReader {
	return &decryptingReader{
		src:       src,
		ring:      ring,
		sessionID: sessionID,
		cache:     make(map[byte]*recordingAEAD),
	}
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

func (r *decryptingReader) aeadFor(id byte) (*recordingAEAD, error) {
	if a, ok := r.cache[id]; ok {
		return a, nil
	}
	master, err := r.ring.masterFor(id)
	if err != nil {
		return nil, err
	}
	a, err := newRecordingAEAD(master, r.sessionID)
	if err != nil {
		return nil, err
	}
	r.cache[id] = a
	return a, nil
}

func (r *decryptingReader) nextFrame() error {
	// keyID + length are read together; a clean EOF before the key id
	// means we've consumed every frame.
	var hdr [frameKeyIDPrefix + frameLengthPrefix]byte
	if _, err := io.ReadFull(r.src, hdr[:]); err != nil {
		return err
	}
	keyID := hdr[0]
	ctLen := int(binary.BigEndian.Uint32(hdr[frameKeyIDPrefix:]))
	if ctLen < frameTagLen {
		return errors.New("recording frame ciphertext too short for GCM tag")
	}
	frame := make([]byte, frameNonceLen+ctLen)
	if _, err := io.ReadFull(r.src, frame); err != nil {
		// Truncated tail — likely a crash mid-write. Treat as EOF so the
		// rest of the recording still plays.
		return io.EOF
	}
	aead, err := r.aeadFor(keyID)
	if err != nil {
		return err
	}
	nonce := frame[:frameNonceLen]
	ciphertext := frame[frameNonceLen:]
	plaintext, err := aead.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decrypt frame (key id %d): %w", keyID, err)
	}
	r.pending = plaintext
	return nil
}
