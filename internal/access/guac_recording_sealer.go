// Package access — PAM A1: seal (encrypt-at-rest) guacd session recordings.
//
// guacd writes RDP/SSH session recordings straight to disk as plaintext. Unlike
// the WebRTC remote-support path — where openidx sees every MediaRecorder chunk
// inline and encrypts it on write (remote_support_recording.go) — openidx never
// touches guacd's bytes as they are produced. A filesystem compromise (stolen
// disk, leaked backup, world-readable path) therefore yields a replayable
// recording of a privileged session.
//
// This sealer closes that gap. After a guac session has ended AND its plaintext
// transcript has been generated (guaclog needs the cleartext, so sealing must
// come last), the sweep:
//
//  1. streams the plaintext file, computing its SHA-256 as it goes;
//  2. re-encrypts the bytes through the SAME AES-256-GCM keyring + on-disk
//     framing used by the WebRTC store (recording_crypto.go), so playback and
//     key-rotation logic are shared;
//  3. atomically replaces the plaintext file with the sealed one (temp file +
//     rename, so a crash never leaves a half-written recording);
//  4. records recording_sealed_at / recording_sha256 / recording_key_id on the
//     session row and writes a hash-chained audit event.
//
// The whole feature is inert unless an encryption keyring is configured
// (SetGuacRecordingRing with an enabled ring) — back-compat for single-tenant
// deployments that keep recordings plaintext.
//
// Chunking: the file is sealed as a sequence of fixed-size frames (each an
// independent GCM unit under the shared framing) so the decrypting reader that
// already exists can play it back with no special-casing, and so a large
// recording never has to be held fully in memory on the read path.
package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

// errAlreadySealed says the file on disk is already ciphertext under this
// keyring, so sealing it again would encrypt the ciphertext.
//
// THE FAILURE IT PREVENTS IS UNRECOVERABLE, WHICH IS WHY THIS IS A REFUSAL AND
// NOT A WARNING. sealOneGuacRecording rewrites the recording in place, and the
// candidate query selects on recording_sealed_at IS NULL with no claim. Two
// replicas running the same tick both see the same unsealed row, both stat the
// same file, and both seal it -- the second reading the first's ciphertext as
// though it were plaintext. What lands on disk is doubly encrypted, and
// recording_sha256 then holds the digest of the ciphertext the second sealer
// saw rather than of the recording. One decrypt pass yields ciphertext, and
// nothing on the row says so: on a product that records privileged sessions for
// compliance, the evidence is destroyed silently.
//
// The same shape reaches here without any concurrency at all, and the sweep's
// own comment already named it: a crash after the rename but before the
// metadata write leaves ciphertext on disk with the row still unsealed, so the
// next tick re-seals it. That path is closed by the same refusal.
var errAlreadySealed = errors.New("guac recording is already sealed")

// guacSealChunkBytes is the plaintext frame size the sealer cuts the recording
// into before encrypting each frame. 1 MiB keeps per-frame memory bounded while
// keeping framing overhead (key id + length + nonce + tag = 33 bytes/frame)
// negligible relative to a multi-megabyte recording.
const guacSealChunkBytes = 1 << 20 // 1 MiB

// sealGuacRecordings encrypts-at-rest every ended guac session recording that
// is still plaintext on disk. Runs on the recording-retention enforcer tick,
// AFTER generateGuacTranscripts, so guaclog has already consumed the cleartext.
//
// No-op unless a keyring is wired and enabled. Cross-org background sweep under
// the bypass-RLS context set by StartRecordingRetentionEnforcer; each write is
// keyed by the session PK and stamped with the row's own org.
func (h *RemoteSupportHandler) sealGuacRecordings(ctx context.Context) {
	if h.guacRecordingRing == nil || !h.guacRecordingRing.Enabled() {
		return // encryption disabled → sealer inert
	}
	if h.db == nil || h.db.Pool == nil {
		return
	}

	//orgscope:ignore background cross-org sweep under bypass-RLS; org_id selected per row and used to scope the write
	rows, err := h.db.Pool.Query(ctx, `
		SELECT id, COALESCE(org_id::text, ''), recording_path
		  FROM guacamole_sessions
		 WHERE status IN ('ended', 'terminated')
		   AND recording_path IS NOT NULL
		   AND recording_path <> ''
		   AND recording_purged_at IS NULL
		   AND recording_sealed_at IS NULL
		 LIMIT 50`)
	if err != nil {
		h.logger.Warn("sealGuacRecordings: query failed", zap.Error(err))
		return
	}
	type job struct {
		id    string
		orgID string
		path  string
	}
	var jobs []job
	for rows.Next() {
		var j job
		if rows.Scan(&j.id, &j.orgID, &j.path) == nil {
			jobs = append(jobs, j)
		}
	}
	rows.Close()

	sealed := 0
	for _, j := range jobs {
		// Guard the path against directory traversal / root-equality the same
		// way the purge sweep does, so a malformed recording_path can never
		// make us read or overwrite something outside the recordings root.
		if !h.guacRecordingPathSafe(j.path) {
			h.logger.Warn("sealGuacRecordings: skipping unsafe recording_path",
				zap.String("session_id", j.id))
			continue
		}
		if _, statErr := os.Stat(j.path); statErr != nil {
			continue // recording not on disk (yet) — leave unsealed for a later tick
		}
		sum, keyID, sealErr := h.sealOneGuacRecording(j.path)
		if errors.Is(sealErr, errAlreadySealed) {
			// Ciphertext with no seal metadata: either another replica sealed
			// it between this tick's SELECT and now (harmless -- its own write
			// carries the digest), or a previous tick died between the rename
			// and the metadata write. Encrypting it again is the one thing
			// that would make the recording unrecoverable, so the sweep leaves
			// it alone and says so.
			h.logger.Warn("sealGuacRecordings: recording is already ciphertext but the row carries no seal metadata; refusing to encrypt it twice",
				zap.String("session_id", j.id))
			continue
		}
		if sealErr != nil {
			h.logger.Warn("sealGuacRecordings: seal failed",
				zap.String("session_id", j.id), zap.Error(sealErr))
			continue
		}
		claimed, execErr := h.recordGuacSeal(ctx, j.id, j.orgID, sum, keyID)
		if execErr != nil {
			// The bytes are already encrypted on disk; if we can't persist the
			// metadata we log loudly. The row stays unsealed so a later tick
			// retries — but the file is now ciphertext, so retry re-reads it as
			// "plaintext", double-encrypting. To avoid that, treat a metadata
			// write failure as fatal for this file and surface it; operationally
			// this is extremely rare (same pool the SELECT just succeeded on).
			h.logger.Error("sealGuacRecordings: sealed bytes but metadata write FAILED — manual reconciliation needed",
				zap.String("session_id", j.id), zap.Error(execErr))
			continue
		}
		if !claimed {
			continue
		}
		sealed++
	}
	if sealed > 0 {
		h.logger.Info("sealGuacRecordings: sealed recordings", zap.Int("count", sealed))
	}
}

// sealOneGuacRecording reads the plaintext recording at path, computes its
// SHA-256, and rewrites it in place (atomically) as keyring-encrypted frames.
// Returns the hex digest of the ORIGINAL plaintext and the key id used.
//
// Atomicity: we write the sealed bytes to a sibling temp file and os.Rename it
// over the original only after a successful fsync+close. A crash mid-seal
// leaves the original plaintext intact (and the row still unsealed), so the
// next tick retries cleanly — never a half-encrypted, unplayable file.
func (h *RemoteSupportHandler) sealOneGuacRecording(path string) (string, byte, error) {
	src, err := h.openUnsealedRecording(path)
	if err != nil {
		return "", 0, err
	}
	defer src.Close()
	return h.sealFrom(src, path)
}

// openUnsealedRecording opens path ONCE and proves, on that same descriptor,
// that it holds plaintext.
//
// THE RACE THIS CLOSES, measured rather than reasoned about: the seal sweep
// runs in every replica, and two of them selected the same unsealed row. The
// old shape was probe-by-path, then open-by-path -- two separate open(2) calls
// on the same name. Between them the other replica's rename landed, so the
// second call resolved the NEW inode: the first replica's ciphertext. The probe
// had said "plaintext" about an inode that no longer sat behind the name, and
// the sealer encrypted ciphertext. On disk: seal(seal(plaintext)). One decrypt
// pass returned 32801 bytes for a 32768-byte session -- exactly one envelope
// too many -- in 1 of 60 runs on main. A recording that does not decrypt by the
// documented path is evidence an auditor cannot read.
//
// Binding the proof to the descriptor removes the window by construction: the
// bytes the probe authenticated are the bytes that will be encrypted, whatever
// happens to the directory entry in between. If the other replica renames
// after this open, this sealer encrypts the old (plaintext) inode and its
// rename replaces one valid single envelope with another valid single envelope
// of the same plaintext -- same digest, different nonces. The row claim
// (recordGuacSeal) then decides who announces; the file is sound either way.
func (h *RemoteSupportHandler) openUnsealedRecording(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if h.sealedFile(f, path) {
		_ = f.Close()
		return nil, errAlreadySealed
	}
	// The probe consumed the first frame's worth of bytes; the encrypt pass
	// has to start from zero or the recording loses its head.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// sealFrom encrypts an already-opened, already-proven-plaintext descriptor into
// a private temp file and renames it over path. It is split from
// sealOneGuacRecording so the interleaving that used to corrupt recordings can
// be driven deterministically in a test: open here, let another replica finish,
// then seal from the descriptor that was held.
func (h *RemoteSupportHandler) sealFrom(src *os.File, path string) (string, byte, error) {
	activeID := h.guacRecordingRing.ActiveID()
	master, err := h.guacRecordingRing.masterFor(activeID)
	if err != nil {
		return "", 0, err
	}
	// Session-scope the derived key by the file's stable base name so playback
	// (which derives from the same identifier) matches. We use the recording
	// file path's directory+name; the download path must pass the same id.
	sessionKey := guacRecordingSessionKey(path)
	aead, err := newRecordingAEAD(master, sessionKey)
	if err != nil {
		return "", 0, err
	}

	// A PRIVATE temp per sealer. The old name was path+".sealing" for every
	// replica, so two concurrent sealers opened the same temp with O_TRUNC:
	// each wiped the other's frames mid-write, and whichever renamed first
	// installed a file the other was still writing. CreateTemp gives each
	// sealer its own inode, so the only shared step left is the rename, and a
	// rename is atomic.
	dst, err := newSealTemp(path)
	if err != nil {
		return "", 0, err
	}
	tmp := dst.Name()
	// Best-effort cleanup of the temp file on any error path before rename.
	committed := false
	defer func() {
		if !committed {
			_ = dst.Close()
			_ = os.Remove(tmp)
		}
	}()

	hasher := sha256.New()
	buf := make([]byte, guacSealChunkBytes)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			plaintext := buf[:n]
			hasher.Write(plaintext)
			frame, ferr := aead.encryptChunk(activeID, plaintext)
			if ferr != nil {
				return "", 0, ferr
			}
			if _, werr := dst.Write(frame); werr != nil {
				return "", 0, werr
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", 0, rerr
		}
	}
	if syncErr := dst.Sync(); syncErr != nil {
		return "", 0, syncErr
	}
	if closeErr := dst.Close(); closeErr != nil {
		return "", 0, closeErr
	}
	if renameErr := os.Rename(tmp, path); renameErr != nil {
		return "", 0, renameErr
	}
	committed = true
	return hex.EncodeToString(hasher.Sum(nil)), activeID, nil
}

// guacRecordingSessionKey derives the HKDF session identifier for a guac
// recording file from its path. Stable across seal and playback so the derived
// per-recording key matches. We use the parent dir + base name so two files
// with the same base in different dirs don't share a key.
func guacRecordingSessionKey(path string) string {
	return filepath.Base(filepath.Dir(path)) + "/" + filepath.Base(path)
}

// sealedFile reports whether the open descriptor f already holds sealed frames,
// by decrypting its first frame through the very reader playback uses. A
// successful read is an AES-GCM authentication: the key id, the nonce and the
// tag all have to be right, so the answer is not a heuristic about how the
// bytes look. It takes the DESCRIPTOR, not the path, so that the answer is
// about the inode the caller is holding -- see openUnsealedRecording for the
// race that a path-based answer left open.
//
// False is the safe direction and every uncertain case returns it: an
// unreadable file, an empty one, a frame that does not authenticate. The caller
// then seals, which is what it would have done anyway. f's offset is advanced
// by the probe; the caller seeks back.
func (h *RemoteSupportHandler) sealedFile(f *os.File, path string) bool {
	if h.guacRecordingRing == nil || !h.guacRecordingRing.Enabled() {
		return false
	}
	r := newDecryptingReader(f, h.guacRecordingRing, guacRecordingSessionKey(path))
	var probe [1]byte
	n, err := r.Read(probe[:])
	return n > 0 && err == nil
}

// alreadySealed is the path form of sealedFile, for callers that only want the
// answer and are not about to encrypt. The sealer itself must not use it: a
// path answer and a later open are two lookups of one name.
func (h *RemoteSupportHandler) alreadySealed(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return h.sealedFile(f, path)
}

// newSealTemp creates this sealer's private temp file beside the recording.
func newSealTemp(path string) (*os.File, error) {
	return os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".sealing-*")
}

// guacRecordingPathSafe rejects empty paths, the recordings root itself, and
// any path that escapes the configured root — mirroring the purge sweep's
// guard so the sealer never reads or overwrites a file outside the root.
func (h *RemoteSupportHandler) guacRecordingPathSafe(path string) bool {
	if path == "" {
		return false
	}
	root := h.guacRecordingsRoot
	if root == "" {
		// No configured root to validate against: fail safe (don't seal).
		return false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	if absPath == absRoot {
		return false
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return false
	}
	if rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
		return false
	}
	return true
}

// auditGuacSeal writes the hash-chained audit event recording the seal event.
// The integrity hash (of the original plaintext) is captured so a later auditor
// can prove a decrypted recording matches what guacd originally wrote.
// recordGuacSeal stamps the seal metadata and announces it, and the stamp is
// also the CLAIM: `AND recording_sealed_at IS NULL` means the replica that
// records a seal is the one that announces it.
//
// It returns whether this caller claimed the session. False is not an error --
// another replica got there first, its write carries the digest and its audit
// event is the record.
//
// WHY THIS IS ITS OWN FUNCTION, AND THE TEST THAT MADE IT ONE. The claim lives
// on a path the sweep can no longer reach with two replicas and one recording:
// the sealer now refuses ciphertext, so the second replica returns before it
// ever gets here. A two-replica test therefore passes with the claim REMOVED --
// measured, not assumed; the mutation stayed green and the reason was that the
// refusal short-circuits first, not that the claim was doing anything.
//
// The claim still has a window of its own, which is why it stays: if the second
// replica reads the file BEFORE the first replica's rename, it seals the same
// plaintext, and both reach this line. The bytes are fine (the second rename
// wins, and both sealed the same plaintext, so both digests agree) but the
// announcement would be made twice. On a product where an auditor asks "when
// was this recording sealed, and under which key", two answers is a wrong one.
//
// So the unit is named and tested directly, rather than left as a line inside a
// sweep whose earlier guard hides it.
func (h *RemoteSupportHandler) recordGuacSeal(ctx context.Context, sessionID, orgID, sum string, keyID byte) (bool, error) {
	//orgscope:ignore background sweep; row identified by PK, org already fixed at insert
	tag, err := h.db.Pool.Exec(ctx, `
		UPDATE guacamole_sessions
		   SET recording_sealed_at = NOW(),
		       recording_sha256    = $1,
		       recording_key_id    = $2
		 WHERE id = $3 AND recording_sealed_at IS NULL`, sum, int(keyID), sessionID)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	h.auditGuacSeal(ctx, sessionID, orgID, sum, keyID)
	return true, nil
}

func (h *RemoteSupportHandler) auditGuacSeal(ctx context.Context, sessionID, orgID, sha256hex string, keyID byte) {
	details := fmt.Sprintf(`{"session_id":%q,"sha256":%q,"key_id":%d}`, sessionID, sha256hex, int(keyID))
	var org any
	if orgID != "" {
		org = orgID
	} else {
		org = nil
	}
	//orgscope:ignore audit_events stamped with the session's own org_id; background sweep has no request org
	if _, err := h.db.Pool.Exec(ctx, `
		INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, target_type, resource_id, details, created_at, org_id)
		VALUES (gen_random_uuid(), 'pam.recording.sealed', 'privileged_access', 'recording.seal', 'success', 'system', 'guacamole_session', $1, $2, NOW(), $3)`,
		sessionID, details, org); err != nil {
		h.logger.Warn("auditGuacSeal: audit insert failed", zap.Error(err))
	}
}
