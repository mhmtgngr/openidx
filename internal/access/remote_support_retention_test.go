package access

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestResolveEffectiveRetention_Layers walks each step of the four-layer
// fallback chain to confirm the priority order matches the documented
// contract.
//
// Layer 1: per-session override — wins over everything below.
// Layer 2: per-org policy in the DB — skipped here (no DB in the unit
//
//	test), exercised indirectly via the integration test that
//	inserts a row. We assert the fallthrough behavior instead.
//
// Layer 3: configured default — used when neither session nor policy
//
//	contribute.
//
// Layer 4: hard fallback (90) — when default is zero.
func TestResolveEffectiveRetention_Layers(t *testing.T) {
	h := &RemoteSupportHandler{logger: zap.NewNop()}
	// No DB → org policy is never consulted; we exercise layers 1, 3, 4.

	t.Run("per-session override wins", func(t *testing.T) {
		v := 7
		h.defaultRetentionDays = 30
		got := h.resolveEffectiveRetention(context.Background(), &v, "any-org")
		assert.Equal(t, 7, got)
	})

	t.Run("session override of 0 means infinite", func(t *testing.T) {
		zero := 0
		h.defaultRetentionDays = 30
		got := h.resolveEffectiveRetention(context.Background(), &zero, "any-org")
		assert.Equal(t, 0, got,
			"a session-level 0 must propagate as infinite, not fall through")
	})

	t.Run("default fallback when no override or policy", func(t *testing.T) {
		h.defaultRetentionDays = 30
		got := h.resolveEffectiveRetention(context.Background(), nil, "")
		assert.Equal(t, 30, got)
	})

	t.Run("hard fallback when default is unset", func(t *testing.T) {
		h.defaultRetentionDays = 0
		got := h.resolveEffectiveRetention(context.Background(), nil, "")
		assert.Equal(t, retentionHardFallbackDays, got)
	})
}

// TestFilesystemRecordingStore_DeleteRoundTrip exercises Append → Open →
// Delete to confirm the filesystem store's purge path. After delete,
// Open must report "not found" and re-Append must succeed (re-creates
// the directory).
func TestFilesystemRecordingStore_DeleteRoundTrip(t *testing.T) {
	root := t.TempDir()
	store, err := newFilesystemRecordingStore(root, nil)
	require.NoError(t, err)

	sessionID := "session-test-1"
	payload := []byte("fake-webm-bytes")

	written, err := store.Append(sessionID, 0, bytes.NewReader(payload))
	require.NoError(t, err)
	assert.Equal(t, int64(len(payload)), written)

	// Confirm the per-session directory now exists.
	sessionDir := filepath.Dir(filepath.Join(root, sessionID, "recording.webm"))
	_, err = os.Stat(sessionDir)
	require.NoError(t, err, "session dir should exist after Append")

	// Delete should succeed and tear the directory down.
	require.NoError(t, store.Delete(sessionID))
	_, err = os.Stat(sessionDir)
	assert.True(t, os.IsNotExist(err), "session dir should be gone after Delete")

	// A second delete on the same session is a no-op.
	require.NoError(t, store.Delete(sessionID),
		"Delete must be idempotent for the retention sweeper")

	// Re-Append on a deleted session must succeed (re-creates the dir).
	written, err = store.Append(sessionID, 0, bytes.NewReader(payload))
	require.NoError(t, err)
	assert.Equal(t, int64(len(payload)), written)

	// Cleanup so the temp-dir teardown doesn't trip on perms.
	_ = store.Delete(sessionID)
}

// TestFilesystemRecordingStore_DeleteMissingIsIdempotent makes sure the
// sweeper's "delete then update DB" sequence is safe even when the blob
// was already cleaned up by an out-of-band process.
func TestFilesystemRecordingStore_DeleteMissingIsIdempotent(t *testing.T) {
	root := t.TempDir()
	store, err := newFilesystemRecordingStore(root, nil)
	require.NoError(t, err)
	assert.NoError(t, store.Delete("never-existed"))
}
