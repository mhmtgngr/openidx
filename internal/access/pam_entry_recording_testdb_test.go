package access

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// An entry session's recording, end to end on the migrated schema: the sweep
// leaves an active session alone, seals an ended one in place (the bytes on
// disk are no longer the plaintext, the row carries the plaintext's digest,
// one seal is announced), the admin download returns the original bytes, the
// retention sweep removes the file once the session is older than the
// organization keeps recordings and the download then answers 410, and a
// recording a route session also names is left to the route path.
func TestPamEntryRecordingIsSealedServedAndPurged(t *testing.T) {
	f := newExternalPamFixture(t)
	ctx := orgctx.WithBypassRLS(context.Background())
	root := t.TempDir()
	f.svc.config.GuacamoleRecordingPath = root
	ring := makeTestRing(t)
	f.svc.guacRecordingRing = ring
	h := &RemoteSupportHandler{logger: zap.NewNop(), db: f.db, guacRecordingRing: ring, guacRecordingsRoot: root}

	entry := f.entry("rec", "ssh", "direct", 22, `{}`)
	recording := func(name string) (string, []byte) {
		t.Helper()
		p := filepath.Join(root, name)
		b := make([]byte, 3*guacSealChunkBytes/2) // more than one frame
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p, b
	}
	session := func(status, path string) string {
		return f.scalar(`INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol, guac_connection_id, recording_path, status, ended_at)
			VALUES ($1, $2, $3, 'ssh', 'c9', $4, $5::text, CASE WHEN $5::text = 'active' THEN NULL ELSE NOW() END) RETURNING id::text`,
			f.org, entry, f.operator, path, status)
	}

	livePath, livePlain := recording("pam-live")
	endedPath, endedPlain := recording("pam-ended")
	live := session("active", livePath)
	ended := session("ended", endedPath)

	h.sealPamEntryRecordings(ctx)
	h.sealPamEntryRecordings(ctx) // a second tick changes nothing

	if b, _ := os.ReadFile(livePath); string(b) != string(livePlain) {
		t.Error("a live session's recording was touched")
	}
	if b, _ := os.ReadFile(endedPath); string(b) == string(endedPlain) {
		t.Fatal("the ended session's recording is still plaintext on disk")
	}
	sum := sha256.Sum256(endedPlain)
	if got := f.scalar(`SELECT COALESCE(recording_sha256,'') FROM pam_entry_sessions WHERE id = $1`, ended); got != hex.EncodeToString(sum[:]) {
		t.Errorf("recording_sha256 %q is not the plaintext's digest", got)
	}
	if n := f.scalar(`SELECT count(*)::text FROM audit_events WHERE event_type = 'pam.recording.sealed' AND resource_id = $1`, ended); n != "1" {
		t.Errorf("%s seal announcements, want 1", n)
	}

	download := func(id string, roles ...string) *httptest.ResponseRecorder {
		t.Helper()
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: f.org}))
			c.Set("user_id", f.admin)
			c.Set("roles", roles)
			c.Next()
		})
		r.GET("/pam/sessions/:id/recording", f.svc.requireAdminRole(), f.svc.handlePamEntryRecording)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/pam/sessions/"+id+"/recording", nil))
		return w
	}
	if w := download(ended, "user"); w.Code != http.StatusForbidden {
		t.Errorf("a non-admin download: %d, want 403", w.Code)
	}
	w := download(ended, "admin")
	if w.Code != http.StatusOK || w.Body.String() != string(endedPlain) {
		t.Fatalf("admin download: %d, %d bytes, want 200 and the original %d bytes", w.Code, w.Body.Len(), len(endedPlain))
	}
	if !f.audit.has("pam.recording_downloaded", "success", map[string]interface{}{"session_id": ended, "sealed": true}) {
		t.Error("the download was not audited")
	}

	// Retention: the default keeps 90 days.
	f.exec(`UPDATE pam_entry_sessions SET ended_at = NOW() - interval '10 days' WHERE id = $1`, ended)
	h.sweepExpiredPamEntryRecordings(ctx)
	if _, err := os.Stat(endedPath); err != nil {
		t.Fatal("a 10-day-old recording was purged under a 90-day retention")
	}
	f.exec(`UPDATE pam_entry_sessions SET ended_at = NOW() - interval '91 days' WHERE id = $1`, ended)
	h.sweepExpiredPamEntryRecordings(ctx)
	if _, err := os.Stat(endedPath); !os.IsNotExist(err) {
		t.Fatalf("a 91-day-old recording is still on disk: %v", err)
	}
	if w := download(ended, "admin"); w.Code != http.StatusGone {
		t.Errorf("download after purge: %d, want 410", w.Code)
	}

	// A recording a route session also names belongs to the route path.
	routePath, routePlain := recording("route-shared")
	shared := session("ended", routePath)
	conn := f.scalar(`INSERT INTO guacamole_connections (org_id, route_id, guacamole_connection_id, protocol, hostname, port)
		VALUES ($1, NULL, 'gc-shared', 'ssh', 'h', 22) RETURNING id::text`, f.org)
	f.exec(`INSERT INTO guacamole_sessions (org_id, connection_id, recording_path, status) VALUES ($1, $2, $3, 'ended')`, f.org, conn, routePath)
	h.sealPamEntryRecordings(ctx)
	if b, _ := os.ReadFile(routePath); string(b) != string(routePlain) {
		t.Error("the entry sweep sealed a recording the route path owns")
	}
	if f.scalar(`SELECT (recording_sealed_at IS NULL)::text FROM pam_entry_sessions WHERE id = $1`, shared) != "true" {
		t.Error("the entry row of a route recording was stamped sealed")
	}
	if f.scalar(`SELECT status FROM pam_entry_sessions WHERE id = $1`, live) != "active" {
		t.Error("the live session's row changed")
	}
}
