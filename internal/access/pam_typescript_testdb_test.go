package access

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

func TestPamTypescriptParams(t *testing.T) {
	p := map[string]string{}
	pamTypescriptParams(p, "ssh", true, "/rec", "pam-e-1")
	if p["typescript-path"] != "/rec" || p["typescript-name"] != "pam-e-1.typescript" {
		t.Errorf("recorded ssh: %v", p)
	}
	if _, ok := p["create-typescript-path"]; ok {
		t.Error("the typescript must not create directories; it lives in the recording's own")
	}
	for name, tc := range map[string]struct {
		proto  string
		record bool
		path   string
	}{
		"not recorded":       {"ssh", false, "/rec"},
		"rdp":                {"rdp", true, "/rec"},
		"no recordings root": {"ssh", true, ""},
	} {
		p := map[string]string{}
		pamTypescriptParams(p, tc.proto, tc.record, tc.path, "n")
		if len(p) != 0 {
			t.Errorf("%s: %v", name, p)
		}
	}
	// A stored setting cannot point it anywhere.
	q := buildPamGuacParams("password", "u", "", []byte("x"),
		map[string]interface{}{"typescript-path": "/etc", "typescript-name": "x"}, false, "", "")
	if _, ok := q["typescript-path"]; ok {
		t.Error("a setting set typescript-path")
	}
}

// An SSH session's text transcript, with a real guacd 1.6.0 typescript
// (testdata: a session that ran `echo SECRET-MARKER-42; ls /`): sealed with
// the recording so the marker is no longer readable on disk, the recording is
// stamped only then, the admin download returns the original text, and the
// retention purge removes it with the recording.
func TestPamEntryTypescriptSealedServedAndPurged(t *testing.T) {
	f := newExternalPamFixture(t)
	ctx := orgctx.WithBypassRLS(context.Background())
	root := t.TempDir()
	f.svc.config.GuacamoleRecordingPath = root
	ring := makeTestRing(t)
	f.svc.guacRecordingRing = ring
	h := &RemoteSupportHandler{logger: zap.NewNop(), db: f.db, guacRecordingRing: ring, guacRecordingsRoot: root}

	rec := filepath.Join(root, "pam-ssh")
	if err := os.WriteFile(rec, []byte("4.size,1.0,3.640,3.480;4.sync,4.1000;"), 0o600); err != nil {
		t.Fatal(err)
	}
	typescript, _ := os.ReadFile("testdata/guacd-1.6.0-ssh.typescript")
	timing, _ := os.ReadFile("testdata/guacd-1.6.0-ssh.typescript.timing")
	if !bytes.Contains(typescript, []byte("SECRET-MARKER-42")) {
		t.Fatal("testdata typescript lacks its marker")
	}
	files := pamTypescriptFiles(rec)
	_ = os.WriteFile(files[0], typescript, 0o600)
	_ = os.WriteFile(files[1], timing, 0o600)

	entry := f.entry("ts", "ssh", "direct", 22, `{}`)
	id := f.scalar(`INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol, guac_connection_id, recording_path, status, ended_at)
		VALUES ($1, $2, $3, 'ssh', 'c1', $4, 'ended', NOW()) RETURNING id::text`, f.org, entry, f.operator, rec)

	h.sealPamEntryRecordings(ctx)
	for _, p := range append([]string{rec}, files...) {
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte("SECRET-MARKER-42")) || bytes.Contains(b, []byte("4.size,")) || bytes.Equal(b, timing) {
			t.Errorf("%s is still plaintext on disk", filepath.Base(p))
		}
	}
	if f.scalar(`SELECT (recording_sealed_at IS NOT NULL)::text FROM pam_entry_sessions WHERE id = $1`, id) != "true" {
		t.Fatal("the recording was not stamped sealed")
	}

	get := func(path string, roles ...string) *httptest.ResponseRecorder {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: f.org}))
			c.Set("user_id", f.admin)
			c.Set("roles", roles)
		})
		r.GET("/pam/sessions/:id/typescript", f.svc.requireAdminRole(), f.svc.handlePamEntryTypescript)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	if w := get("/pam/sessions/"+id+"/typescript", "user"); w.Code != http.StatusForbidden {
		t.Errorf("non-admin: %d, want 403", w.Code)
	}
	w := get("/pam/sessions/"+id+"/typescript", "admin")
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), typescript) {
		t.Fatalf("admin download: %d, %d bytes, want the original %d", w.Code, w.Body.Len(), len(typescript))
	}
	if !f.audit.has("pam.typescript_downloaded", "success", map[string]interface{}{"session_id": id, "sealed": true}) {
		t.Error("the download was not audited")
	}

	f.exec(`UPDATE pam_entry_sessions SET ended_at = NOW() - interval '91 days' WHERE id = $1`, id)
	h.sweepExpiredPamEntryRecordings(ctx)
	for _, p := range append([]string{rec}, files...) {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived the purge", filepath.Base(p))
		}
	}
	if w := get("/pam/sessions/"+id+"/typescript", "admin"); w.Code != http.StatusGone {
		t.Errorf("after purge: %d, want 410", w.Code)
	}

	// An RDP session has no typescript: the sweep still seals its recording.
	rdp := filepath.Join(root, "pam-rdp")
	_ = os.WriteFile(rdp, []byte("4.size,1.0,3.640,3.480;4.sync,4.1000;"), 0o600)
	rid := f.scalar(`INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol, guac_connection_id, recording_path, status, ended_at)
		VALUES ($1, $2, $3, 'rdp', 'c2', $4, 'ended', NOW()) RETURNING id::text`, f.org, entry, f.operator, rdp)
	h.sealPamEntryRecordings(ctx)
	if f.scalar(`SELECT (recording_sealed_at IS NOT NULL)::text FROM pam_entry_sessions WHERE id = $1`, rid) != "true" {
		t.Error("a recording with no typescript was not sealed")
	}
	if w := get("/pam/sessions/"+rid+"/typescript", "admin"); w.Code != http.StatusNotFound {
		t.Errorf("an RDP session's typescript: %d, want 404", w.Code)
	}
}
