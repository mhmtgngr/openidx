package access

import (
	"testing"
)

// TestIsUnderRoot covers the data-loss guard used by purgeGuacRecording to
// ensure it never calls os.RemoveAll on the recordings root itself or on a
// path that escapes the root.
//
// The recording-path join (filepath.Join(recPath, recName) in
// handleGuacamoleConnect) and the transcript-path derivation
// (recordingPath+".txt" in purgeGuacRecording) are both inline in
// handler/method bodies that are DB/exec-bound, so they are not extracted as
// pure functions and are therefore skipped here per the task brief.  The
// live-set key (ConnectionIdentifier+"|"+Username) inside
// detectEndedGuacSessions is likewise inline.  Only isUnderRoot is a pure
// exported-free helper and is tested below.
func TestIsUnderRoot(t *testing.T) {
	t.Parallel()

	root := "/var/lib/openidx/recordings/guacamole"

	cases := []struct {
		name string
		p    string
		root string
		want bool
	}{
		// --- strictly inside root: expected true ---
		{
			name: "file directly under root",
			p:    "/var/lib/openidx/recordings/guacamole/conn-123-1234567890",
			root: root,
			want: true,
		},
		{
			name: "file one subdirectory deeper",
			p:    "/var/lib/openidx/recordings/guacamole/sessions/conn-456",
			root: root,
			want: true,
		},
		{
			name: "transcript (.txt) file under root",
			p:    "/var/lib/openidx/recordings/guacamole/conn-789-9999.txt",
			root: root,
			want: true,
		},
		{
			name: "path with trailing slash on p normalises to inside",
			p:    "/var/lib/openidx/recordings/guacamole/conn-1/",
			root: root,
			want: true,
		},

		// --- p equals root: must be false (prevents RemoveAll of root) ---
		{
			name: "p equals root exactly",
			p:    root,
			root: root,
			want: false,
		},
		{
			name: "p equals root with trailing slash",
			p:    root + "/",
			root: root,
			want: false,
		},

		// --- p is a parent of root: must be false ---
		{
			name: "p is parent directory of root",
			p:    "/var/lib/openidx/recordings",
			root: root,
			want: false,
		},
		{
			name: "p is /var/lib",
			p:    "/var/lib",
			root: root,
			want: false,
		},
		{
			name: "p is filesystem root /",
			p:    "/",
			root: root,
			want: false,
		},

		// --- sibling/prefix confusion: must be false ---
		{
			name: "sibling directory with same prefix (recordings2 ≠ under recordings)",
			p:    "/var/lib/openidx/recordings/guacamole2/conn-123",
			root: "/var/lib/openidx/recordings/guacamole",
			want: false,
		},
		{
			name: "sibling that shares a long common prefix",
			p:    "/var/lib/openidx/recordings/guacamolebad/conn-1",
			root: root,
			want: false,
		},

		// --- path traversal / escape via ".." ---
		{
			name: "traversal via .. escapes root",
			p:    "/var/lib/openidx/recordings/guacamole/../../../etc/passwd",
			root: root,
			want: false,
		},
		{
			name: "traversal that lands exactly at root",
			p:    "/var/lib/openidx/recordings/guacamole/subdir/../..",
			root: root,
			want: false,
		},
		{
			name: "traversal that stays inside root after clean",
			p:    "/var/lib/openidx/recordings/guacamole/subdir/../conn-1",
			root: root,
			want: true,
		},

		// --- empty inputs: must be false ---
		{
			name: "empty p",
			p:    "",
			root: root,
			want: false,
		},
		{
			name: "empty root",
			p:    "/var/lib/openidx/recordings/guacamole/conn-1",
			root: "",
			want: false,
		},
		{
			name: "both empty",
			p:    "",
			root: "",
			want: false,
		},

		// --- root with trailing slash: Clean normalises it ---
		{
			name: "root with trailing slash still works",
			p:    "/var/lib/openidx/recordings/guacamole/conn-1",
			root: root + "/",
			want: true,
		},

		// --- completely unrelated paths ---
		{
			name: "completely unrelated path",
			p:    "/tmp/evil",
			root: root,
			want: false,
		},
		{
			name: "p is /etc/passwd",
			p:    "/etc/passwd",
			root: root,
			want: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isUnderRoot(tc.p, tc.root)
			if got != tc.want {
				t.Errorf("isUnderRoot(%q, %q) = %v, want %v", tc.p, tc.root, got, tc.want)
			}
		})
	}
}
