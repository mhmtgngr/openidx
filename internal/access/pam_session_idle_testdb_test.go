package access

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real guacd 1.6.0 SSH recordings (recording-include-keys=true), 30 s each:
// "active" typed `ls` 3 s before the end, "idle" typed it 3 s after the start
// and nothing after. The scanner must read the input timestamps off guacd's
// own clock.
func TestScanRecordingActivityRealGuacd(t *testing.T) {
	for name, want := range map[string][2]time.Duration{
		"active": {2 * time.Second, 5 * time.Second},
		"idle":   {25 * time.Second, 29 * time.Second},
	} {
		b, err := os.ReadFile(filepath.Join("testdata", "guacd-ssh-"+name+".rec"))
		if err != nil {
			t.Fatal(err)
		}
		a := scanRecordingActivity(b, true)
		if a.LastInput == 0 {
			t.Fatalf("%s: no input found", name)
		}
		got, known := a.idleFor(true)
		if !known || got < want[0] || got > want[1] {
			t.Errorf("%s: idle %v (known %v), want %v..%v", name, got, known, want[0], want[1])
		}
		// A tail cut mid-instruction and mid-file still parses to the same
		// answer as long as the input is in it.
		cut := b[len(b)/3 : len(b)-7]
		if c := scanRecordingActivity(cut, false); c.LastInput != a.LastInput && name == "active" {
			t.Errorf("%s: truncated tail lost the input (%d vs %d)", name, c.LastInput, a.LastInput)
		}
	}
}

func TestIdleForNeedsEvidence(t *testing.T) {
	// No input in a partial tail: cannot tell, whatever the gap.
	if _, known := (recordingActivity{FirstSync: 1, LastSync: 10_000_000}).idleFor(false); known {
		t.Error("a partial tail without input was judged")
	}
	// No input in the whole recording: idle since the start.
	if d, known := (recordingActivity{FirstSync: 1000, LastSync: 61_000}).idleFor(true); !known || d != time.Minute {
		t.Errorf("whole recording without input: %v %v", d, known)
	}
	// Nothing parsed.
	if _, known := (recordingActivity{}).idleFor(true); known {
		t.Error("an empty recording was judged")
	}
}

// synthRecording writes a recording whose syncs run from 0 to span on
// guacd's clock with one keystroke at lastKey (negative: none).
func synthRecording(t *testing.T, path string, span, lastKey time.Duration) {
	t.Helper()
	const base = int64(2494861086)
	var sb strings.Builder
	el := func(s string) string { return fmt.Sprintf("%d.%s", len(s), s) }
	for ms := int64(0); ms <= span.Milliseconds(); ms += 30_000 {
		if lastKey >= 0 && ms <= lastKey.Milliseconds() && ms+30_000 > lastKey.Milliseconds() {
			ts := fmt.Sprint(base + lastKey.Milliseconds())
			sb.WriteString(el("key") + "," + el("108") + "," + el("1") + "," + el(ts) + ";")
		}
		sb.WriteString(el("sync") + "," + el(fmt.Sprint(base+ms)) + "," + el("0") + ";")
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The idle sweep against the migrated schema and the fake broker: with a
// 15-minute policy, a session whose recording shows 20 idle minutes is ended
// (reason idle_timeout, audited, broker kill), one with recent input, one
// without a recording file, one whose recording lies outside the recording
// root, and one in an org with the timeout off are kept.
func TestIdlePamEntrySessionsEnd(t *testing.T) {
	f := newExternalPamFixture(t)
	ctx := f.octx()
	root := t.TempDir()
	f.svc.config.GuacamoleRecordingPath = root
	f.exec(`INSERT INTO org_pam_policy (org_id, idle_timeout_minutes) VALUES ($1, 15)
		ON CONFLICT (org_id) DO UPDATE SET idle_timeout_minutes = 15`, f.org)
	entry := f.entry("idle", "ssh", "direct", 22, `{}`)
	session := func(conn, rec string) string {
		t.Helper()
		return f.scalar(`INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol, guac_connection_id, guac_username, recording_path, started_at)
			VALUES ($1, $2, $3, 'ssh', $4, $4, $5, NOW() - interval '1 hour') RETURNING id::text`,
			f.org, entry, f.operator, conn, rec)
	}
	status := func(id string) string {
		return f.scalar(`SELECT status FROM pam_entry_sessions WHERE id = $1`, id)
	}
	idlePath := filepath.Join(root, "idle")
	busyPath := filepath.Join(root, "busy")
	synthRecording(t, idlePath, 40*time.Minute, 20*time.Minute) // 20 min without input
	synthRecording(t, busyPath, 40*time.Minute, 38*time.Minute) // 2 min
	outside := filepath.Join(t.TempDir(), "outside")
	synthRecording(t, outside, 40*time.Minute, time.Minute)

	idle := session("c1", idlePath)
	busy := session("c2", busyPath)
	missing := session("c3", filepath.Join(root, "not-written-yet"))
	escaped := session("c4", outside)

	f.svc.endIdlePamEntrySessions(ctx)
	for name, tc := range map[string]struct{ id, want string }{
		"idle":         {idle, "ended"},
		"recent input": {busy, "active"},
		"no recording": {missing, "active"},
		"outside root": {escaped, "active"},
	} {
		if got := status(tc.id); got != tc.want {
			t.Errorf("%s: %s, want %s", name, got, tc.want)
		}
	}
	var audited int
	if err := f.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM unified_audit_events
		WHERE event_type = 'pam.session_ended' AND details->>'reason' = 'idle_timeout'
		  AND details->>'session_id' = $1`, idle).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Errorf("%d idle ends audited, want 1", audited)
	}

	// Timeout off: nothing is judged.
	synthRecording(t, busyPath, 40*time.Minute, 5*time.Minute)
	f.exec(`UPDATE org_pam_policy SET idle_timeout_minutes = 0 WHERE org_id = $1`, f.org)
	f.svc.endIdlePamEntrySessions(ctx)
	if status(busy) != "active" {
		t.Error("a session was ended with the idle timeout off")
	}
	// On again: the now-idle session goes.
	f.exec(`UPDATE org_pam_policy SET idle_timeout_minutes = 15 WHERE org_id = $1`, f.org)
	f.svc.endIdlePamEntrySessions(ctx)
	if status(busy) != "ended" {
		t.Error("a session idle for 35 minutes under a 15-minute policy is still active")
	}
}
