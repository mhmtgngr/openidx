package access

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// A real guacd 1.6.0 SSH typescript: `mkdir -p /tmp/x; rm -rf /tmp/x`, a
// line typed `echx`, two backspaces, `o safe-line` (the shell ran `eco`), and
// `sudo -n true`. The scanner must see the lines as the terminal showed them.
func TestScanTypescriptRealGuacd(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "guacd-1.6.0-ssh-risky.typescript"))
	if err != nil {
		t.Fatal(err)
	}
	patterns := []string{`\brm\s+-[a-z]*r[a-z]*f`, `^\S+:\S*\$ sudo\b`, `echx`}
	res, err := compileRiskyCommandPatterns(patterns)
	if err != nil {
		t.Fatal(err)
	}
	m, total, truncated, err := scanTypescript(bytes.NewReader(b), patterns, res)
	if err != nil || truncated {
		t.Fatalf("scan: %v truncated=%v", err, truncated)
	}
	if total != 2 || len(m) != 2 {
		t.Fatalf("got %d matches %+v, want rm -rf and sudo", total, m)
	}
	if m[0].Pattern != patterns[0] || !strings.HasSuffix(m[0].Text, "$ mkdir -p /tmp/x; rm -rf /tmp/x") {
		t.Errorf("first match %+v", m[0])
	}
	if m[1].Pattern != patterns[1] || !strings.HasSuffix(m[1].Text, "$ sudo -n true") {
		t.Errorf("second match %+v", m[1])
	}
	// The erased text is not what the terminal showed.
	for _, x := range m {
		if strings.Contains(x.Text, "\x1b") || strings.Contains(x.Text, "\r") {
			t.Errorf("control bytes left in %q", x.Text)
		}
	}
}

func TestTerminalLineText(t *testing.T) {
	for in, want := range map[string]string{
		"\x1b[?2004hhost:~$ ls\r\n":      "host:~$ ls",
		"echx\b\x1b[K\b\x1b[Ko safe\r\n": "eco safe",
		"\x1b]0;title\x07pwd\n":          "pwd",
		"\x1b]0;title\x1b\\pwd\n":        "pwd",
		"a\tb\n":                         "a b",
		"çalış\n":                        "çalış",
		"\x1b(Bplain\n":                  "plain",
	} {
		if got := strings.TrimSpace(terminalLineText([]byte(in))); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestCompileRiskyCommandPatternsBounds(t *testing.T) {
	if _, err := compileRiskyCommandPatterns([]string{"("}); err == nil {
		t.Error("an invalid expression compiled")
	}
	if _, err := compileRiskyCommandPatterns([]string{"  "}); err == nil {
		t.Error("an empty pattern was accepted")
	}
	if _, err := compileRiskyCommandPatterns([]string{strings.Repeat("a", maxRiskyCommandPatternLen+1)}); err == nil {
		t.Error("an over-long pattern was accepted")
	}
	many := make([]string, maxRiskyCommandPatterns+1)
	for i := range many {
		many[i] = "x"
	}
	if _, err := compileRiskyCommandPatterns(many); err == nil {
		t.Error("too many patterns were accepted")
	}
	res, err := compileRiskyCommandPatterns([]string{"DROP TABLE"})
	if err != nil || !res[0].MatchString("psql> drop table users;") {
		t.Error("patterns are not case-insensitive")
	}
}

// The scan against the migrated schema: an ended recorded SSH session whose
// typescript has risky lines is warned once (audit with the lines, webhook
// with patterns and line numbers only), a sealed typescript is read through
// the keyring, a clean one is stamped 0 with no warning, a missing one is
// stamped NULL, and an org without patterns is not scanned at all.
func TestScanRiskyCommandsWarnsOnce(t *testing.T) {
	f := newExternalPamFixture(t)
	ctx := f.octx()
	root := t.TempDir()
	f.svc.config.GuacamoleRecordingPath = root
	hooks := &fakeWebhooks{}
	f.svc.webhooks = hooks
	ring := makeTestRing(t)
	f.svc.guacRecordingRing = ring

	risky, err := os.ReadFile(filepath.Join("testdata", "guacd-1.6.0-ssh-risky.typescript"))
	if err != nil {
		t.Fatal(err)
	}
	clean, err := os.ReadFile(filepath.Join("testdata", "guacd-1.6.0-ssh.typescript"))
	if err != nil {
		t.Fatal(err)
	}
	entry := f.entry("risky", "ssh", "direct", 22, `{}`)
	session := func(name string, ts []byte, ended string) string {
		t.Helper()
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		rec := filepath.Join(dir, "recording")
		if ts != nil {
			if err := os.WriteFile(rec+pamTypescriptSuffix, ts, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return f.scalar(`INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol, recording_path, status, started_at, ended_at)
			VALUES ($1, $2, $3, 'ssh', $4, 'ended', NOW() - interval '1 hour', NOW() - $5::interval) RETURNING id::text`,
			f.org, entry, f.operator, rec, ended)
	}
	plain := session("plain", risky, "10 minutes")
	sealed := session("sealed", risky, "10 minutes")
	ok := session("clean", clean, "10 minutes")
	none := session("none", nil, "10 minutes")
	settling := session("settling", risky, "30 seconds")

	// Seal one transcript as the sealer does, without stamping the row.
	h := &RemoteSupportHandler{logger: zap.NewNop(), guacRecordingRing: ring, guacRecordingsRoot: root}
	if _, _, err := h.sealOneGuacRecording(filepath.Join(root, "sealed", "recording"+pamTypescriptSuffix)); err != nil {
		t.Fatal(err)
	}

	// No patterns: nothing is scanned.
	f.svc.scanRiskyCommands(ctx)
	if n := f.scalar(`SELECT count(*)::text FROM pam_entry_sessions WHERE commands_scanned_at IS NOT NULL`); n != "0" {
		t.Fatalf("%s sessions scanned with no patterns", n)
	}

	f.exec(`INSERT INTO org_pam_policy (org_id, risky_command_patterns) VALUES ($1, ARRAY['rm\s+-rf', 'sudo\s'])
		ON CONFLICT (org_id) DO UPDATE SET risky_command_patterns = EXCLUDED.risky_command_patterns`, f.org)
	f.svc.scanRiskyCommands(ctx)
	f.svc.scanRiskyCommands(ctx) // a second tick warns nothing again

	count := func(id string) string {
		return f.scalar(`SELECT COALESCE(risky_command_count::text, 'null') || '/' || (commands_scanned_at IS NOT NULL)::text
			FROM pam_entry_sessions WHERE id = $1`, id)
	}
	for name, tc := range map[string]struct{ id, want string }{
		"plaintext": {plain, "2/true"},
		"sealed":    {sealed, "2/true"},
		"clean":     {ok, "0/true"},
		"missing":   {none, "null/true"},
		"settling":  {settling, "null/false"},
	} {
		if got := count(tc.id); got != tc.want {
			t.Errorf("%s: %s, want %s", name, got, tc.want)
		}
	}

	for _, id := range []string{plain, sealed} {
		ev := hooks.of("pam.session.risky_command", "session_id", id)
		if len(ev) != 1 {
			t.Fatalf("%d webhooks for %s, want 1", len(ev), id)
		}
		if ev[0].Org != f.org || ev[0].Bypass {
			t.Errorf("webhook under org %q bypass=%v", ev[0].Org, ev[0].Bypass)
		}
		lines, _ := ev[0].Payload["matches"].([]map[string]interface{})
		if len(lines) != 2 {
			t.Fatalf("webhook matches %#v", ev[0].Payload["matches"])
		}
		for _, l := range lines {
			if _, has := l["text"]; has {
				t.Error("the webhook carries transcript text")
			}
		}
		var audited int
		var text string
		if err := f.db.Pool.QueryRow(context.Background(), `SELECT count(*), COALESCE(max(details->'matches'->0->>'text'), '')
			FROM unified_audit_events WHERE event_type = 'pam.risky_command' AND details->>'session_id' = $1`, id).Scan(&audited, &text); err != nil {
			t.Fatal(err)
		}
		if audited != 1 || !strings.Contains(text, "rm -rf /tmp/x") {
			t.Errorf("%s: %d audit events, first line %q", id, audited, text)
		}
	}
	if n := len(hooks.of("pam.session.risky_command", "session_id", ok)); n != 0 {
		t.Error("a clean session was warned about")
	}

	// Two replicas that both listed the same session: one claim lands.
	race := session("race", risky, "10 minutes")
	two := 2
	first, err1 := f.svc.claimRiskyCommandScan(ctx, race, f.org, &two)
	second, err2 := f.svc.claimRiskyCommandScan(ctx, race, f.org, &two)
	if err1 != nil || err2 != nil || !first || second {
		t.Errorf("claims: %v %v (%v %v), want exactly the first", first, second, err1, err2)
	}
	// Another organization cannot claim it.
	if got, _ := f.svc.claimRiskyCommandScan(ctx, settling, "00000000-0000-0000-0000-000000000001", &two); got {
		t.Error("a claim under another org landed")
	}
}
