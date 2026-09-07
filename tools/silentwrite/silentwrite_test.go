package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The gate's rule, checked against source written here rather than against the
// tree, so a clean tree cannot make these vacuous.
func TestWhatCountsAsASilentWrite(t *testing.T) {
	cases := []struct {
		name  string
		src   string
		want  int
		other string // "cleared" or "nonwrite" when the site should land there
		why   string
	}{
		{
			name: "an UPDATE with both results dropped",
			src: `package p
func f() {
	_, _ = pool.Exec(ctx, "UPDATE users SET x = 1 WHERE id = $1", id)
}`,
			want: 1,
			why:  "this is the shape the gate exists for",
		},
		{
			name: "the call standing alone as a statement",
			src: `package p
func f() {
	pool.Exec(ctx, "DELETE FROM users WHERE id = $1", id)
}`,
			want: 1,
			why:  "both results dropped, just spelled differently",
		},
		{
			name: "the error is bound",
			src: `package p
func f() error {
	_, err := pool.Exec(ctx, "INSERT INTO users (id) VALUES ($1)", id)
	return err
}`,
			want: 0,
			why:  "a bound error is not discarded; proving it unread would need flow analysis, and guessing would report working code",
		},
		{
			name: "checked inline",
			src: `package p
func f() {
	if _, err := pool.Exec(ctx, "UPDATE users SET x = 1"); err != nil {
		return
	}
}`,
			want: 0,
			why:  "the idiomatic check",
		},
		{
			name: "a SET is session setup, not a write",
			src: `package p
func f() {
	_, _ = pool.Exec(ctx, "SET LOCAL app.org_id = 'x'")
}`,
			want:  0,
			other: "nonwrite",
			why:   "failing on these would bury the writes in noise",
		},
		{
			name: "a SELECT through Exec is not a write",
			src: `package p
func f() {
	_, _ = pool.Exec(ctx, "SELECT set_config('app.bypass_rls','on',false)")
}`,
			want:  0,
			other: "nonwrite",
			why:   "same reason",
		},
		{
			name: "a statement built elsewhere is not judged",
			src: `package p
func f() {
	_, _ = pool.Exec(ctx, query, args...)
}`,
			want: 0,
			why:  "the gate reads literals only; what it cannot read it must not judge",
		},
		{
			name: "a reason above the call clears it",
			src: `package p
func f() {
	//silentwrite:ok a stale last_seen_at costs a wrong "last active" column and
	//silentwrite:ok nothing else; the session row itself is authoritative.
	_, _ = pool.Exec(ctx, "UPDATE users SET last_seen_at = NOW() WHERE id = $1", id)
}`,
			want:  0,
			other: "cleared",
			why:   "the marker is the whole escape hatch",
		},
		{
			name: "a reason too short to be a reason",
			src: `package p
func f() {
	//silentwrite:ok best effort
	_, _ = pool.Exec(ctx, "UPDATE users SET last_seen_at = NOW() WHERE id = $1", id)
}`,
			want: 1,
			why:  "\"best effort\" restates the shape without saying what is lost, which is the one thing a reader cannot work out alone",
		},
		{
			name: "a marker several statements up does not reach",
			src: `package p
func f() {
	//silentwrite:ok this reason belongs to the write below it and to no other,
	//silentwrite:ok which is why the run has to be adjacent to the call.
	_, _ = pool.Exec(ctx, "UPDATE a SET x = 1")
	doSomething()
	anotherThing()
	somethingElse()
	yetMore()
	andMore()
	_, _ = pool.Exec(ctx, "DELETE FROM b WHERE id = $1", id)
}`,
			want: 1,
			why:  "a marker that drifted upward would come to cover writes it was never written about",
		},
		{
			name: "a CTE still reads as its write",
			src: `package p
func f() {
	_, _ = pool.Exec(ctx, "WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x")
}`,
			want: 1,
			why:  "the leading WITH must not hide the INSERT behind it",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "x.go")
			if err := os.WriteFile(path, []byte(c.src), 0o600); err != nil {
				t.Fatal(err)
			}
			findings, cleared, nonWrites, err := scanFile(path)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if len(findings) != c.want {
				t.Errorf("found %d finding(s), want %d — %s", len(findings), c.want, c.why)
			}
			switch c.other {
			case "cleared":
				if cleared != 1 {
					t.Errorf("cleared = %d, want 1 — a marked write must be counted as marked, not merely not reported", cleared)
				}
			case "nonwrite":
				if nonWrites != 1 {
					t.Errorf("nonWrites = %d, want 1 — %s", nonWrites, c.why)
				}
			}
		})
	}
}

func TestTheReportNamesTheTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.go")
	src := `package p
func f() {
	_, _ = pool.Exec(ctx, "UPDATE access_requests SET status='expired' WHERE id=$1", id)
}`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, _, _, err := scanFile(path)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("found %d findings, want 1", len(findings))
	}
	if findings[0].Verb != "UPDATE" || findings[0].Table != "access_requests" {
		t.Errorf("reported %q %q, want UPDATE access_requests — a report that does not say which table was "+
			"touched sends the reader back to the file to find out what is at stake",
			findings[0].Verb, findings[0].Table)
	}
}

// The classifier, on the three verbs and on what must not be one.
func TestClassify(t *testing.T) {
	cases := map[string]string{
		"INSERT INTO t (a) VALUES (1)":               "INSERT",
		"  \n\t UPDATE t SET a = 1":                  "UPDATE",
		"DELETE FROM t WHERE id = 1":                 "DELETE",
		"insert into t (a) values (1)":               "INSERT",
		"SELECT 1":                                   "",
		"SET LOCAL app.org_id = 'x'":                 "",
		"-- a leading comment\nUPDATE t SET a = 1":   "UPDATE",
		"WITH c AS (SELECT 1) DELETE FROM t":         "DELETE",
		"CREATE TABLE t (a int)":                     "",
		"SELECT set_config('app.bypass_rls','on',0)": "",
	}
	for sql, want := range cases {
		if got, _ := classify(sql); got != want {
			t.Errorf("classify(%q) = %q, want %q", sql, got, want)
		}
	}
}

// The real run, over the real tree. This is the one that goes red when a new
// write lands with its error dropped and no word about why.
func TestNoWriteIsSilentWithoutAReason(t *testing.T) {
	root := filepath.Join("..", "..")
	var findings []finding
	scanned := 0

	for _, dir := range []string{"internal", "cmd", "pkg"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				switch info.Name() {
				case ".git", "node_modules", "vendor", "third_party", "web", "client", "agent", "docs":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			scanned++
			f, _, _, ferr := scanFile(path)
			if ferr != nil {
				return nil
			}
			findings = append(findings, f...)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d file(s); the walk is looking in the wrong place and every assertion below "+
			"would pass vacuously", scanned)
	}

	// THE RATCHET. The tree had 137 of these when this gate was written. The
	// fixes so far -- the invitation acceptance, the approval-chain builder, the
	// directory sync that replaced a group's membership without checking either
	// half, the remote-support refusal that did not end the session, and the
	// device-trust approval that left the device untrusted -- have taken it to
	// the number below. Every site still in it has
	// to be read and then either fixed or given a reason; until that is done, a
	// bare count is what keeps the number from going back up.
	//
	// A count is a weaker guard than a per-site register, and it is worth saying
	// why rather than pretending otherwise: it cannot tell a site that was fixed
	// from one that was swapped for a new one somewhere else. It is here because
	// the alternative -- landing the gate only once all 128 carry a verdict --
	// leaves the tree unguarded in the meantime, and because the number can only
	// go down, so the register it becomes is the empty one.
	const backlog = 71

	var lines []string
	for _, f := range findings {
		lines = append(lines, f.File+":"+itoa(f.Line)+"  "+f.Verb+" "+f.Table)
	}

	if len(findings) > backlog {
		t.Errorf("%d write(s) change the database and cannot tell whether they did, up from %d. A new one has "+
			"landed. Handle the error, or write the reason above the call as %s <what is lost>:\n  %s",
			len(findings), backlog, marker, strings.Join(lines, "\n  "))
		return
	}
	if len(findings) < backlog {
		t.Errorf("the backlog is down to %d from %d. Lower the `backlog` constant in this file to %d so it "+
			"cannot drift back up -- a ratchet that is not tightened is a ceiling nobody is under.",
			len(findings), backlog, len(findings))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
