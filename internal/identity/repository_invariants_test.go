package identity

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestWritesNeverUseReplica is an architecture guard for the Repository pattern's
// core correctness invariant: WRITE methods (Create/Update/Delete) must use the
// PRIMARY pool (db.Pool), never db.Reader() (the read replica). Reading a lagging
// replica is fine; writing to one is a correctness bug (it's read-only, and
// read-your-write breaks). This test fails if a future edit points a write at the
// replica, so the invariant can't silently regress.
//
// It is a lightweight source scan (not full AST): for each repository file, it
// isolates the body of every write method and asserts it contains no `.Reader(`.
func TestWritesNeverUseReplica(t *testing.T) {
	repoFiles := []string{
		"user_repository.go",
		"group_repository.go",
		"session_repository.go",
	}
	// Method-name prefixes considered writes. Includes session write verbs
	// (UpdateActivity matches Update; Terminate is an explicit delete).
	writeMethod := regexp.MustCompile(`^func \(r \*Postgres\w+Repository\) (Create|Update|Delete|Terminate)\(`)

	for _, file := range repoFiles {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		lines := strings.Split(string(src), "\n")

		inWrite := false
		methodName := ""
		braceDepth := 0
		for _, line := range lines {
			if !inWrite {
				if m := writeMethod.FindStringSubmatch(line); m != nil {
					inWrite = true
					methodName = m[1]
					braceDepth = strings.Count(line, "{") - strings.Count(line, "}")
					continue
				}
				continue
			}
			// Inside a write method body.
			if strings.Contains(line, ".Reader(") {
				t.Errorf("%s: write method %s uses .Reader() (must use the primary db.Pool)", file, methodName)
			}
			braceDepth += strings.Count(line, "{") - strings.Count(line, "}")
			if braceDepth <= 0 {
				inWrite = false
			}
		}
	}
}

// TestReadsUseReplica is the complementary guard: read methods should use
// db.Reader() so they benefit from read-replica offload (Tier 1.6). This is a
// softer check (a read on the primary is correct, just not offloaded), so it only
// asserts the canonical getters route through Reader().
func TestReadsUseReplica(t *testing.T) {
	cases := []struct {
		file   string
		method string
	}{
		{"user_repository.go", "GetByID"},
		{"user_repository.go", "GetByUsername"},
		{"group_repository.go", "GetByID"},
		{"group_repository.go", "GetByName"},
	}
	for _, tc := range cases {
		src, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		body := methodBody(string(src), tc.method)
		if body == "" {
			t.Fatalf("%s: could not find method %s", tc.file, tc.method)
		}
		if !strings.Contains(body, ".Reader(") {
			t.Errorf("%s: read method %s should use db.Reader() for replica offload", tc.file, tc.method)
		}
	}
}

// TestSecurityCriticalReadUsesPrimary pins the deliberate exception: session
// validity (IsValid) is a read-after-write security check — a just-revoked
// session must never read as valid off a lagging replica — so it MUST use the
// primary db.Pool, NOT db.Reader(). This guards against a future "optimization"
// that moves it to the replica and silently introduces an auth bug.
func TestSecurityCriticalReadUsesPrimary(t *testing.T) {
	src, err := os.ReadFile("session_repository.go")
	if err != nil {
		t.Fatalf("read session_repository.go: %v", err)
	}
	body := methodBody(string(src), "IsValid")
	if body == "" {
		t.Fatal("could not find IsValid method")
	}
	if strings.Contains(body, ".Reader(") {
		t.Error("session IsValid must read the PRIMARY (db.Pool), not the replica — read-after-write security check")
	}
	if !strings.Contains(body, ".Pool.") {
		t.Error("session IsValid should read via db.Pool (primary)")
	}
}

// methodBody returns the source of the first method with the given name.
func methodBody(src, method string) string {
	re := regexp.MustCompile(`func \(r \*Postgres\w+Repository\) ` + regexp.QuoteMeta(method) + `\(`)
	loc := re.FindStringIndex(src)
	if loc == nil {
		return ""
	}
	rest := src[loc[0]:]
	depth := 0
	started := false
	for i, r := range rest {
		switch r {
		case '{':
			depth++
			started = true
		case '}':
			depth--
			if started && depth == 0 {
				return rest[:i+1]
			}
		}
	}
	return rest
}
