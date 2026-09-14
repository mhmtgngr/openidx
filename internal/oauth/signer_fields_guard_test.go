package oauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The legacy single-key fields are construction-time state, and the whole point
// of the fix they came out of is that nothing assigns them afterwards: a plain
// field written on a ticker goroutine and read on request goroutines is a data
// race, and these two are read by every SAML signing path.
//
// Derived rather than listed -- it reads the package's own sources -- so the
// next "keep the legacy fields in step for any direct readers" line fails here
// instead of being found by the race detector months later, or not at all.
func TestTheLegacySigningFieldsAreWrittenOnlyAtConstruction(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var offenders []string
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		checked++
		for i, line := range strings.Split(string(body), "\n") {
			code := line
			if c := strings.Index(code, "//"); c >= 0 {
				code = code[:c]
			}
			for _, field := range []string{"s.privateKey", "s.publicKey"} {
				rest, ok := strings.CutPrefix(strings.TrimSpace(code), field)
				if !ok {
					continue
				}
				rest = strings.TrimSpace(rest)
				// An assignment, not a read: `= x` or `= x, y`, but not `==`.
				if strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "==") {
					offenders = append(offenders, name+":"+itoa(i+1)+": "+strings.TrimSpace(line))
				}
			}
		}
	}
	if checked < 10 {
		t.Fatalf("only %d non-test files scanned -- the guard is not seeing the package", checked)
	}
	if len(offenders) != 0 {
		t.Errorf("the legacy signing fields are assigned after construction:\n  %s\n\n"+
			"They are read by the SAML signing paths on request goroutines, so a write anywhere "+
			"else is a data race. The current key belongs in the atomic snapshot; read it with "+
			"activePrivateKey()/activePublicKey().", strings.Join(offenders, "\n  "))
	}
}

// itoa keeps the guard free of fmt for one number.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
