package ipc

import (
	"regexp"
	"strings"
	"testing"
)

// aceRights returns the rights field of the ACE granted to the given SID
// abbreviation in an SDDL string, or "" when there is none.
func aceRights(t *testing.T, sddl, sid string) string {
	t.Helper()
	re := regexp.MustCompile(`\(A;;([A-Z0-9x]+);;;` + sid + `\)`)
	m := re.FindStringSubmatch(sddl)
	if m == nil {
		return ""
	}
	return m[1]
}

// TestAuthenticatedUsersMayOnlyReadThePipe pins the half of the pipe's ACL that
// faces an ordinary signed-in user: read, and nothing that lets them create a
// further instance of the pipe or rewrite its ACL. A regression to GA (or any
// right containing GW, WD or WO) fails here before it reaches a Windows runner.
func TestAuthenticatedUsersMayOnlyReadThePipe(t *testing.T) {
	if !strings.HasPrefix(pipeSDDL, "D:P(") {
		t.Fatalf("the DACL must be protected (D:P) so the pipe inherits nothing: %q", pipeSDDL)
	}
	au := aceRights(t, pipeSDDL, "AU")
	if au != "GR" {
		t.Fatalf("Authenticated Users must get exactly GR (generic read), got %q in %q", au, pipeSDDL)
	}
	for _, sid := range []string{"SY", "BA"} {
		if got := aceRights(t, pipeSDDL, sid); got != "GA" {
			t.Fatalf("%s must keep GA so the service can serve and an admin can inspect, got %q", sid, got)
		}
	}
	if strings.Contains(pipeSDDL, "(D;") {
		t.Fatalf("no deny ACE is expected; one would mask a grant below it: %q", pipeSDDL)
	}
}
