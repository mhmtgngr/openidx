package main

import "testing"

// TestServiceRunGoesStraightToTheDispatcher guards the MSI upgrade fix: the
// SCM command line must be recognised before cobra so svc.Run is the first
// thing `service run` does.
func TestServiceRunGoesStraightToTheDispatcher(t *testing.T) {
	dir, ok := serviceRunArgs([]string{"service", "run", "--config-dir", `C:\ProgramData\OpenIDX\agent`})
	if !ok || dir != `C:\ProgramData\OpenIDX\agent` {
		t.Fatalf("got %q %v", dir, ok)
	}
	if dir, ok := serviceRunArgs([]string{"service", "run", "--config-dir=/x"}); !ok || dir != "/x" {
		t.Fatalf("= form: got %q %v", dir, ok)
	}
	if _, ok := serviceRunArgs([]string{"service", "run"}); !ok {
		t.Fatal("bare service run not recognised")
	}
	for _, a := range [][]string{{"service", "install"}, {"run"}, {}, {"enroll"}} {
		if _, ok := serviceRunArgs(a); ok {
			t.Fatalf("%v wrongly treated as service run", a)
		}
	}
}
