package tunnel

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The fake tunneler is this test binary re-executed with fakeEnv set. It
// answers the three commands the supervisor uses:
//
//	version                         prints fakeVersion
//	tunnel_status -P <pipe>         prints the file named by fakeStatusEnv, or
//	                                fails like the real CLI with no instance
//	run --identity-dir <d> -P <p>   appends its arguments to fakeStartsEnv, then
//	                                exits at once (fakeRunEnv=crash) or runs
//	                                until signalled (fakeRunEnv=stay)
const (
	fakeEnv       = "OPENIDX_FAKE_TUNNELER"
	fakeStatusEnv = "OPENIDX_FAKE_TUNNELER_STATUS"
	fakeStartsEnv = "OPENIDX_FAKE_TUNNELER_STARTS"
	fakeRunEnv    = "OPENIDX_FAKE_TUNNELER_RUN"
	fakeVersion   = "v1.18.7-fake"
)

func TestMain(m *testing.M) {
	if os.Getenv(fakeEnv) == "1" {
		os.Exit(fakeTunneler(os.Args[1:]))
	}
	// The fake tunneler is this test binary, which lives under the
	// world-writable temporary directory and would rightly be refused.
	// verifyTrustedBinary has tests of its own (security_test.go).
	verifyBinary = func(string) error { return nil }
	os.Exit(m.Run())
}

func fakeTunneler(args []string) int {
	if len(args) == 0 {
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Println(fakeVersion)
		return 0
	case "tunnel_status":
		if len(args) != 3 || args[1] != "-P" || args[2] != IPCDiscriminator {
			fmt.Fprintln(os.Stderr, "unexpected tunnel_status args:", args)
			return 2
		}
		data, err := os.ReadFile(os.Getenv(fakeStatusEnv))
		if err != nil {
			fmt.Fprint(os.Stderr, "failed to connect to pipe: 2")
			return 1
		}
		fmt.Println("some log line before the JSON")
		os.Stdout.Write(data)
		return 0
	case "run":
		if f, err := os.OpenFile(os.Getenv(fakeStartsEnv), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
			fmt.Fprintln(f, strings.Join(args, " "))
			f.Close()
		}
		if os.Getenv(fakeRunEnv) == "crash" {
			return 3
		}
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		select {
		case <-sig:
			return 0
		case <-time.After(2 * time.Minute):
			return 4
		}
	}
	return 2
}
