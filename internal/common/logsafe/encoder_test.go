package logsafe_test

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/openidx/openidx/internal/common/logsafe"
)

// The package comment makes four claims about how a hostile string travels from
// a request into a log file. Each one decides whether a caller has to reach for
// logsafe, and the comment this file replaced got one of them backwards for a
// release. Claims about someone else's library belong in a test, not a comment:
// zap can change, and when it does this file says so.

// forged is what an attacker would like to see appear in the log as its own
// entry: a plausible timestamp, a level, and a lie.
const forged = "/api/v1/users\n2026-09-06T00:00:00Z\tFATAL\tforged\tall users deleted"

func consoleOut(t *testing.T, msg string, fields ...zap.Field) string {
	t.Helper()
	var buf bytes.Buffer
	enc := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	zap.New(zapcore.NewCore(enc, zapcore.AddSync(&buf), zapcore.DebugLevel)).Warn(msg, fields...)
	return buf.String()
}

func jsonOut(t *testing.T, msg string, fields ...zap.Field) string {
	t.Helper()
	var buf bytes.Buffer
	enc := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	zap.New(zapcore.NewCore(enc, zapcore.AddSync(&buf), zapcore.DebugLevel)).Warn(msg, fields...)
	return buf.String()
}

// lines counts the entries a reader (or a log shipper splitting on \n) would see.
func lines(out string) int {
	return len(strings.Split(strings.TrimRight(out, "\n"), "\n"))
}

// Claim 1: reachability. A route pattern cannot contain a newline; a REQUEST
// PATH can, because %0A survives net/http's parsing and is decoded into
// URL.Path. Without this, every "sanitize the path" argument is hypothetical.
func TestPercentEncodedNewlineReachesRequestPath(t *testing.T) {
	raw := "GET /api/v1/users%0A2026-01-01%09FATAL%09forged HTTP/1.1\r\nHost: openidx.test\r\n\r\n"
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if !strings.Contains(req.URL.Path, "\n") {
		t.Fatalf("URL.Path = %q — expected a decoded newline; if net/http started rejecting this, "+
			"the package comment's reachability claim needs rewriting, not this test deleting", req.URL.Path)
	}
	// The method, by contrast, cannot carry one: a CR or LF would have ended the
	// request line before the method token finished. It is still cleaned at the
	// call sites, because a rule with an exception is a rule people misapply.
	if strings.ContainsAny(req.Method, "\r\n") {
		t.Fatalf("Method = %q carried a line break", req.Method)
	}
}

// Claim 2: a FIELD is escaped by both encoders, so it cannot forge a line. This
// is the claim the old comment had backwards.
func TestBothEncodersEscapeAField(t *testing.T) {
	for name, out := range map[string]string{
		"console": consoleOut(t, "X-Org-ID ignored", zap.String("path", forged)),
		"json":    jsonOut(t, "X-Org-ID ignored", zap.String("path", forged)),
	} {
		if got := lines(out); got != 1 {
			t.Errorf("%s encoder emitted %d lines for a field carrying a newline, want 1:\n%s", name, got, out)
		}
		if !strings.Contains(out, `\n`) {
			t.Errorf("%s encoder did not escape the newline in a field:\n%s", name, out)
		}
	}
}

// ...including an ANSI escape, which a terminal would otherwise act on.
func TestConsoleEncoderEscapesANSIInAField(t *testing.T) {
	out := consoleOut(t, "x", zap.String("path", "/a\x1b[2J\x1b[1;31mDANGER"))
	if strings.ContainsRune(out, 0x1b) {
		t.Fatalf("console encoder passed a raw ESC through a field: %q", out)
	}
}

// Claim 3: the MESSAGE is the half that is raw. This is the shape that forges a
// line, which is why no_interpolated_message_test.go exists — the escaping here
// is the encoder's choice, and only one of the two encoders makes it.
func TestConsoleEncoderWritesTheMessageRaw(t *testing.T) {
	out := consoleOut(t, "X-Org-ID ignored on "+forged)
	if lines(out) != 2 {
		t.Fatalf("console encoder emitted %d lines for an interpolated message, want 2 "+
			"(this test documents a weakness; if zap started escaping messages, say so here):\n%s", lines(out), out)
	}
	if !strings.Contains(out, "FATAL\tforged") {
		t.Fatalf("the forged second line did not appear as its own entry:\n%s", out)
	}

	if got := lines(jsonOut(t, "X-Org-ID ignored on "+forged)); got != 1 {
		t.Fatalf("json encoder emitted %d lines for an interpolated message, want 1", got)
	}
}

// Claim 4: Clean closes it at the source, so the value is safe before it reaches
// any encoder at all — including the message position, and including a sink that
// is not zap.
func TestCleanNeutralisesTheForgedLineEverywhere(t *testing.T) {
	safe := logsafe.Clean(forged)
	if strings.ContainsAny(safe, "\r\n\t") {
		t.Fatalf("Clean left a line break or tab: %q", safe)
	}
	if got := lines(consoleOut(t, "X-Org-ID ignored on "+safe)); got != 1 {
		t.Fatalf("a cleaned value still forged a line in the message position (%d lines)", got)
	}
	if !strings.Contains(safe, "all users deleted") {
		t.Fatalf("Clean removed the readable text as well as the control characters: %q", safe)
	}
}

// The bound Clean also applies — which no encoder does — is covered by
// TestCleanBoundsLength in logsafe_test.go.
