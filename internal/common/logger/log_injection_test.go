package logger

import (
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// TestUserValuesInFieldsCannotForgeALogRecord pins the property that makes
// CodeQL's 757 `go/log-injection` findings against this tree false positives —
// and makes the one shape that would NOT be a false positive fail loudly.
//
// Log injection is forging a record: a user-supplied value carrying CR/LF so
// that what reads as a second log line was in fact typed by the attacker. What
// stops it here is the encoder, not a sanitiser at each of 757 call sites:
//
//   - production (`APP_ENV=production`) builds `zap.NewProductionConfig()`,
//     whose encoding is JSON;
//   - development builds `zap.NewDevelopmentConfig()`, whose console encoder
//     still writes structured FIELDS through the JSON encoder.
//
// Either way a `zap.String("k", userInput)` value is JSON-escaped, and a
// newline inside it appears as the two characters `\` and `n`.
//
// The shape that would be a real defect is a user value interpolated into the
// MESSAGE under console encoding, which is written verbatim. The last subtest
// pins that difference so the distinction stays visible: it is the thing to
// look for when triaging a log-injection alert, rather than the field values
// the alerts mostly name.
func TestUserValuesInFieldsCannotForgeALogRecord(t *testing.T) {
	const forged = "alice\nlevel=error msg=\"admin deleted all users\"\rmore"

	encode := func(t *testing.T, enc zapcore.Encoder) string {
		t.Helper()
		buf, err := enc.EncodeEntry(zapcore.Entry{
			Level:   zapcore.InfoLevel,
			Message: "login attempt",
		}, []zapcore.Field{zap.String("username", forged)})
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		return buf.String()
	}

	t.Run("production JSON encoding escapes the newlines", func(t *testing.T) {
		out := encode(t, zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()))
		assertNoRawBreak(t, out)
	})

	t.Run("development console encoding escapes them too, in fields", func(t *testing.T) {
		// The console encoder is the one a reader would assume is unsafe. It is
		// not, for fields: zap writes the structured part as JSON.
		out := encode(t, zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()))
		assertNoRawBreak(t, out)
	})

	t.Run("the real defect shape is a user value in the message", func(t *testing.T) {
		enc := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
		buf, err := enc.EncodeEntry(zapcore.Entry{
			Level:   zapcore.InfoLevel,
			Message: "login attempt for " + forged, // never do this
		}, nil)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		body := strings.TrimSuffix(buf.String(), "\n")
		if !strings.Contains(body, "\n") {
			t.Error("console encoding escaped a message it writes verbatim — if zap " +
				"has changed, the triage note on go/log-injection needs rewriting, " +
				"because it rests on this being the one unsafe shape")
		}
	})
}

// assertNoRawBreak fails if anything but the encoder's own trailing newline
// survives as a real line break: a raw CR or LF inside the record is exactly
// the forged second line the attacker wanted.
func assertNoRawBreak(t *testing.T, out string) {
	t.Helper()
	body := strings.TrimSuffix(out, "\n")
	if strings.ContainsAny(body, "\n\r") {
		t.Errorf("a user-supplied field value put a raw line break into the record:\n%q", out)
	}
	if !strings.Contains(body, `\n`) {
		t.Errorf("expected the newline to appear escaped as \\n, got:\n%q", out)
	}
}
