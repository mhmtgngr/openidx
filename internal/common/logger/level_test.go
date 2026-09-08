package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestSetLevelMovesTheLevelEveryLoggerShares(t *testing.T) {
	before := level.Level()
	t.Cleanup(func() { level.SetLevel(before) })

	log := New()

	if err := SetLevel("error"); err != nil {
		t.Fatalf("SetLevel(error): %v", err)
	}
	if log.Core().Enabled(zapcore.InfoLevel) {
		t.Error("a logger handed out before SetLevel still logs at info; the level is not shared, " +
			"so the configured value reaches nothing built at startup — which is the whole defect")
	}
	if !log.Core().Enabled(zapcore.ErrorLevel) {
		t.Error("error is not enabled at level error")
	}

	if err := SetLevel("debug"); err != nil {
		t.Fatalf("SetLevel(debug): %v", err)
	}
	if !log.Core().Enabled(zapcore.DebugLevel) {
		t.Error("the same logger did not follow the level back down")
	}
}

func TestSetLevelLeavesTheEnvironmentsChoiceWhenUnset(t *testing.T) {
	before := level.Level()
	t.Cleanup(func() { level.SetLevel(before) })

	level.SetLevel(zap.WarnLevel)
	for _, empty := range []string{"", "   "} {
		if err := SetLevel(empty); err != nil {
			t.Fatalf("SetLevel(%q): %v", empty, err)
		}
		if level.Level() != zap.WarnLevel {
			t.Fatalf("SetLevel(%q) moved the level to %v; an install that never set log_level "+
				"must keep what LOG_LEVEL and APP_ENV chose", empty, level.Level())
		}
	}
}

// A name zap does not know must be loud. Silently logging at whatever was
// already set, for the life of the deployment, is the same failure this whole
// change is about: the operator set something and believes it took.
//
// "warning" is deliberately NOT the example — zapcore accepts it as an alias for
// "warn", and asserting a rejection there would have pinned a behaviour the
// library does not have.
func TestSetLevelRefusesAnUnknownName(t *testing.T) {
	before := level.Level()
	t.Cleanup(func() { level.SetLevel(before) })

	err := SetLevel("verbose")
	if err == nil {
		t.Fatal("SetLevel(\"verbose\") accepted a name zap does not know")
	}
	if !strings.Contains(err.Error(), "verbose") {
		t.Errorf("the error does not name the value the operator set: %v", err)
	}
	if level.Level() != before {
		t.Error("a rejected level still moved the level")
	}
}

// The spellings an operator can reasonably write must all work, including the
// aliases zapcore accepts and any casing.
func TestSetLevelAcceptsTheNamesAnOperatorWrites(t *testing.T) {
	before := level.Level()
	t.Cleanup(func() { level.SetLevel(before) })

	for name, want := range map[string]zapcore.Level{
		"debug":   zap.DebugLevel,
		"INFO":    zap.InfoLevel,
		" warn ":  zap.WarnLevel,
		"warning": zap.WarnLevel,
		"Error":   zap.ErrorLevel,
	} {
		if err := SetLevel(name); err != nil {
			t.Errorf("SetLevel(%q): %v", name, err)
			continue
		}
		if level.Level() != want {
			t.Errorf("SetLevel(%q) = %v, want %v", name, level.Level(), want)
		}
	}
}

// The reason the field was dead in the first place: a service builds its logger
// before it has a config, so nothing applied the configured value. Every binary
// that loads a Config must apply it, and this derives that set from the tree
// rather than listing it — a tenth service added next month is covered without
// anybody remembering this test exists.
func TestEveryBinaryThatLoadsAConfigAppliesItsLogLevel(t *testing.T) {
	mains, err := filepath.Glob("../../../cmd/*/main.go")
	if err != nil {
		t.Fatalf("glob cmd: %v", err)
	}
	if len(mains) == 0 {
		t.Fatal("no cmd/*/main.go found; this test would pass vacuously")
	}

	checked := 0
	for _, main := range mains {
		body, err := os.ReadFile(main)
		if err != nil {
			t.Fatalf("read %s: %v", main, err)
		}
		text := string(body)
		if !strings.Contains(text, "config.Load(") {
			continue
		}
		checked++
		if !strings.Contains(text, "logger.SetLevel(") {
			t.Errorf("%s loads a Config and never applies cfg.LogLevel: "+
				"`log_level:` in a configuration file does nothing for this binary", main)
		}
	}
	if checked == 0 {
		t.Fatal("no cmd/*/main.go loads a Config; the check above ran against nothing")
	}
}
