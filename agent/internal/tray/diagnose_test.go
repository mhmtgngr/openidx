package tray

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/doctor"
	"github.com/openidx/openidx/agent/internal/doctor/collect"
	"github.com/openidx/openidx/agent/internal/ipc"
)

func TestDiagnosisSaysWhatIsWrongInTheTrayLanguage(t *testing.T) {
	old := T
	defer func() { T = old }()
	deps := collect.Deps{
		LoadConfig: func(string) (*agent.AgentConfig, error) { return nil, fs.ErrNotExist },
		QueryIPC:   func() (*ipc.Status, error) { return nil, errors.New("no pipe") },
		Probes:     doctor.NewProbes(),
		Actions:    doctor.NewActions(),
	}

	T = &trStrings
	text, healthy := diagnosis(context.Background(), deps, "")
	if healthy || !strings.Contains(text, "Bu cihaz henüz OpenIDX'e kaydedilmemiş.") || !strings.Contains(text, "OX1-") {
		t.Errorf("Turkish diagnosis:\n%s", text)
	}
	T = &enStrings
	if text, _ := diagnosis(context.Background(), deps, ""); !strings.Contains(text, "not registered with OpenIDX") {
		t.Errorf("English diagnosis:\n%s", text)
	}
}
