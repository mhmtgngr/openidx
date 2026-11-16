package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/doctor"
	"github.com/openidx/openidx/agent/internal/doctor/collect"
	"github.com/openidx/openidx/agent/internal/ipc"
	"github.com/openidx/openidx/agent/internal/tunnel"
)

type okProbes struct{}

func (okProbes) Resolve(context.Context, string) ([]string, error) {
	return []string{"198.51.100.7"}, nil
}
func (okProbes) DialTCP(context.Context, string) error              { return nil }
func (okProbes) TLSHandshake(context.Context, string, string) error { return nil }
func (okProbes) HTTPGet(context.Context, string) (doctor.HTTPResult, error) {
	return doctor.HTTPResult{Status: 401, Date: time.Now()}, nil
}
func (okProbes) Proxy(string) *url.URL { return nil }
func (okProbes) Now() time.Time        { return time.Now() }

type stubActions struct{ onRestart func() }

func (stubActions) FlushDNS(context.Context) error { return nil }
func (s stubActions) RestartService(context.Context) error {
	if s.onRestart != nil {
		s.onRestart()
	}
	return nil
}

const fixtureToken = "s3cret-fixture-token"

func enrolledConfig(string) (*agent.AgentConfig, error) {
	return &agent.AgentConfig{
		ServerURL: "https://idx.example.test", AgentID: "agent-1", AuthToken: fixtureToken,
		Tunnel: &agent.TunnelConfig{Enabled: true},
	}, nil
}

func pipe(state tunnel.State) func() (*ipc.Status, error) {
	return func() (*ipc.Status, error) {
		return &ipc.Status{
			Enrolled: true, AgentID: "agent-1", ServerURL: "https://idx.example.test",
			Tunnel: &tunnel.Status{State: state},
		}, nil
	}
}

func testDeps() collect.Deps {
	return collect.Deps{
		LoadConfig: enrolledConfig, QueryIPC: pipe(tunnel.StateConnected),
		Probes: okProbes{}, Actions: stubActions{},
	}
}

func TestConfigUnreadableWithoutPipe(t *testing.T) {
	var out bytes.Buffer
	d := testDeps()
	d.LoadConfig = func(string) (*agent.AgentConfig, error) {
		return nil, fmt.Errorf("reading agent config: %w", fs.ErrPermission)
	}
	d.QueryIPC = func() (*ipc.Status, error) { return nil, errors.New("no pipe") }
	code, err := runDoctor(context.Background(), d, &out, "", doctorFlags{JSON: true})
	if err != nil || code != 1 {
		t.Fatalf("code %d, err %v", code, err)
	}
	if !strings.Contains(out.String(), doctor.CodeConfigUnreadable) {
		t.Errorf("output lacks %s:\n%s", doctor.CodeConfigUnreadable, out.String())
	}
}

func TestRunDoctorHealthyJSON(t *testing.T) {
	var out bytes.Buffer
	code, err := runDoctor(context.Background(), testDeps(), &out, "", doctorFlags{JSON: true})
	if err != nil || code != 0 {
		t.Fatalf("code %d, err %v\n%s", code, err, out.String())
	}
	var b doctor.Bundle
	if err := json.Unmarshal(out.Bytes(), &b); err != nil {
		t.Fatalf("output is not a bundle: %v", err)
	}
	if b.Schema != doctor.SchemaVersion || len(b.Checks) != len(doctor.CheckOrder) {
		t.Errorf("bundle = %+v", b)
	}
	if strings.Contains(out.String(), fixtureToken) {
		t.Error("the auth token leaked into the bundle")
	}
}

func TestRunDoctorFailingTextAndPlan(t *testing.T) {
	var out bytes.Buffer
	d := testDeps()
	d.QueryIPC = pipe(tunnel.StateDegraded)
	code, err := runDoctor(context.Background(), d, &out, "", doctorFlags{Lang: "tr"})
	if err != nil || code != 1 {
		t.Fatalf("code %d, err %v", code, err)
	}
	for _, want := range []string{"Güvenli tünel çalışmıyor.", "--fix ile denenir"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestRunDoctorFixReRunsChecks(t *testing.T) {
	var out bytes.Buffer
	d := testDeps()
	state := tunnel.StateDegraded
	d.QueryIPC = func() (*ipc.Status, error) { return pipe(state)() }
	d.Actions = stubActions{onRestart: func() { state = tunnel.StateConnected }}

	code, err := runDoctor(context.Background(), d, &out, "", doctorFlags{JSON: true, Fix: true})
	if err != nil || code != 0 {
		t.Fatalf("code %d, err %v\n%s", code, err, out.String())
	}
	var b doctor.Bundle
	if err := json.Unmarshal(out.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Repairs) != 1 || b.Repairs[0].ID != doctor.RepairRestartService || b.Repairs[0].Outcome != doctor.OutcomeApplied {
		t.Errorf("repairs = %+v", b.Repairs)
	}
}

func TestRunDoctorRejectsUnknownLanguage(t *testing.T) {
	var out bytes.Buffer
	if code, err := runDoctor(context.Background(), testDeps(), &out, "", doctorFlags{Lang: "de"}); code != 2 || err == nil {
		t.Errorf("code %d, err %v", code, err)
	}
}

func TestExportWritesOwnerOnlyAndNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	var out bytes.Buffer
	if code, err := runDoctor(context.Background(), testDeps(), &out, "", doctorFlags{Export: path}); code != 0 || err != nil {
		t.Fatalf("code %d, err %v", code, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var b doctor.Bundle
	if err := json.Unmarshal(data, &b); err != nil || b.Schema != doctor.SchemaVersion {
		t.Errorf("exported file is not a bundle: %v", err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, want 0600", st.Mode().Perm())
		}
	}
	if code, err := runDoctor(context.Background(), testDeps(), &out, "", doctorFlags{Export: path}); code != 2 || err == nil {
		t.Errorf("second export: code %d, err %v; an existing file must be refused", code, err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, data) {
		t.Error("the existing file was changed")
	}
}
