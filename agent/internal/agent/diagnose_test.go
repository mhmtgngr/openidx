package agent

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openidx/openidx/agent/internal/doctor"
)

type reachableProbes struct{}

func (reachableProbes) Resolve(context.Context, string) ([]string, error) {
	return []string{"198.51.100.7"}, nil
}
func (reachableProbes) DialTCP(context.Context, string) error              { return nil }
func (reachableProbes) TLSHandshake(context.Context, string, string) error { return nil }
func (reachableProbes) HTTPGet(context.Context, string) (doctor.HTTPResult, error) {
	return doctor.HTTPResult{Status: 401, Date: time.Now()}, nil
}
func (reachableProbes) Proxy(string) *url.URL { return nil }
func (reachableProbes) Now() time.Time        { return time.Now() }

// A "diagnose" fleet command answers with the doctor's bundle, and the
// bundle never carries the agent's credential.
func TestDiagnoseCommandAnswersWithABundle(t *testing.T) {
	old := doctorProbes
	doctorProbes = func() doctor.Probes { return reachableProbes{} }
	defer func() { doctorProbes = old }()

	const secret = "s3cret-fixture-token"
	a := &Agent{
		Version: "0.6.0",
		config:  &AgentConfig{AgentID: "agent-1", ServerURL: "https://idx.example.test", AuthToken: secret},
	}
	out := a.runCommand(Command{ID: "c1", Kind: "diagnose"})
	if out.status != "done" || out.after != nil || out.artifact != nil {
		t.Fatalf("outcome = %+v", out)
	}
	raw, err := json.Marshal(out.result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("the auth token is in the command result")
	}
	var got struct {
		Bundle doctor.Bundle `json:"bundle"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	b := got.Bundle
	if b.Schema != doctor.SchemaVersion || b.AgentID != "agent-1" || b.AgentVersion != "0.6.0" || len(b.Checks) != len(doctor.CheckOrder) {
		t.Errorf("bundle = %+v", b)
	}
	for _, c := range b.Checks {
		if c.ID == doctor.CheckService && c.Status != doctor.StatusPass {
			t.Errorf("the agent answering the command is running: %+v", c)
		}
		if c.Status == doctor.StatusFail {
			t.Errorf("unexpected failure %+v", c)
		}
	}
	if len(raw) > 32<<10 {
		t.Errorf("the result is %d bytes; the server refuses results over 64 KiB", len(raw))
	}
}
