package tray

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/openidx/openidx/agent/internal/desktoppam"
	"github.com/openidx/openidx/agent/internal/ipc"
)

func TestJustificationRefusalOpensJustifyLink(t *testing.T) {
	err := fmt.Errorf("%w: x", desktoppam.ErrJustificationRequired)
	if got := refusalActionFor(err); got != actionJustify {
		t.Fatalf("a justification refusal maps to %v", got)
	}
	link := JustifyLink("entry 1/../x")
	id, ok := ParseJustifyLink(link)
	if ok {
		t.Errorf("an entry id with a path in it was accepted: %q", id)
	}
	id, ok = ParseJustifyLink(JustifyLink("6f1c-entry"))
	if !ok || id != "6f1c-entry" {
		t.Errorf("round trip gave %q %v", id, ok)
	}
	for _, bad := range []string{"openidx://enroll?request=x", "https://justify?request=x", "openidx://justify", "::"} {
		if _, ok := ParseJustifyLink(bad); ok {
			t.Errorf("%q parsed as a justify link", bad)
		}
	}
	if validJustification("too short") == "" || validJustification(strings.Repeat("a", 501)) == "" {
		t.Error("an out-of-range reason was accepted")
	}
	if msg := validJustification("Restoring the payroll DB after a failed job"); msg != "" {
		t.Error(msg)
	}
	if errors.Is(err, desktoppam.ErrApprovalRequired) {
		t.Error("a justification refusal also reads as a bare approval refusal")
	}
}

func TestAboutShowsVersionChannelAndUpdateState(t *testing.T) {
	st := &ipc.Status{Enrolled: true, UpdateChannel: "beta", UpdateState: "failed", UpdateVersion: "0.6.5", Unclaimed: true}
	msg := aboutText("0.6.4", "https://idp.example", "agent-1", "dev-1", `C:\ProgramData\OpenIDX\agent`, st)
	for _, want := range []string{"OpenIDX agent 0.6.4", "Update channel: beta", "Last update: failed (0.6.5)", "Agent ID: agent-1", "Sign in to claim"} {
		if !strings.Contains(msg, want) {
			t.Errorf("About lacks %q:\n%s", want, msg)
		}
	}
	paused := aboutText("0.6.4", "", "", "", "/x", &ipc.Status{UpdatePaused: true})
	if !strings.Contains(paused, "Update channel: stable (updates paused") || !strings.Contains(paused, "(not enrolled)") {
		t.Errorf("paused About:\n%s", paused)
	}
	if strings.Contains(aboutText("0.6.4", "s", "", "", "/x", nil), "Update channel") {
		t.Error("About claimed a channel with no service answer")
	}
}

func TestClaimPromptOnlyForUnclaimedDevice(t *testing.T) {
	if got := claimPrompt(false, &ipc.Status{Enrolled: true, Unclaimed: true}); got != "Sign in to claim this device" {
		t.Errorf("signed out: %q", got)
	}
	if got := claimPrompt(true, &ipc.Status{Enrolled: true, Unclaimed: true}); got != "Claim this device" {
		t.Errorf("signed in: %q", got)
	}
	for _, st := range []*ipc.Status{nil, {Enrolled: true}, {Enrolled: true, Unclaimed: true, Revoked: true}, {Unclaimed: true}} {
		if got := claimPrompt(false, st); got != "" {
			t.Errorf("%+v offered %q", st, got)
		}
	}
}
