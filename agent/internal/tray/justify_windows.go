//go:build windows

package tray

import (
	"context"
	"encoding/base64"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/authstore"
	"github.com/openidx/openidx/agent/internal/desktoppam"
	"github.com/openidx/openidx/agent/internal/sso"
)

// askText shows a one-line text prompt and returns what was typed, ok false
// when the person cancelled. Windows has no native one-call text box; the
// Visual Basic InputBox, run by PowerShell with the prompt passed encoded so
// nothing in it is parsed as script, is the one every Windows has.
func askText(prompt string) (string, bool) {
	enc := func(s string) string {
		u := utf16.Encode([]rune(s))
		b := make([]byte, len(u)*2)
		for i, r := range u {
			b[2*i], b[2*i+1] = byte(r), byte(r>>8)
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	script := "Add-Type -AssemblyName Microsoft.VisualBasic;" +
		"$p=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('" + enc(prompt) + "'));" +
		"$r=[Microsoft.VisualBasic.Interaction]::InputBox($p,'OpenIDX','');" +
		"[Console]::OutputEncoding=[Text.Encoding]::UTF8;[Console]::Out.Write($r)"
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-EncodedCommand", enc(script))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	s := strings.TrimSpace(string(out))
	return s, s != ""
}

// justifyAndRequest asks for a written reason until it is acceptable, then
// files the access request for entryID with it.
func (a *app) justifyAndRequest(entryID string) {
	a.mu.Lock()
	t := a.tokens
	a.mu.Unlock()
	if t == nil {
		a.tell("Sign in first, then open the connection again.")
		return
	}
	prompt := "This connection asks why you are opening it.\n\nWrite what you need to do and why (10 to 500 characters). Your approver reads it."
	for {
		reason, ok := askText(prompt)
		if !ok {
			return
		}
		if msg := validJustification(reason); msg != "" {
			prompt = msg
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err := desktoppam.RequestAccess(ctx, a.server(), t.AccessToken, entryID, strings.TrimSpace(reason))
		cancel()
		if err != nil {
			a.logger.Warn("tray: justified access request failed", zap.String("entry", entryID), zap.Error(err))
			a.tell("The request could not be sent.\n\n" + desktoppam.UserMessage(err))
			return
		}
		a.tell("Your request was sent with your reason. You can connect once it is approved.")
		return
	}
}

// openJustifyLink hands the openidx://justify link to the OS, which routes
// it back to this agent (RunJustifyLink). When the link cannot be opened the
// prompt runs in this process instead.
func (a *app) openJustifyLink(entryID string) {
	if err := sso.OpenURL(JustifyLink(entryID)); err != nil {
		a.justifyAndRequest(entryID)
	}
}

// RunJustifyLink serves an openidx://justify link in a process of its own:
// it loads the signed-in session the tray saved and asks for the reason.
func RunJustifyLink(logger *zap.Logger, configDir, server, link string) {
	entryID, ok := ParseJustifyLink(link)
	if !ok {
		return
	}
	a := &app{logger: logger, configDir: configDir, serverURL: strings.TrimRight(server, "/")}
	a.resolveServer()
	if t, _ := authstore.Load(configDir); t != nil {
		a.tokens = t
	}
	a.justifyAndRequest(entryID)
}
