//go:build windows

package tray

import (
	"context"

	"github.com/getlantern/systray"
	"golang.org/x/sys/windows"

	"github.com/openidx/openidx/agent/internal/doctor/collect"
)

// watchDiagnose serves the "Why can't I connect?" item: one check at a time,
// the answer in a dialog.
func (a *app) watchDiagnose(mi *systray.MenuItem) {
	for range mi.ClickedCh {
		mi.Disable()
		mi.SetTitle(T.DiagnoseRunning)
		text, healthy := diagnosis(context.Background(), collect.DefaultDeps(), a.configDir)
		mi.SetTitle(T.Diagnose)
		mi.Enable()
		showDiagnosis(text, healthy)
	}
}

func showDiagnosis(msg string, healthy bool) {
	text, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return
	}
	caption, err := windows.UTF16PtrFromString("OpenIDX")
	if err != nil {
		return
	}
	icon := uint32(windows.MB_ICONWARNING)
	if healthy {
		icon = windows.MB_ICONINFORMATION
	}
	_, _ = windows.MessageBox(0, text, caption, windows.MB_OK|icon|windows.MB_SETFOREGROUND|windows.MB_TOPMOST)
}
