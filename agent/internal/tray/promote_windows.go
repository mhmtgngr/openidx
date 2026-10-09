//go:build windows

package tray

import (
	"os"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Windows 11 puts a new tray icon in the overflow behind the ^ arrow, where
// nobody finds it, and the icon is how a person learns the device is managed
// and how to sign in. The first time the tray runs for a user it moves its
// icon onto the taskbar, once: the choice is recorded, so a person who later
// hides it again is not overridden.
const (
	notifyIconSettingsKey = `Control Panel\NotifyIconSettings`
	trayPromotedValue     = "TrayPromoted"
	promoteAttempts       = 6
	promoteInterval       = 5 * time.Second
)

// promoteIconOnce runs in the background after the icon is set. Explorer
// writes the icon's NotifyIconSettings entry only after the icon first
// appears, so it is looked for a few times.
func (a *app) promoteIconOnce() {
	if trayPromoted() {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	folders := knownFolderPaths()
	for i := 0; i < promoteAttempts; i++ {
		time.Sleep(promoteInterval)
		found, supported := promoteIcon(exe, folders)
		if !supported {
			return // Windows 10: no such settings, the icon is shown by default
		}
		if found {
			markTrayPromoted()
			a.logger.Info("tray: icon moved onto the taskbar")
			return
		}
	}
	a.logger.Debug("tray: no NotifyIconSettings entry for this tray yet; will try at next start",
		zap.String("exe", exe))
}

// promoteIcon sets IsPromoted on every NotifyIconSettings entry for exe.
func promoteIcon(exe string, folders map[string]string) (found, supported bool) {
	root, err := registry.OpenKey(registry.CURRENT_USER, notifyIconSettingsKey,
		registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false, false
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return false, true
	}
	for _, name := range names {
		k, err := registry.OpenKey(root, name, registry.QUERY_VALUE|registry.SET_VALUE)
		if err != nil {
			continue
		}
		path, _, err := k.GetStringValue("ExecutablePath")
		if err == nil && notifyIconPathMatches(path, exe, folders) {
			if k.SetDWordValue("IsPromoted", 1) == nil {
				found = true
			}
		}
		k.Close()
	}
	return found, true
}

func knownFolderPaths() map[string]string {
	out := map[string]string{}
	for _, id := range []*windows.KNOWNFOLDERID{
		windows.FOLDERID_ProgramFilesX64,
		windows.FOLDERID_ProgramFiles,
		windows.FOLDERID_ProgramFilesX86,
	} {
		if p, err := windows.KnownFolderPath(id, 0); err == nil {
			out[(*windows.GUID)(id).String()] = p
		}
	}
	return out
}

func trayPromoted() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, autostartKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(trayPromotedValue)
	return err == nil && v == 1
}

func markTrayPromoted() {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, autostartKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.SetDWordValue(trayPromotedValue, 1)
}
