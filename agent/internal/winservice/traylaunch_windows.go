//go:build windows

package winservice

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

// trayRecheck is how often the service looks for signed-in sessions without a
// tray. It also bounds how long after an install, an upgrade or a sign-in the
// icon takes to appear.
const trayRecheck = 15 * time.Second

// trayLoop brings the tray to every signed-in session (see traysToLaunch).
func (h *handler) trayLoop(ctx context.Context) {
	exe, err := os.Executable()
	if err != nil {
		h.logger.Warn("service: cannot locate own executable; not starting trays", zap.Error(err))
		return
	}
	launched := map[uint32]uint64{}
	t := time.NewTicker(trayRecheck)
	defer t.Stop()
	for {
		h.bringTrays(exe, launched)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (h *handler) bringTrays(exe string, launched map[uint32]uint64) {
	sessions, err := listUserSessions()
	if err != nil {
		h.logger.Debug("service: listing sessions", zap.Error(err))
		return
	}
	forgetEndedSessions(launched, sessions)
	withTray, err := sessionsWithTray(exe)
	if err != nil {
		h.logger.Debug("service: listing tray processes", zap.Error(err))
		return
	}
	for _, s := range traysToLaunch(sessions, withTray, launched) {
		// Recorded before the attempt: a launch that fails is reported once
		// per logon, not every trayRecheck.
		launched[s.ID] = s.Logon
		if err := launchTrayIn(s.ID, exe); err != nil {
			h.logger.Warn("service: could not start the tray in a session",
				zap.Uint32("session", s.ID), zap.Error(err))
			continue
		}
		h.logger.Info("service: started the tray in a session", zap.Uint32("session", s.ID))
	}
}

// listUserSessions returns every session with, for those someone is signed
// in to, the logon session id of that user.
func listUserSessions() ([]userSession, error) {
	var info *windows.WTS_SESSION_INFO
	var n uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &info, &n); err != nil {
		return nil, fmt.Errorf("WTSEnumerateSessions: %w", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	out := make([]userSession, 0, n)
	for _, si := range unsafe.Slice(info, n) {
		s := userSession{ID: si.SessionID, Active: si.State == windows.WTSActive}
		if s.ID != 0 && s.Active {
			s.Logon = sessionLogon(s.ID)
		}
		out = append(out, s)
	}
	return out, nil
}

// tokenStatistics is TOKEN_STATISTICS, which x/sys/windows does not define.
type tokenStatistics struct {
	TokenID            windows.LUID
	AuthenticationID   windows.LUID
	ExpirationTime     int64
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedID         windows.LUID
}

// sessionLogon is the logon session id of the user signed in to a session,
// or 0 when nobody is.
func sessionLogon(session uint32) uint64 {
	var tok windows.Token
	if err := windows.WTSQueryUserToken(session, &tok); err != nil {
		return 0
	}
	defer tok.Close()
	var st tokenStatistics
	var n uint32
	if err := windows.GetTokenInformation(tok, windows.TokenStatistics,
		(*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &n); err != nil {
		return 0
	}
	return uint64(uint32(st.AuthenticationID.HighPart))<<32 | uint64(st.AuthenticationID.LowPart)
}

// sessionsWithTray returns the sessions, other than the services' session 0,
// that run this executable. Outside session 0 this program runs only as the
// tray, or briefly for an enrolment link, so any copy there counts.
func sessionsWithTray(exe string) (map[uint32]bool, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	base := filepath.Base(exe)
	out := map[uint32]bool{}
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if !strings.EqualFold(windows.UTF16ToString(pe.ExeFile[:]), base) {
			continue
		}
		var session uint32
		if windows.ProcessIdToSessionId(pe.ProcessID, &session) != nil || session == 0 {
			continue
		}
		// A copy of the same file name installed elsewhere is not ours; one
		// whose path cannot be read is counted, since a second tray is worse
		// than a late one.
		if path, ok := processImage(pe.ProcessID); ok && !strings.EqualFold(path, exe) {
			continue
		}
		out[session] = true
	}
	return out, nil
}

func processImage(pid uint32) (string, bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", false
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", false
	}
	return windows.UTF16ToString(buf[:n]), true
}

// launchTrayIn starts `<exe> tray --autostart` as the user signed in to a
// session, on that user's desktop. --autostart makes the tray honour the
// user's "Start when I sign in" switch, exactly as the Run key does. The
// user's own token is not elevated (UAC hands WTSQueryUserToken the filtered
// one), so the tray runs with the same rights as one started from the Run key.
func launchTrayIn(session uint32, exe string) error {
	var user windows.Token
	if err := windows.WTSQueryUserToken(session, &user); err != nil {
		return fmt.Errorf("WTSQueryUserToken: %w", err)
	}
	defer user.Close()
	var primary windows.Token
	if err := windows.DuplicateTokenEx(user, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityIdentification, windows.TokenPrimary, &primary); err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer primary.Close()

	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, primary, false); err != nil {
		return fmt.Errorf("CreateEnvironmentBlock: %w", err)
	}
	defer windows.DestroyEnvironmentBlock(env)

	cmd, err := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{exe, "tray", "--autostart"}))
	if err != nil {
		return err
	}
	dir, err := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return err
	}
	desktop, err := windows.UTF16PtrFromString(`winsta0\default`)
	if err != nil {
		return err
	}
	si := windows.StartupInfo{Desktop: desktop}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(primary, nil, cmd, nil, nil, false,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, env, dir, &si, &pi); err != nil {
		return fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}
