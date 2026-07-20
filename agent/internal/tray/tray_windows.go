//go:build windows

// Package tray is the end-user system-tray app (Windows). It runs in the
// interactive user session (NOT the service — session 0 has no desktop) and
// owns the user's SSO session and PAM launch. Device posture/enrollment stay
// with the service; a later phase adds a named-pipe link for live status.
package tray

import (
	"context"
	"sync"
	"time"

	"github.com/getlantern/systray"
	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/assets"
	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/authstore"
	"github.com/openidx/openidx/agent/internal/desktoppam"
	"github.com/openidx/openidx/agent/internal/ipc"
	"github.com/openidx/openidx/agent/internal/sso"
)

const maxConnSlots = 25

type app struct {
	logger    *zap.Logger
	configDir string
	serverURL string

	mBanner   *systray.MenuItem
	mStatus   *systray.MenuItem
	mSignIn   *systray.MenuItem
	mSignOut  *systray.MenuItem
	mConnRoot *systray.MenuItem

	mu       sync.Mutex
	tokens   *sso.Tokens
	connSlot []*systray.MenuItem
	slotID   []string // slot index -> entry id
	rsAgent  *agent.Agent // remote-support agent running in this user session
}

// Run starts the tray UI and blocks until the user quits.
func Run(logger *zap.Logger, configDir, serverURL string) error {
	a := &app{logger: logger, configDir: configDir, serverURL: serverURL}
	systray.Run(a.onReady, func() {})
	return nil
}

func (a *app) onReady() {
	systray.SetIcon(assets.OpenIDXICO)
	systray.SetTitle("OpenIDX")
	systray.SetTooltip("OpenIDX")

	// Remote-support banner: hidden until a session is live, then shown at the
	// very top so the user always sees "An OpenIDX admin can see and control
	// this device."
	a.mBanner = systray.AddMenuItem("", "")
	a.mBanner.Disable()
	a.mBanner.Hide()
	systray.AddSeparator()

	a.mStatus = systray.AddMenuItem("Not signed in", "")
	a.mStatus.Disable()
	systray.AddSeparator()
	a.mSignIn = systray.AddMenuItem("Sign in", "Sign in to OpenIDX")
	a.mSignOut = systray.AddMenuItem("Sign out", "Sign out")
	a.mSignOut.Hide()
	systray.AddSeparator()
	a.mConnRoot = systray.AddMenuItem("My Connections", "Launch a privileged session")
	for i := 0; i < maxConnSlots; i++ {
		mi := a.mConnRoot.AddSubMenuItem("", "")
		mi.Hide()
		a.connSlot = append(a.connSlot, mi)
		a.slotID = append(a.slotID, "")
		go a.watchSlot(i, mi)
	}
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit", "Quit OpenIDX")

	// Restore a saved session, if any.
	if t, _ := authstore.Load(a.configDir); t != nil {
		a.setSignedIn(t)
	}
	a.updateStatus()

	go a.loop(mQuit)
	go a.statusTicker()
	go a.runRemoteSupportAgent()
}

// runRemoteSupportAgent runs a lightweight agent loop IN THE USER SESSION whose
// only job is to service remote-support sessions (screen capture + input),
// which must happen where there is an interactive desktop. The Windows service
// (session 0) handles posture/enrollment but has DisableRemoteSupport set, so
// this is the single place screen-share runs. Posture double-reporting is
// harmless (idempotent), and this keeps the user from ever having to launch the
// agent by hand: the tray auto-starts at login and remote support "just works".
func (a *app) runRemoteSupportAgent() {
	// Never let a transient failure permanently stop remote-support handling —
	// that would leave the operator with the "start a new session but it won't
	// stream until I restart the client" symptom. Recover from panics and
	// restart the agent loop with a short backoff if Run ever returns.
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					a.logger.Error("tray remote-support agent panicked", zap.Any("recover", r))
				}
			}()
			ag, err := agent.NewAgent(a.logger, a.configDir)
			if err != nil {
				a.logger.Warn("tray: could not start remote-support agent", zap.Error(err))
				return
			}
			ag.RegisterBuiltinChecks()
			a.mu.Lock()
			a.rsAgent = ag
			a.mu.Unlock()
			if err := ag.Run(context.Background()); err != nil && err != context.Canceled {
				a.logger.Warn("tray remote-support agent stopped; will restart", zap.Error(err))
			}
		}()
		time.Sleep(3 * time.Second)
	}
}

// updateStatus composes the status line from the sign-in state and the
// device-service status (best-effort, over the named pipe).
func (a *app) updateStatus() {
	a.mu.Lock()
	signedIn := a.tokens != nil
	a.mu.Unlock()

	signPart := "Not signed in"
	if signedIn {
		signPart = "Signed in"
	}
	devPart := "device: unknown"
	if st, err := ipc.Query(); err == nil && st != nil {
		if st.Enrolled {
			devPart = "device: enrolled"
			if st.ZitiEnrolled {
				devPart += " · ziti"
			}
		} else {
			devPart = "device: not enrolled"
		}
		a.updateBanner(st.RemoteSupportActive, st.RemoteSupportControlled)
	}
	a.mStatus.SetTitle(signPart + " · " + devPart)
}

// updateBanner raises or clears the remote-support notice at the top of the
// tray menu and reflects it in the tooltip, so the person at the device always
// knows when an admin can see/control it.
func (a *app) updateBanner(active, controlled bool) {
	if a.mBanner == nil {
		return
	}
	if !active {
		a.mBanner.Hide()
		systray.SetTooltip("OpenIDX")
		return
	}
	msg := "🔴 An OpenIDX admin can see this device"
	if controlled {
		msg = "🔴 An OpenIDX admin can see and CONTROL this device"
	}
	a.mBanner.SetTitle(msg)
	a.mBanner.Show()
	systray.SetTooltip(msg)
}

func (a *app) statusTicker() {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for range t.C {
		a.updateStatus()
	}
}

func (a *app) loop(mQuit *systray.MenuItem) {
	for {
		select {
		case <-a.mSignIn.ClickedCh:
			go a.signIn()
		case <-a.mSignOut.ClickedCh:
			a.signOut()
		case <-mQuit.ClickedCh:
			systray.Quit()
			return
		}
	}
}

func (a *app) signIn() {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	t, err := sso.Login(ctx, a.serverURL)
	if err != nil {
		a.logger.Warn("tray: sign-in failed", zap.Error(err))
		a.mStatus.SetTitle("Sign-in failed")
		return
	}
	_ = authstore.Save(a.configDir, t)
	a.setSignedIn(t)
}

func (a *app) signOut() {
	_ = authstore.Clear(a.configDir)
	a.mu.Lock()
	a.tokens = nil
	a.mu.Unlock()
	a.mSignIn.Show()
	a.mSignOut.Hide()
	a.updateStatus()
	for i, mi := range a.connSlot {
		mi.Hide()
		a.slotID[i] = ""
	}
}

func (a *app) setSignedIn(t *sso.Tokens) {
	a.mu.Lock()
	a.tokens = t
	a.mu.Unlock()
	a.mSignIn.Hide()
	a.mSignOut.Show()
	a.updateStatus()
	go a.refreshConnections()
}

func (a *app) refreshConnections() {
	a.mu.Lock()
	t := a.tokens
	a.mu.Unlock()
	if t == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	entries, err := desktoppam.ListEntries(ctx, a.serverURL, t.AccessToken)
	if err != nil {
		a.logger.Warn("tray: list connections failed", zap.Error(err))
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, mi := range a.connSlot {
		if i < len(entries) {
			mi.SetTitle(entries[i].Name)
			a.slotID[i] = entries[i].ID
			mi.Show()
		} else {
			mi.Hide()
			a.slotID[i] = ""
		}
	}
}

func (a *app) watchSlot(i int, mi *systray.MenuItem) {
	for range mi.ClickedCh {
		a.mu.Lock()
		id := a.slotID[i]
		t := a.tokens
		a.mu.Unlock()
		if id == "" || t == nil {
			continue
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if _, err := desktoppam.Connect(ctx, a.serverURL, t.AccessToken, id); err != nil {
				a.logger.Warn("tray: connect failed", zap.String("entry", id), zap.Error(err))
			}
		}()
	}
}
