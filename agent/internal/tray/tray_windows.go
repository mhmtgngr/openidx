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

	mStatus   *systray.MenuItem
	mSignIn   *systray.MenuItem
	mSignOut  *systray.MenuItem
	mConnRoot *systray.MenuItem

	mu       sync.Mutex
	tokens   *sso.Tokens
	connSlot []*systray.MenuItem
	slotID   []string // slot index -> entry id
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
	}
	a.mStatus.SetTitle(signPart + " · " + devPart)
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
