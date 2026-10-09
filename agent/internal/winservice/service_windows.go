//go:build windows

// Package winservice hosts the OpenIDX agent as a Windows Service so the
// device-trust posture loop runs always-on under LocalSystem in session 0.
package winservice

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/ipc"
	"github.com/openidx/openidx/agent/internal/updater"
)

// statusProvider builds a read-only status snapshot for the tray from the
// persisted agent config and the running agent's latest posture cycle.
func (h *handler) statusProvider() ipc.Status {
	cfg, err := agent.LoadConfig(h.configDir)
	if err != nil || cfg == nil {
		return ipc.Status{Enrolled: false}
	}
	zitiUp := false
	if cfg.ZitiIdentityFile != "" {
		if _, statErr := os.Stat(cfg.ZitiIdentityFile); statErr == nil {
			zitiUp = true
		}
	}
	var rsActive, rsControlled, revoked bool
	var posture *agent.PostureSummary
	h.mu.Lock()
	if h.agent != nil {
		rsActive, rsControlled = h.agent.RemoteSupportState()
		revoked = h.agent.Revoked()
		posture = h.agent.LastPosture()
	}
	h.mu.Unlock()
	st := ipc.Status{
		Enrolled:                cfg.AgentID != "",
		AgentID:                 cfg.AgentID,
		DeviceID:                cfg.DeviceID,
		ServerURL:               cfg.ServerURL,
		ZitiEnrolled:            zitiUp,
		Revoked:                 revoked,
		RemoteSupportActive:     rsActive,
		RemoteSupportControlled: rsControlled,
	}
	fillPosture(&st, posture)
	return st
}

// ServiceName is the Windows Service key/name.
const ServiceName = "OpenIDXAgent"

// enrolmentRecheck is how often an unenrolled service looks for agent.json.
const enrolmentRecheck = 30 * time.Second

// DisplayName is shown in services.msc.
const DisplayName = "OpenIDX Agent"

// handler adapts the agent run-loop to the Windows Service control protocol.
type handler struct {
	logger    *zap.Logger
	configDir string
	version   string

	mu    sync.Mutex
	agent *agent.Agent // the running agent, for live status (remote-support banner)
}

// Execute implements svc.Handler.
func (h *handler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		// A device enrolled after the service started (every MSI install: the
		// service starts before the enrol action runs; every link or code
		// enrolment) must not need a reboot to get its posture loop.
		a, err := agent.WaitEnrolled(ctx, h.logger, h.configDir, enrolmentRecheck)
		if err != nil {
			if ctx.Err() == nil {
				h.logger.Error("service: creating agent", zap.Error(err))
			}
			cancel()
			return
		}
		// The service runs in session 0 (no interactive desktop), so screen
		// capture would be black and injected input would go nowhere. Remote
		// support runs in the TRAY (user session) instead; the service only does
		// posture/enrollment/self-update.
		a.DisableRemoteSupport = true
		a.RegisterBuiltinChecks()
		a.LoadPlugins()
		h.mu.Lock()
		h.agent = a
		h.mu.Unlock()
		if err := a.Run(ctx); err != nil && err != context.Canceled {
			h.logger.Error("service: agent run failed", zap.Error(err))
		}
		cancel()
	}()

	// Expose read-only status to the user-session tray over a named pipe.
	go func() {
		if err := ipc.Serve(ctx, h.statusProvider); err != nil {
			h.logger.Warn("service: ipc server stopped", zap.Error(err))
		}
	}()
	// Periodic self-update (no-op unless update_manifest_url is configured).
	go h.updateLoop(ctx)
	// The tray in every signed-in session, right after an install or upgrade
	// rather than at the next sign-in.
	go h.trayLoop(ctx)

	s <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case <-ctx.Done():
			s <- svc.Status{State: svc.StopPending}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				h.logger.Info("service: stop requested")
				cancel()
				s <- svc.Status{State: svc.StopPending}
				return false, 0
			}
		}
	}
}

// IsWindowsService reports whether the process was started by the SCM.
func IsWindowsService() (bool, error) { return svc.IsWindowsService() }

// Run runs the agent under the Windows Service control manager.
func Run(logger *zap.Logger, configDir, version string) error {
	return svc.Run(ServiceName, &handler{logger: logger, configDir: configDir, version: version})
}

// updateLoop periodically self-updates when an update manifest is configured.
func (h *handler) updateLoop(ctx context.Context) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cfg, err := agent.LoadConfig(h.configDir)
			if err != nil || cfg == nil || cfg.UpdateManifestURL == "" {
				continue
			}
			// The manifest URL and the publisher certificate decide what this
			// service installs as SYSTEM. They are obeyed only from a file that
			// nobody but SYSTEM and an administrator could have written.
			if err := agent.ConfigTrusted(h.configDir); err != nil {
				h.logger.Error("service: not updating: agent.json could have been written by an "+
					"account this service does not trust", zap.Error(err))
				continue
			}
			// Resolved per poll rather than once at startup so an operator who
			// corrects update_trusted_cert does not have to restart the service
			// — and so a malformed one is reported every six hours instead of
			// silently disabling updates for the life of the process.
			trust, err := updater.TrustForConfig(cfg.UpdateTrustedCertPEM)
			if err != nil {
				h.logger.Warn("service: no usable update publisher; not updating", zap.Error(err))
				continue
			}
			applied, newV, err := updater.CheckAndApply(ctx, cfg.UpdateManifestURL, h.version, trust)
			if err != nil {
				h.logger.Warn("service: update check failed",
					zap.String("publisher", trust.Describe()), zap.Error(err))
			} else if applied {
				h.logger.Info("service: applying update", zap.String("version", newV))
			}
		}
	}
}

// Install registers the service (auto-start, LocalSystem) to launch the given
// exe with `service run --config-dir <dir>`.
func Install(exePath, configDir string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(ServiceName); err == nil {
		s.Close()
		return fmt.Errorf("service %s already installed", ServiceName)
	}

	s, err := m.CreateService(ServiceName, exePath, mgr.Config{
		DisplayName:  DisplayName,
		Description:  "OpenIDX device-trust agent (enrollment, posture, OpenZiti connectivity).",
		StartType:    mgr.StartAutomatic,
		Dependencies: []string{},
	}, "service", "run", "--config-dir", configDir)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	// Restart after a failure, as the MSI's util:ServiceConfig also sets; a
	// service installed by hand must not be the one that stays down.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
	}, 24*60*60); err != nil {
		return fmt.Errorf("set recovery actions: %w", err)
	}

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	return nil
}

// StartIfInstalled starts the service when it is installed and not running.
// It is called after an enrolment so the posture loop begins at once; the
// service also notices on its own within enrolmentRecheck. Not installed is
// not an error (a foreground `run` has no service); a stopped service that
// cannot be started is.
func StartIfInstalled() (started bool, err error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return false, nil
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return false, fmt.Errorf("query service: %w", err)
	}
	if st.State != svc.Stopped {
		return false, nil
	}
	if err := s.Start(); err != nil {
		return false, fmt.Errorf("start service: %w", err)
	}
	return true, nil
}

// Uninstall stops and removes the service.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s not installed: %w", ServiceName, err)
	}
	defer s.Close()

	_, _ = s.Control(svc.Stop)
	// Give it a moment to stop before deleting.
	time.Sleep(500 * time.Millisecond)
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	return nil
}
