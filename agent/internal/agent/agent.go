package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/checks"
	"github.com/openidx/openidx/agent/internal/devicekey"
	"github.com/openidx/openidx/agent/internal/plugin"
	"github.com/openidx/openidx/agent/internal/remotesupport"
	"github.com/openidx/openidx/agent/internal/transport"
	"github.com/openidx/openidx/agent/internal/tunnel"
	"github.com/openidx/openidx/agent/internal/updater"
)

// Agent orchestrates configuration syncing, check execution, and result reporting.
type Agent struct {
	logger    *zap.Logger
	config    *AgentConfig
	configDir string
	client    transport.Transport
	registry  *checks.Registry
	engine    *checks.Engine
	serverCfg *ServerConfig

	// ConsentDecider decides how to answer a consent-required remote-support
	// session. It returns "grant", "deny", or "" (defer — decide later, e.g.
	// while a native Allow/Deny dialog is still open). The tray can install a
	// prompt-backed decider; the default is policy-driven (see
	// defaultConsentDecider). Called at most once per session id.
	ConsentDecider func(rs *RemoteSupportBlock) string
	// handledConsent tracks session ids we have already answered so a repeated
	// config poll does not re-submit a decision.
	handledConsent map[string]bool
	// handledSessions tracks session ids we have already begun streaming so a
	// repeated config poll does not launch a second peer for the same session.
	handledSessions map[string]bool
	// RemoteInputSink, when set, receives inbound pointer/keyboard/control
	// events for an active remote-support session (a Windows SendInput injector
	// installs one). Nil = view-only (no input applied).
	RemoteInputSink remotesupport.InputSink
	// remoteSupportActive/Controlled expose live session state for the tray
	// banner ("An OpenIDX admin can see and control this device"). Set while a
	// session streams; controlled follows the admin's control_state toggle.
	remoteSupportActive     atomic.Bool
	remoteSupportControlled atomic.Bool
	// lastPosture is the outcome of the latest posture cycle, for the tray.
	lastPosture atomic.Pointer[PostureSummary]

	// DisableRemoteSupport gates the remote-support screen-share + input path.
	// The Windows SERVICE runs in session 0, which has no interactive desktop,
	// so a capture there is black and input goes nowhere. The service sets this
	// true and the TRAY (running in the user session) runs remote-support
	// instead. Default false = enabled (single-process / foreground `run`).
	DisableRemoteSupport bool

	// LoggedOnUser, when set, names the person signed in at the console
	// (DOMAIN\user or a UPN). The Windows service sets it; the report carries
	// it as logged_on_user, which the server reads only under claim_mode
	// logged_on_user to give an ownerless device its owner.
	LoggedOnUser func() string

	// revoked is set when the server answers /agent/config with 403: an
	// administrator revoked this device. Nothing the agent sends after that
	// is accepted, so the cycle stops at the sync until a sync succeeds again
	// (a re-enrolled device, after the service restarts with its new token).
	revoked atomic.Bool

	// authFails counts the config syncs in a row the server answered 401: it
	// does not accept the credential this device holds. authInvalid is set once
	// that count reaches authFailThreshold. Unlike a revoke, the device can fix
	// it itself by enrolling again; unlike an unreachable server, retrying
	// never will. A device left in this state used to report into the void for
	// months while its tray said "enrolled".
	authFails   atomic.Int32
	authInvalid atomic.Bool

	// RemoteSupportOnly makes RunOnce poll the server's config, so a pending
	// remote-support session is noticed and answered, and do nothing else: no
	// posture check runs and no report is posted. The Windows TRAY sets it.
	// The SYSTEM service is the one posture reporter; a second report from
	// the user session, made without administrator rights, read BitLocker and
	// the firewall differently and contradicted the service's results on the
	// server. Default false = the full cycle.
	RemoteSupportOnly bool

	// tun supervises the bundled OpenZiti tunneler (tunnel.go). Nil until
	// Run starts it, and always nil in a RemoteSupportOnly agent.
	tun atomic.Pointer[tunnel.Supervisor]
	// orgAlwaysOn is the server's org_network_policy.always_on.
	orgAlwaysOn atomic.Bool
	// tunLocalOn is a trusted agent.json's tunnel.enabled (tunnel.go).
	tunLocalOn atomic.Bool
	// netPolicy is the last versioned org_network_policy the server sent and
	// how this device applied it; directBlock enforces its block on direct
	// corporate access where the platform can (tunnel.go). directBlock is set
	// by startTunnel, so only the process that supervises the tunnel ever
	// touches the firewall.
	netPolicy   atomic.Pointer[appliedPolicy]
	directBlock atomic.Pointer[tunnel.DirectBlock]
	policyMu    sync.Mutex

	// deviceKey signs posture reports once loaded (device_key.go).
	deviceKey       devicekey.Key
	deviceKeyFailed bool
	lastKeyOffer    time.Time
}

// NewAgent loads the persisted agent config from configDir, creates a transport
// client, and initialises an empty check registry and engine.
func NewAgent(logger *zap.Logger, configDir string) (*Agent, error) {
	cfg, err := LoadConfig(configDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %v", ErrNotEnrolled, err)
		}
		return nil, fmt.Errorf("loading agent config: %w", err)
	}
	if cfg.AgentID == "" {
		return nil, fmt.Errorf("%w: agent.json names no agent", ErrNotEnrolled)
	}

	client := transport.NewTransport(cfg.ServerURL, cfg.AuthToken, cfg.AgentID, cfg.ZitiIdentityFile, cfg.ZitiServiceName, logger)
	registry := checks.NewRegistry()
	engine := checks.NewEngine(registry)

	defaultCfg := DefaultServerConfig()
	a := &Agent{
		logger:    logger,
		config:    cfg,
		configDir: configDir,
		client:    client,
		registry:  registry,
		engine:    engine,
		serverCfg: &defaultCfg,
	}

	return a, nil
}

// builtinChecks is the one list of the agent's own checks, by registry name.
// RegisterBuiltinChecks registers it and LoadPlugins refuses a plugin that
// declares any name in it, so a check added here is protected from being
// replaced by a plugin without anyone having to remember a second list.
func builtinChecks() map[string]checks.Check {
	return map[string]checks.Check{
		"os_version":      &checks.OSVersionCheck{},
		"disk_encryption": &checks.DiskEncryptionCheck{},
		"process_running": &checks.ProcessCheck{},
		"firewall":        &checks.FirewallCheck{},
		"screen_lock":     &checks.ScreenLockCheck{},
		"antivirus":       &checks.AntivirusCheck{},
		"domain_joined":   &checks.DomainCheck{},
		"patch_level":     &checks.PatchLevelCheck{},
		"integrity":       &checks.IntegrityCheck{},
		"agent_version":   &checks.AgentVersionCheck{},
	}
}

// RegisterBuiltinChecks registers the built-in check implementations with the
// agent's registry.
func (a *Agent) RegisterBuiltinChecks() {
	for name, c := range builtinChecks() {
		a.registry.Register(name, c)
	}
}

// Registry returns the agent's check registry. Exposed primarily for testing.
func (a *Agent) Registry() *checks.Registry {
	return a.registry
}

// LoadPlugins discovers plugins in the configured plugin directory and registers
// each as a PluginCheck in the agent's registry. If no PluginDir is configured,
// LoadPlugins is a no-op.
func (a *Agent) LoadPlugins() {
	pluginDir := a.config.PluginDir
	if pluginDir == "" {
		return
	}
	// plugin_dir is obeyed only from a config file nobody but the service and
	// an administrator could have written. The loader checks the plugin
	// directory and each executable the same way; this closes the hop before
	// them, where the directory itself is chosen.
	if err := ConfigTrusted(a.configDir); err != nil {
		a.logger.Error("not loading plugins: agent.json could have been written by an account "+
			"this service does not trust", zap.Error(err))
		return
	}

	// A plugin runs with the same privileges an update installs with, so it
	// must be signed by the same publisher: the pinned OpenIDX release key, or
	// the operator's own named by update_trusted_cert. Neither the service nor
	// the CLI chooses this for itself; TrustForConfig is the one answer.
	policy := plugin.Policy{AllowUnsigned: a.config.AllowUnsignedPlugins}
	for name := range builtinChecks() {
		policy.ReservedCheckTypes = append(policy.ReservedCheckTypes, name)
	}
	if trust, err := updater.TrustForConfig(a.config.UpdateTrustedCertPEM); err == nil {
		policy.Verifier = trust
	} else if !policy.AllowUnsigned {
		a.logger.Error("not loading plugins: update_trusted_cert, which names the publisher plugins "+
			"must be signed by, cannot be used", zap.Error(err))
		return
	}
	if policy.AllowUnsigned {
		a.logger.Warn("allow_unsigned_plugins is set: plugins are loaded without checking who " +
			"published them. This is meant for a lab, not for a managed fleet")
	}

	loader := plugin.NewLoader(pluginDir, policy, a.logger)
	plugins, err := loader.Discover()
	if err != nil {
		a.logger.Error("plugin discovery failed", zap.String("dir", pluginDir), zap.Error(err))
		return
	}

	for _, p := range plugins {
		a.registry.Register(p.Name(), p)
		a.logger.Info("plugin registered", zap.String("check_type", p.Name()))
	}

	if len(plugins) > 0 {
		a.logger.Info("plugins loaded", zap.Int("count", len(plugins)))
	}
}

// SyncConfig fetches the server-side configuration via the transport client and
// parses it into a ServerConfig. On any error it falls back to DefaultServerConfig
// and logs a warning.
func (a *Agent) SyncConfig(ctx context.Context) error {
	data, err := a.client.GetConfig()
	if errors.Is(err, transport.ErrAgentAuthInvalid) && a.reloadIfReenrolled() {
		// The device was enrolled again while this process ran (a code or
		// link enrolment: the service is already running, so nothing restarts
		// it). Ask again with the credential that enrolment wrote.
		data, err = a.client.GetConfig()
	}
	if err != nil {
		def := DefaultServerConfig()
		a.serverCfg = &def
		if errors.Is(err, transport.ErrAgentRevoked) {
			// The one failure that is a state. Log it once, loudly: a device
			// that keeps warning "failed to fetch server config" every hour
			// looks like a network problem to whoever reads the log.
			if !a.revoked.Swap(true) {
				a.logger.Error("this device has been revoked by an administrator; " +
					"posture reporting stops until it is enrolled again")
			}
			a.forgetSealedToken()
			return fmt.Errorf("fetching server config: %w", err)
		}
		if errors.Is(err, transport.ErrAgentAuthInvalid) {
			// One 401 may be a passing fault (a restore, a racing re-enrol);
			// several in a row are a state, said once.
			n := a.authFails.Add(1)
			if n >= authFailThreshold && a.reenrolFromSealedToken() {
				// The refusal was a state, and the device's sealed fleet token
				// fixed it (sealed_token.go). Ask with the new credential.
				if data, err = a.client.GetConfig(); err == nil {
					return a.acceptConfig(data)
				}
			}
			if n >= authFailThreshold && !a.authInvalid.Swap(true) {
				a.logger.Error("the server no longer accepts this device's credential; "+
					"posture reporting stops until the device is enrolled again "+
					"(My Devices -> Add a device)", zap.Int32("refusals_in_a_row", n))
			}
			return fmt.Errorf("fetching server config: %w", err)
		}
		a.logger.Warn("failed to fetch server config, using defaults", zap.Error(err))
		return fmt.Errorf("fetching server config: %w", err)
	}
	return a.acceptConfig(data)
}

// acceptConfig clears the refusal states after a config sync succeeded and
// applies the config it returned.
func (a *Agent) acceptConfig(data []byte) error {
	if a.revoked.Swap(false) {
		a.logger.Info("the server accepts this device again; posture reporting resumes")
	}
	a.authFails.Store(0)
	if a.authInvalid.Swap(false) {
		a.logger.Info("the server accepts this device's credential again; posture reporting resumes")
	}

	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		def := DefaultServerConfig()
		a.serverCfg = &def
		a.logger.Warn("failed to parse server config, using defaults", zap.Error(err))
		return fmt.Errorf("parsing server config: %w", err)
	}

	a.serverCfg = &cfg
	a.logger.Info("server config synced", zap.Int("checks", len(cfg.Checks)))
	a.applyNetworkPolicy(cfg.OrgNetworkPolicy)
	if !a.DisableRemoteSupport {
		a.processRemoteSupportConsent(cfg.RemoteSupport)
	}
	return nil
}

// defaultConsentDecider answers a consent-required session when no prompt is
// wired: it denies. A session the administrator started as attended is one
// the person at the device must allow, and a process with no way to ask them
// cannot say they did. It used to grant, so the runbook's Allow/Deny step was
// never shown and every attended session began as if it had been. An
// unattended session (consent_required false) never reaches this; the tray
// installs a prompt-backed decider (Agent.ConsentDecider) for attended ones.
func defaultConsentDecider(_ *RemoteSupportBlock) string { return "deny" }

// processRemoteSupportConsent answers a consent-required remote-support session
// that is still pending. It is a no-op when there is no session, consent is not
// required, or the decision was already sent. The admin cannot view/control
// until the device grants (server-enforced in HandleAdminWS), so this is the
// device's half of the attended-support handshake.
func (a *Agent) processRemoteSupportConsent(rs *RemoteSupportBlock) {
	if rs == nil || !rs.ConsentRequired || rs.SessionID == "" {
		// No consent required (or no session): if a session is present and
		// already grantable, stream it directly.
		if rs != nil && rs.SessionID != "" && rs.WSPath != "" &&
			(!rs.ConsentRequired || rs.ConsentStatus == "granted") {
			a.runRemoteSupport(rs)
		}
		return
	}
	if rs.ConsentStatus == "granted" {
		a.runRemoteSupport(rs) // already granted (e.g. reconnect) — stream
		return
	}
	if rs.ConsentStatus != "pending" {
		return // denied
	}
	if a.handledConsent == nil {
		a.handledConsent = map[string]bool{}
	}
	if a.handledConsent[rs.SessionID] {
		return
	}
	decide := a.ConsentDecider
	if decide == nil {
		a.logger.Warn("remote-support session asks for consent and this process has no way to ask the user; denying",
			zap.String("session_id", rs.SessionID))
		decide = defaultConsentDecider
	}
	decision := decide(rs)
	if decision != "grant" && decision != "deny" {
		return // deferred — a native prompt is still open; try again next poll
	}
	if err := a.client.SendConsent(rs.SessionID, decision); err != nil {
		a.logger.Warn("remote-support consent send failed",
			zap.String("session_id", rs.SessionID), zap.String("decision", decision), zap.Error(err))
		return
	}
	a.handledConsent[rs.SessionID] = true
	a.logger.Info("remote-support consent sent",
		zap.String("session_id", rs.SessionID), zap.String("decision", decision))
	// On grant, begin streaming immediately (don't wait for the next poll).
	if decision == "grant" {
		rs.ConsentStatus = "granted"
		a.runRemoteSupport(rs)
	}
}

// reportPayload is the JSON body sent to the report endpoint.
type reportPayload struct {
	AgentID    string         `json:"agent_id"`
	DeviceID   string         `json:"device_id"`
	Results    []engineResult `json:"results"`
	ReportedAt time.Time      `json:"reported_at"`
	// TunnelStatus is the bundled tunneler's state. Omitted by an agent that
	// supervises none, so the server can tell "no tunnel support" from "off".
	TunnelStatus *tunnel.Status `json:"tunnel_status,omitempty"`
	// LoggedOnUser is the console session's user, when the service knows it.
	LoggedOnUser string `json:"logged_on_user,omitempty"`
}

// engineResult is one result in the report, in the shape the access service
// reads (internal/access/agent_api.go checkResult): the outcome nested under
// "result". It used to send the outcome flat at the top level, which the
// server does not read, so every Windows report was stored with an empty
// status and a zero score and the device's compliance stayed "unknown".
type engineResult struct {
	CheckType string       `json:"check_type"`
	Severity  string       `json:"severity"`
	Result    resultDetail `json:"result"`
	RanAt     time.Time    `json:"ran_at"`
}

// resultDetail is the outcome of one check.
type resultDetail struct {
	Status      checks.Status          `json:"status"`
	Score       float64                `json:"score"`
	Message     string                 `json:"message,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// RunOnce performs a single sync-check-report cycle:
//  1. SyncConfig — fetch latest check config from the server.
//  2. Run all configured checks via the engine.
//  3. Marshal results and POST them to the report endpoint.
//
// SyncConfig errors are logged but do not abort the cycle; the agent proceeds
// with whatever config is currently loaded.
func (a *Agent) RunOnce(ctx context.Context) error {
	// Best-effort config sync; proceed even on failure.
	if err := a.SyncConfig(ctx); err != nil {
		a.logger.Warn("config sync failed, proceeding with cached config", zap.Error(err))
	}
	if a.RemoteSupportOnly {
		// The sync above is the whole job: it hands any remote-support
		// session to processRemoteSupportConsent. Posture is the service's.
		return nil
	}
	if a.revoked.Load() || a.authInvalid.Load() {
		// A report from a revoked device is refused with the same 403, and one
		// from a device whose credential is refused with the same 401; running
		// the checks for it is wasted work and a second error line per cycle.
		return nil
	}
	a.bindDeviceKey()

	engineResults := a.engine.RunChecks(ctx, a.serverCfg.Checks)
	summary := summarizePosture(engineResults, a.serverCfg.EnforcementPolicy, time.Now().UTC())
	a.lastPosture.Store(&summary)

	results := make([]engineResult, 0, len(engineResults))
	for _, er := range engineResults {
		results = append(results, engineResult{
			CheckType: er.CheckType,
			Severity:  er.Severity,
			Result: resultDetail{
				Status:      er.Result.Status,
				Score:       er.Result.Score,
				Message:     er.Result.Message,
				Remediation: er.Result.Remediation,
				Details:     er.Result.Details,
			},
			RanAt: er.RanAt,
		})
	}

	payload := reportPayload{
		AgentID:      a.config.AgentID,
		DeviceID:     a.config.DeviceID,
		Results:      results,
		ReportedAt:   time.Now().UTC(),
		TunnelStatus: a.TunnelStatus(),
	}
	if a.LoggedOnUser != nil {
		payload.LoggedOnUser = a.LoggedOnUser()
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling report payload: %w", err)
	}

	if rr, ok := a.client.(transport.ReportResponder); ok {
		body, err := rr.ReportResultsResponse(data)
		if err != nil {
			return fmt.Errorf("reporting results: %w", err)
		}
		a.applyReportResponse(body)
	} else if err := a.client.ReportResults(data); err != nil {
		return fmt.Errorf("reporting results: %w", err)
	}

	a.logger.Info("results reported", zap.Int("checks", len(results)))
	return nil
}

// Revoked reports whether the server has refused this device as revoked on
// its last config sync. The service passes it to the tray over the status
// pipe, so the person at the device is told rather than left with a menu that
// looks signed in and connections that never open.
func (a *Agent) Revoked() bool { return a.revoked.Load() }

// authFailThreshold is how many config syncs in a row must be refused 401
// before the device calls its credential invalid. At the default hourly
// interval that is a few hours, which rides out a server restore or a racing
// re-enrolment and still tells the person the same day.
const authFailThreshold = 3

// AuthInvalid reports whether the server has refused this device's credential
// on authFailThreshold config syncs in a row. The service passes it to the
// tray, which tells the person to enroll the device again.
func (a *Agent) AuthInvalid() bool { return a.authInvalid.Load() }

// reloadIfReenrolled re-reads agent.json and, when it now holds a different
// credential than this process started with, switches to it. It reports
// whether it switched.
//
// The running service read agent.json once. An enrolment made while it runs,
// from a code or a link (the way a person fixes a refused credential), writes
// a new token to the file, and "openidx-agent enroll" only starts a service
// that is stopped. Without this the service kept presenting the old token, was
// refused, and the device stayed broken until a reboot. It runs only after a
// 401, so a healthy device never re-reads the file.
//
// The service sets DisableRemoteSupport, so no other goroutine of it uses the
// client; SyncConfig, the only caller, runs on the agent's own loop. Any other
// process (the tray, a foreground "run") may have a remote-support stream on
// the client, so it never swaps it; restarting it picks the new file up.
func (a *Agent) reloadIfReenrolled() bool {
	if !a.DisableRemoteSupport {
		return false
	}
	cfg, err := LoadConfig(a.configDir)
	if err != nil || cfg == nil || cfg.AgentID == "" || cfg.AuthToken == "" {
		return false
	}
	if cfg.AuthToken == a.config.AuthToken && cfg.AgentID == a.config.AgentID {
		return false
	}
	a.config = cfg
	a.client = transport.NewTransport(cfg.ServerURL, cfg.AuthToken, cfg.AgentID,
		cfg.ZitiIdentityFile, cfg.ZitiServiceName, a.logger)
	if a.deviceKey != nil {
		transport.SetSigner(a.client, devicekey.Signer{Key: a.deviceKey, AgentID: cfg.AgentID})
	}
	a.logger.Info("agent.json holds a new enrolment; using its credential",
		zap.String("agent_id", cfg.AgentID))
	return true
}

// Run executes an initial RunOnce cycle and then repeats on the interval
// specified by serverCfg.ReportInterval. It blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.logger.Info("agent starting", zap.String("agent_id", a.config.AgentID))
	if !a.RemoteSupportOnly {
		a.startTunnel(ctx)
	}

	if err := a.RunOnce(ctx); err != nil {
		a.logger.Error("initial run failed", zap.Error(err))
	}

	interval := parseInterval(a.serverCfg.ReportInterval, time.Hour)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("agent shutting down")
			return ctx.Err()
		case <-ticker.C:
			// Re-read interval in case SyncConfig updated serverCfg.
			newInterval := parseInterval(a.serverCfg.ReportInterval, time.Hour)
			if newInterval != interval {
				interval = newInterval
				ticker.Reset(interval)
			}

			if err := a.RunOnce(ctx); err != nil {
				a.logger.Error("run cycle failed", zap.Error(err))
			}
		}
	}
}

// parseInterval parses a duration string, returning fallback on any error.
func parseInterval(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

// LastPosture returns the outcome of the latest posture cycle, or nil before
// the first one has run.
func (a *Agent) LastPosture() *PostureSummary { return a.lastPosture.Load() }
