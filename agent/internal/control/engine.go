// Package control provides the OpenIDX native-client "engine": a headless
// facade over the agent's existing SSO / enrollment / PAM / posture / Ziti
// capabilities, plus a local control server (see server.go) that a desktop GUI
// talks to.
//
// The Engine facade is deliberately gomobile-friendly: every exported method
// takes and returns only string / []byte / bool / int values and returns a
// (result, error) pair. No generics, channels, maps, slices, or rich structs
// cross the boundary — rich data is marshalled to a JSON string. This lets
// Phase 2 `gomobile bind` the SAME facade for the mobile app with no changes.
package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/authstore"
	"github.com/openidx/openidx/agent/internal/checks"
	"github.com/openidx/openidx/agent/internal/desktoppam"
	"github.com/openidx/openidx/agent/internal/sso"
	"github.com/openidx/openidx/agent/internal/ziti"
)

// backend is the seam over the network-touching engine APIs (sso / pam /
// enrollment). Tests inject a fake so the HTTP layer can be exercised without a
// live OpenIDX server. The default implementation (realBackend) calls the
// existing packages verbatim.
type backend interface {
	// Login carries the enrolled agent id (empty when not enrolled) so the
	// session can be bound to the device and revoked with it.
	Login(ctx context.Context, serverURL, agentID string) (*sso.Tokens, error)
	Enroll(logger *zap.Logger, serverURL, token, configDir string) (agentID, deviceID, zitiIdentity string, err error)
	PamList(ctx context.Context, serverURL, token string) ([]desktoppam.Entry, error)
	PamConnect(ctx context.Context, serverURL, token, entryID string) (connectURL string, err error)
	PamRequest(ctx context.Context, serverURL, token, entryID, reason string) error
	CompletePushEnroll(serverURL, path, ticket, deviceToken, platform, deviceName string, insecure bool) error
}

// zitiDialer is the seam over the embedded Ziti bridge so tests do not require a
// real enrolled identity. Mirrors *ziti.Dialer.
type zitiDialer interface {
	Bridge(service string) (localAddr string, stop func(), err error)
	Close()
}

// Engine is the headless native-client facade. Construct via NewEngine.
type Engine struct {
	configDir string
	serverURL string
	logger    *zap.Logger

	be           backend
	newDialer    func(identityFile string) (zitiDialer, error)
	loginTimeout time.Duration

	mu                 sync.Mutex
	bridges            map[string]*bridge // active Ziti bridges keyed by service name
	pendingMobileLogin *sso.MobileLogin   // in-flight deep-link login (LoginStart→LoginFinish)
}

type bridge struct {
	localAddr string
	stop      func()
	dialer    zitiDialer
}

// NewEngine loads the enrolled server URL from the agent config in configDir and
// returns a ready facade. A missing/unparseable config is tolerated (serverURL
// is left empty); methods that need a server return a clear error at call time,
// so a not-yet-enrolled device can still report Status.
func NewEngine(configDir string, logger *zap.Logger) (*Engine, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	serverURL := ""
	if cfg, err := agent.LoadConfig(configDir); err == nil {
		serverURL = strings.TrimRight(cfg.ServerURL, "/")
	}
	return &Engine{
		configDir:    configDir,
		serverURL:    serverURL,
		logger:       logger,
		be:           realBackend{},
		newDialer:    func(f string) (zitiDialer, error) { return ziti.NewDialer(f) },
		loginTimeout: 5 * time.Minute,
		bridges:      map[string]*bridge{},
	}, nil
}

// ---- gomobile-friendly facade methods ----------------------------------

// statusPayload is the flat status snapshot (JSON-marshalled by Status).
type statusPayload struct {
	Enrolled     bool   `json:"enrolled"`
	AgentID      string `json:"agent_id,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	ServerURL    string `json:"server_url,omitempty"`
	ZitiEnrolled bool   `json:"ziti_enrolled"`
	LoggedIn     bool   `json:"logged_in"`
	UserSub      string `json:"user_sub,omitempty"`
	UserEmail    string `json:"user_email,omitempty"`
	TokenExpiry  int64  `json:"token_expiry,omitempty"`
	TokenExpired bool   `json:"token_expired,omitempty"`
}

// Status reports enrollment state, the logged-in user (from the cached OAuth
// token), and whether a Ziti identity is present, as a JSON string.
func (e *Engine) Status() (string, error) {
	var st statusPayload

	if cfg, err := agent.LoadConfig(e.configDir); err == nil {
		st.Enrolled = cfg.AgentID != ""
		st.AgentID = cfg.AgentID
		st.DeviceID = cfg.DeviceID
		st.ServerURL = strings.TrimRight(cfg.ServerURL, "/")
		st.ZitiEnrolled = cfg.ZitiIdentityFile != "" && fileExists(cfg.ZitiIdentityFile)
	}
	if st.ServerURL == "" {
		st.ServerURL = e.serverURL
	}
	// A bare ziti-identity.json in the config dir also counts.
	if !st.ZitiEnrolled && fileExists(e.zitiIdentityPath()) {
		st.ZitiEnrolled = true
	}

	if tok, err := authstore.Load(e.configDir); err == nil && tok != nil && tok.AccessToken != "" {
		st.LoggedIn = true
		st.TokenExpiry = tok.ExpiresAt
		if tok.ExpiresAt > 0 {
			st.TokenExpired = time.Now().Unix() >= tok.ExpiresAt
		}
		if sub, email, exp, ok := decodeJWTClaims(tok.AccessToken); ok {
			st.UserSub = sub
			st.UserEmail = email
			if st.TokenExpiry == 0 && exp > 0 {
				st.TokenExpiry = exp
			}
		}
	}

	return toJSON(st)
}

type userPayload struct {
	Sub   string `json:"sub,omitempty"`
	Email string `json:"email,omitempty"`
	Exp   int64  `json:"exp"`
}

// Login runs the interactive browser PKCE flow against the enrolled server,
// caches the tokens, and returns {sub,email,exp} as a JSON string.
func (e *Engine) Login() (string, error) {
	if e.serverURL == "" {
		return "", fmt.Errorf("no server configured: enroll first")
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.loginTimeout)
	defer cancel()

	tok, err := e.be.Login(ctx, e.serverURL, e.enrolledAgentID())
	if err != nil {
		return "", fmt.Errorf("login failed: %w", err)
	}
	if err := authstore.Save(e.configDir, tok); err != nil {
		return "", fmt.Errorf("saving session: %w", err)
	}
	sub, email, exp, _ := decodeJWTClaims(tok.AccessToken)
	if exp == 0 {
		exp = tok.ExpiresAt
	}
	return toJSON(userPayload{Sub: sub, Email: email, Exp: exp})
}

// LoginStart begins the custom-scheme deep-link login used on mobile, where the
// engine cannot open a browser itself. It generates PKCE + state and builds the
// openidx-mobile authorize URL (via sso.StartMobileLogin) and returns that URL
// for the caller (the Dart layer) to open with url_launcher. The server then
// redirects to openidx://oauth-callback?code=…&state=…, which the OS routes back
// to the app; the app hands the full callback URL to LoginFinish. Desktop keeps
// using Login().
func (e *Engine) LoginStart() (string, error) {
	if e.serverURL == "" {
		return "", fmt.Errorf("no server configured: enroll first")
	}
	m, authURL, err := sso.StartMobileLogin(e.serverURL)
	if err != nil {
		return "", fmt.Errorf("login failed: %w", err)
	}
	// Name the device, so the server binds this session's refresh family to it
	// and revoking the phone revokes the session (v185). Persisted with the
	// rest of the flow below, so the cold-start path sends it too.
	m.BindDevice(e.enrolledAgentID())
	e.mu.Lock()
	e.pendingMobileLogin = m
	e.mu.Unlock()
	// Also persist the flow to disk so it survives a process restart. On Android
	// the OS often kills the app while the browser is foreground and cold-starts
	// it to deliver the openidx://oauth-callback redirect; the relaunched process
	// has lost e.pendingMobileLogin and must reload the PKCE material from here to
	// complete the exchange. A save failure is non-fatal — the in-memory flow
	// still covers the warm path where the app stays alive.
	if err := m.Save(e.pendingLoginPath()); err != nil {
		e.logger.Warn("persisting pending mobile login failed; cold-start login will not survive a restart", zap.Error(err))
	}
	return authURL, nil
}

// pendingLoginPath is where LoginStart persists the in-flight mobile login so a
// cold-started process (see LoginStart/LoginFinish) can reload it.
func (e *Engine) pendingLoginPath() string {
	return filepath.Join(e.configDir, "login_pending.json")
}

// LoginFinish completes an in-flight LoginStart from the deep-link callback URL
// (openidx://oauth-callback?code=…&state=…) the app received. It extracts the
// code + state, exchanges the code for tokens, caches them, and returns
// {sub,email,exp} as a JSON string — the same shape as Login(). Errors if no
// login is in progress, if the callback carries an error, or if code is empty.
func (e *Engine) LoginFinish(callbackURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(callbackURL))
	if err != nil {
		return "", fmt.Errorf("invalid callback URL: %w", err)
	}
	q := u.Query()
	if authErr := q.Get("error"); authErr != "" {
		return "", fmt.Errorf("authorization error: %s", authErr)
	}
	code := q.Get("code")
	if code == "" {
		return "", fmt.Errorf("no authorization code in callback")
	}
	state := q.Get("state")

	e.mu.Lock()
	m := e.pendingMobileLogin
	e.mu.Unlock()
	if m == nil {
		// Warm-path flow is gone — most likely the app was killed during the
		// browser step and cold-started to deliver this callback. Reload the
		// persisted PKCE material from disk to complete the exchange.
		if loaded, lerr := sso.LoadMobileLogin(e.pendingLoginPath()); lerr == nil {
			m = loaded
		}
	}
	if m == nil {
		return "", fmt.Errorf("no login in progress")
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.loginTimeout)
	defer cancel()

	tok, err := m.Exchange(ctx, code, state)
	if err != nil {
		return "", fmt.Errorf("login failed: %w", err)
	}
	if err := authstore.Save(e.configDir, tok); err != nil {
		return "", fmt.Errorf("saving session: %w", err)
	}
	// Login is complete: drop the in-memory flow and the on-disk copy so a stale
	// authorization code can't be re-submitted and the file doesn't linger.
	e.mu.Lock()
	e.pendingMobileLogin = nil
	e.mu.Unlock()
	_ = os.Remove(e.pendingLoginPath())
	sub, email, exp, _ := decodeJWTClaims(tok.AccessToken)
	if exp == 0 {
		exp = tok.ExpiresAt
	}
	return toJSON(userPayload{Sub: sub, Email: email, Exp: exp})
}

// Logout ends the session on the server and then clears the local copy.
//
// It used to be authstore.Clear alone. Deleting the file makes the app look
// signed out; the refresh token it deleted stayed valid on the server for its
// full 30 days, so anyone who had already copied it — the case "sign out on a
// shared or lost device" exists for — kept a working credential. RFC 7009
// revocation is what actually ends it.
//
// The local clear happens whichever way the revocation goes: a user who signs
// out must not remain signed in because the network was down. A failure is
// logged rather than returned for the same reason.
func (e *Engine) Logout() error {
	if tok, err := authstore.Load(e.configDir); err == nil && tok != nil && tok.RefreshToken != "" && e.serverURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		// The client id is what the token endpoint authenticates the CALLER as;
		// handleRevoke identifies the token by its own value, so this names the
		// public client this engine uses (as AccessToken's refresh does) rather
		// than deciding which client minted the session.
		if rerr := sso.Revoke(ctx, e.serverURL, sso.MobileClientID, tok.RefreshToken); rerr != nil {
			e.logger.Warn("sign-out: server-side revocation failed; the refresh token stays valid until it expires",
				zap.Error(rerr))
		}
	}
	return authstore.Clear(e.configDir)
}

// enrolledAgentID is the agent id this installation is enrolled as, or "" when
// it is not enrolled yet. A login that names it can be revoked with the device
// (v185); one that cannot name it is simply unbound.
func (e *Engine) enrolledAgentID() string {
	cfg, err := agent.LoadConfig(e.configDir)
	if err != nil || cfg == nil {
		return ""
	}
	return cfg.AgentID
}

type enrollPayload struct {
	AgentID      string `json:"agent_id"`
	DeviceID     string `json:"device_id"`
	ServerURL    string `json:"server_url,omitempty"`
	ZitiIdentity string `json:"ziti_identity,omitempty"`
}

// SetServer configures the target/enrollment server URL. Mobile installs have no
// pre-seeded agent config, so the app supplies the server (from the enroll code's
// server field, an enroll deep-link, or manual entry) before calling Enroll. A
// successful Enroll then persists it to the config dir for subsequent launches.
func (e *Engine) SetServer(url string) error {
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	if url == "" {
		return fmt.Errorf("server URL is required")
	}
	e.mu.Lock()
	e.serverURL = url
	e.mu.Unlock()
	return nil
}

// Enroll enrolls this device with the (already-resolved) server using the
// supplied one-time enrollment code/token, and returns the result as JSON. The
// server URL is picked up from config on the next NewEngine; here we reuse the
// currently-loaded serverURL if present, otherwise require it be pre-set via
// config (Phase 0 keeps enrollment server-selection in the config dir).
func (e *Engine) Enroll(code string) (string, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return "", fmt.Errorf("enrollment code is required")
	}
	if e.serverURL == "" {
		return "", fmt.Errorf("no server configured for enrollment — call SetServer first (or use the enroll deep-link)")
	}
	agentID, deviceID, zitiIdentity, err := e.be.Enroll(e.logger, e.serverURL, code, e.configDir)
	if err != nil {
		return "", fmt.Errorf("enrollment failed: %w", err)
	}
	// Refresh the cached serverURL from the freshly-written config.
	if cfg, err := agent.LoadConfig(e.configDir); err == nil {
		e.serverURL = strings.TrimRight(cfg.ServerURL, "/")
	}
	return toJSON(enrollPayload{
		AgentID:      agentID,
		DeviceID:     deviceID,
		ServerURL:    e.serverURL,
		ZitiIdentity: zitiIdentity,
	})
}

type pushRegisterResult struct {
	Registered bool   `json:"registered"`
	Reason     string `json:"reason,omitempty"`
}

// RegisterPushDevice redeems the pending push-MFA enrollment ticket (stamped in
// config at Enroll) using this device's push token, making the enrolled phone a
// push approver in one step — the FastPass convergence. deviceToken is the FCM
// (Android) / APNs (iOS) token obtained by the mobile layer; platform is "ios",
// "android", or "web".
//
// Best-effort by design: a failure here never undoes the (already-successful)
// device enrollment. Returns {"registered":true} on success, or
// {"registered":false,"reason":...} when there is no pending ticket (e.g. the
// device was enrolled by a non-session path, or push was already registered).
func (e *Engine) RegisterPushDevice(deviceToken, platform string) (string, error) {
	deviceToken = strings.TrimSpace(deviceToken)
	if deviceToken == "" {
		return "", fmt.Errorf("device push token is required")
	}
	cfg, err := agent.LoadConfig(e.configDir)
	if err != nil {
		return "", fmt.Errorf("load config: %w", err)
	}
	if cfg.PushEnrollToken == "" || cfg.PushEnrollPath == "" {
		return toJSON(pushRegisterResult{Registered: false, Reason: "no pending push enrollment ticket"})
	}
	server := strings.TrimRight(cfg.ServerURL, "/")
	if server == "" {
		server = e.serverURL
	}
	deviceName := strings.TrimSpace(platform + " device")
	if err := e.be.CompletePushEnroll(server, cfg.PushEnrollPath, cfg.PushEnrollToken,
		deviceToken, platform, deviceName, cfg.InsecureSkipVerify); err != nil {
		return "", fmt.Errorf("push registration failed: %w", err)
	}
	// Single-use: clear the consumed ticket so a later call is a clean no-op.
	cfg.PushEnrollToken = ""
	cfg.PushEnrollPath = ""
	if serr := cfg.Save(e.configDir); serr != nil {
		e.logger.Warn("failed to clear push-enroll ticket from config", zap.Error(serr))
	}
	e.logger.Info("push device registered via enrollment ticket", zap.String("platform", platform))
	return toJSON(pushRegisterResult{Registered: true})
}

type postureCheck struct {
	Type     string  `json:"type"`
	Severity string  `json:"severity"`
	Status   string  `json:"status"`
	Score    float64 `json:"score"`
	Message  string  `json:"message,omitempty"`
	// Unsupported: this check has no implementation for the running OS, so its
	// status describes the build, not the device.
	Unsupported bool `json:"unsupported,omitempty"`
}

type posturePayload struct {
	Compliant bool `json:"compliant"`
	Passed    int  `json:"passed"`
	Failed    int  `json:"failed"`
	Warned    int  `json:"warned"`
	Errored   int  `json:"errored"`
	// Unsupported counts the checks that could not run on this operating
	// system. It is separate from Warned because it is not a fact about the
	// device at all.
	Unsupported int            `json:"unsupported"`
	RanAt       string         `json:"ran_at"`
	Checks      []postureCheck `json:"checks"`
}

// Posture runs the device's configured compliance checks locally and returns a
// summary JSON. It runs the built-in checks through a fresh engine so it does
// not depend on a reachable report endpoint (RunOnce reports to the server,
// which a GUI-only / offline device may not reach); the summary is what a GUI
// shows the user.
func (e *Engine) Posture() (string, error) {
	registry := checks.NewRegistry()
	registry.Register("os_version", &checks.OSVersionCheck{})
	registry.Register("disk_encryption", &checks.DiskEncryptionCheck{})
	registry.Register("process_running", &checks.ProcessCheck{})
	registry.Register("firewall", &checks.FirewallCheck{})
	registry.Register("screen_lock", &checks.ScreenLockCheck{})
	registry.Register("antivirus", &checks.AntivirusCheck{})
	registry.Register("domain_joined", &checks.DomainCheck{})
	registry.Register("patch_level", &checks.PatchLevelCheck{})
	registry.Register("integrity", &checks.IntegrityCheck{})
	registry.Register("agent_version", &checks.AgentVersionCheck{})

	eng := checks.NewEngine(registry)
	cfg := agent.DefaultServerConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	results := eng.RunChecks(ctx, cfg.Checks)

	return toJSON(summarisePosture(results, time.Now().UTC().Format(time.RFC3339)))
}

// summarisePosture turns check results into the payload a GUI reads. It is a
// pure function separated from Posture() so its arithmetic — which is where
// the compliance claim is actually made — can be driven by tests with the
// result shapes of platforms the test host is not. Posture() itself can only
// ever exercise the platform it runs on, which is precisely why the Android
// and iOS behaviour went unnoticed.
func summarisePosture(results []checks.EngineResult, ranAt string) posturePayload {
	out := posturePayload{RanAt: ranAt}
	for _, r := range results {
		pc := postureCheck{Type: r.CheckType, Severity: r.Severity}
		if r.Result != nil {
			pc.Status = string(r.Result.Status)
			pc.Score = r.Result.Score
			pc.Message = r.Result.Message
			pc.Unsupported = r.Result.Unsupported
			switch {
			case r.Result.Unsupported:
				out.Unsupported++
			case r.Result.Status == checks.StatusPass:
				out.Passed++
			case r.Result.Status == checks.StatusFail:
				out.Failed++
			case r.Result.Status == checks.StatusWarn:
				out.Warned++
			default:
				out.Errored++
			}
		}
		out.Checks = append(out.Checks, pc)
	}

	// Compliance is a claim about the device, so it may only be made when the
	// device was actually examined.
	//
	// This was `Failed == 0 && Errored == 0`. Every check that has no
	// implementation for the running OS answers StatusWarn, and warns did not
	// count -- so on Android and iOS, where seven of the ten checks have no
	// implementation, the engine reported COMPLIANT and the companion app drew
	// a green badge on a phone whose disk encryption (severity: critical) and
	// screen lock had never been looked at. A user reading that badge would
	// reasonably conclude their device had been checked and had passed.
	//
	// Two conditions now, both necessary: nothing failed or errored, AND
	// nothing was skipped for want of an implementation. A platform with no
	// checks at all therefore cannot be called compliant either, which is the
	// right answer to "is this device healthy?" from a build that cannot tell.
	out.Compliant = out.Failed == 0 && out.Errored == 0 && out.Unsupported == 0 &&
		(out.Passed+out.Warned) > 0
	return out
}

// PamList returns the caller's launchable PAM connections as a JSON array.
func (e *Engine) PamList() (string, error) {
	token, err := e.userToken()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	entries, err := e.be.PamList(ctx, e.serverURL, token)
	if err != nil {
		return "", fmt.Errorf("listing PAM entries: %w", err)
	}
	if entries == nil {
		entries = []desktoppam.Entry{}
	}
	return toJSON(entries)
}

// PamConnect launches a brokered session for entryID and returns the connect
// URL the GUI opens in the browser.
func (e *Engine) PamConnect(entryID string) (string, error) {
	entryID = strings.TrimSpace(entryID)
	if entryID == "" {
		return "", fmt.Errorf("entry_id is required")
	}
	token, err := e.userToken()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	url, err := e.be.PamConnect(ctx, e.serverURL, token, entryID)
	if err != nil {
		return "", fmt.Errorf("connecting PAM entry: %w", err)
	}
	return url, nil
}

// PamRequest files an access request for an approval-gated entry.
func (e *Engine) PamRequest(entryID, reason string) error {
	entryID = strings.TrimSpace(entryID)
	if entryID == "" {
		return fmt.Errorf("entry_id is required")
	}
	token, err := e.userToken()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return e.be.PamRequest(ctx, e.serverURL, token, entryID, reason)
}

// ZitiDial brings up (or reuses) a loopback bridge to the named Ziti service and
// returns the local 127.0.0.1:port address a plain-TCP client connects to. The
// bridge is kept alive until ZitiClose(service) is called.
func (e *Engine) ZitiDial(service string) (string, error) {
	service = strings.TrimSpace(service)
	if service == "" {
		return "", fmt.Errorf("service is required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	if b, ok := e.bridges[service]; ok {
		return b.localAddr, nil // idempotent: reuse the existing bridge
	}

	identityFile := e.zitiIdentityPath()
	if cfg, err := agent.LoadConfig(e.configDir); err == nil && cfg.ZitiIdentityFile != "" {
		identityFile = cfg.ZitiIdentityFile
	}
	if !fileExists(identityFile) {
		return "", fmt.Errorf("no Ziti identity at %s: enroll a Ziti identity first", identityFile)
	}

	d, err := e.newDialer(identityFile)
	if err != nil {
		return "", fmt.Errorf("load ziti identity: %w", err)
	}
	localAddr, stop, err := d.Bridge(service)
	if err != nil {
		d.Close()
		return "", fmt.Errorf("bridge %q: %w", service, err)
	}
	e.bridges[service] = &bridge{localAddr: localAddr, stop: stop, dialer: d}
	return localAddr, nil
}

// ZitiClose tears down the loopback bridge for the named service.
func (e *Engine) ZitiClose(service string) error {
	service = strings.TrimSpace(service)
	e.mu.Lock()
	b, ok := e.bridges[service]
	if ok {
		delete(e.bridges, service)
	}
	e.mu.Unlock()
	if !ok {
		return fmt.Errorf("no active bridge for service %q", service)
	}
	if b.stop != nil {
		b.stop()
	}
	if b.dialer != nil {
		b.dialer.Close()
	}
	return nil
}

// closeAll stops every active bridge (called on server shutdown).
func (e *Engine) closeAll() {
	e.mu.Lock()
	bridges := e.bridges
	e.bridges = map[string]*bridge{}
	e.mu.Unlock()
	for _, b := range bridges {
		if b.stop != nil {
			b.stop()
		}
		if b.dialer != nil {
			b.dialer.Close()
		}
	}
}

// AccessToken returns a currently-valid OAuth access token for the signed-in
// user, so the Dart ApiClient (which makes the backend REST calls for the
// journey screens) can authenticate against the SAME session the engine owns.
// Without this, the ApiClient's own (empty) token store would send no
// Authorization header and every governance/mfa/notifications call would 401.
//
// If a token is cached and unexpired it is returned as-is. If it is expired (or
// about to be) and a refresh token exists, AccessToken transparently refreshes
// via /oauth/token, persists the new tokens, and returns the fresh access
// token. If the refresh fails, the stale access token is returned with no error
// so the caller still sends a Bearer header — the server will 401 and the UI's
// auth-lost handling takes over. Errors only when not signed in at all.
func (e *Engine) AccessToken() (string, error) {
	if e.serverURL == "" {
		return "", fmt.Errorf("no server configured: enroll first")
	}
	tok, err := authstore.Load(e.configDir)
	if err != nil {
		return "", fmt.Errorf("loading session: %w", err)
	}
	if tok == nil || tok.AccessToken == "" {
		return "", errNotAuthenticated
	}

	// Consider the token expired if its stored expiry (or JWT exp) is within a
	// small skew of now; refresh proactively so requests don't race the clock.
	const skew = 30 * time.Second
	exp := tok.ExpiresAt
	if exp == 0 {
		if _, _, jwtExp, ok := decodeJWTClaims(tok.AccessToken); ok {
			exp = jwtExp
		}
	}
	expired := exp > 0 && time.Now().Add(skew).Unix() >= exp

	if expired && tok.RefreshToken != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// Mobile sessions were issued to the mobile PKCE client, so refresh must
		// present the same client_id.
		fresh, rerr := sso.RefreshWithClient(ctx, e.serverURL, tok.RefreshToken, sso.MobileClientID)
		if rerr == nil && fresh != nil && fresh.AccessToken != "" {
			if fresh.RefreshToken == "" {
				fresh.RefreshToken = tok.RefreshToken // server may omit an unchanged RT
			}
			if serr := authstore.Save(e.configDir, fresh); serr != nil {
				e.logger.Warn("failed to persist refreshed session", zap.Error(serr))
			}
			return fresh.AccessToken, nil
		}
		// Refresh failed — fall through and return the (stale) access token; let
		// the server 401 and the UI handle re-auth.
		e.logger.Warn("token refresh failed; returning stored token", zap.Error(rerr))
	}

	return tok.AccessToken, nil
}

// ---- internal helpers (never cross the gomobile boundary) --------------

// userToken loads the cached OAuth access token, erroring if not signed in.
func (e *Engine) userToken() (string, error) {
	if e.serverURL == "" {
		return "", fmt.Errorf("no server configured: enroll first")
	}
	tok, err := authstore.Load(e.configDir)
	if err != nil {
		return "", fmt.Errorf("loading session: %w", err)
	}
	if tok == nil || tok.AccessToken == "" {
		return "", errNotAuthenticated
	}
	return tok.AccessToken, nil
}

func (e *Engine) zitiIdentityPath() string {
	return filepath.Join(e.configDir, "ziti-identity.json")
}

// errNotAuthenticated is returned when a token-requiring method is called
// before Login. The server maps it to HTTP 401.
var errNotAuthenticated = fmt.Errorf("not authenticated: sign in first")

func toJSON(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// decodeJWTClaims best-effort-decodes the sub/email/exp claims from a JWT
// access token without verifying the signature (display-only; the server
// authorizes for real). Returns ok=false if the token is not a decodable JWT.
func decodeJWTClaims(token string) (sub, email string, exp int64, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", 0, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", 0, false
	}
	var claims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Exp               int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", 0, false
	}
	email = claims.Email
	if email == "" {
		email = claims.PreferredUsername
	}
	return claims.Sub, email, claims.Exp, true
}
