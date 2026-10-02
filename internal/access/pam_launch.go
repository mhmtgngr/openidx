// Package access — PAM entry launch: passwordless brokered sessions.
//
// The "connect without a password" path of the RDM-parity PAM module
// (pam_entries.go). A launchable entry (rdp/ssh/vnc/telnet) resolves its
// credential server-side — its own vault secret or the linked credential
// entry's — and the plaintext is injected straight into the per-entry
// Guacamole connection. The browser only ever receives a connect URL: the
// user lands inside the remote session without seeing, typing, or being able
// to copy the target credential. Every launch is ACL-checked, optionally
// approval-gated, ledgered in pam_entry_sessions, optionally recorded, and
// audited.
package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/externalid"

	"github.com/openidx/openidx/internal/common/logsafe"
)

// remoteAppSecretArgRE matches credential-looking tokens in a RemoteApp
// command line. RDP passes remote-app-args verbatim and they are visible in the
// target's process list (Task Manager, `Get-CimInstance Win32_Process`), so a
// password placed there leaks to anyone who can see processes on the host. We
// reject the common forms and steer admins to integrated auth (e.g. SSMS `-E`,
// which authenticates as the vault-injected Windows identity — no secret in the
// args at all). Case-insensitive; matches `-P xxx`, `/password:xxx`,
// `--pass=xxx`, `pwd=xxx`, `pass=xxx`.
var remoteAppSecretArgRE = regexp.MustCompile(`(?i)(^|\s)(-{1,2}p(ass(word)?)?|/pass(word)?)([\s:=]|$)|(?i)(^|\s|;|&)(password|passwd|pwd)\s*=`)

// errRemoteAppSecretArg is returned when RemoteApp args appear to carry a
// secret. Callers surface it to the admin (on save) or the user (on launch).
var errRemoteAppSecretArg = errors.New(
	"remote-app-args must not contain a password — RDP command lines are visible in the target's process list. " +
		"Use integrated authentication instead (e.g. SSMS \"-E\"), which signs in as the injected Windows identity")

// validateRemoteAppArgs rejects credential-looking RemoteApp command-line
// arguments. Empty args are always fine.
func validateRemoteAppArgs(args string) error {
	if strings.TrimSpace(args) == "" {
		return nil
	}
	if remoteAppSecretArgRE.MatchString(args) {
		return errRemoteAppSecretArg
	}
	return nil
}

// pamReservedGuacParams are connection parameters an entry's settings JSON may
// NOT override: injected credentials, identity fields, endpoint address,
// recording configuration, and the GFX toggle all come from the entry columns
// / server config. `disable-gfx` is reserved because RemoteApp launches must
// force it on (see forcePamRemoteAppParams) — a stored setting must never be
// able to re-enable GFX and reintroduce the GUACAMOLE-2123 blank-window bug.
var pamReservedGuacParams = map[string]bool{
	"password": true, "private-key": true, "passphrase": true,
	"username": true, "domain": true,
	"hostname": true, "port": true,
	"recording-path": true, "recording-name": true, "recording-include-keys": true,
	"disable-gfx": true,
}

// forcePamRemoteAppParams applies the server-mandated overrides for RemoteApp
// (single published Windows application) launches. Guacamole 1.6.0 enables the
// RDP Graphics Pipeline (GFX) by default, but RemoteApp windows fail to repaint
// with GFX on (GUACAMOLE-2123). Whenever a launch is a RemoteApp — signalled by
// a non-empty `remote-app` parameter — we force `disable-gfx=true` server-side.
// `disable-gfx` is in pamReservedGuacParams so stored settings can never turn
// it back on. No-op for full-desktop RDP, which keeps GFX for responsiveness.
func forcePamRemoteAppParams(params map[string]string) {
	if params["remote-app"] != "" {
		params["disable-gfx"] = "true"
	}
}

// buildPamGuacParams assembles the Guacamole parameters for a PAM entry
// launch. Layering (later wins): protocol extras from entry settings →
// identity (username/domain) → injected credential (password, or private-key
// for ssh_key secrets) → guacd recording parameters. Reserved keys in
// settings are dropped so stored settings can never leak, replace, or
// redirect the injected credential or the recording.
func buildPamGuacParams(secretType, username, domain string, cred []byte, settings map[string]interface{}, record bool, recordingPath, recordingName string) map[string]string {
	params := map[string]string{}
	for k, v := range settings {
		if pamReservedGuacParams[k] {
			continue
		}
		if sv, ok := v.(string); ok && sv != "" {
			params[k] = sv
		}
	}
	if username != "" {
		params["username"] = username
	}
	if domain != "" {
		params["domain"] = domain
	}
	if len(cred) > 0 {
		if secretType == "ssh_key" {
			params["private-key"] = string(cred)
		} else {
			params["password"] = string(cred)
		}
	}
	if record {
		params["recording-path"] = recordingPath
		params["recording-name"] = recordingName
		params["recording-include-keys"] = "true"
	}
	// RemoteApp launches must run with GFX disabled (GUACAMOLE-2123); applied
	// after the settings/credential layering so nothing can override it.
	forcePamRemoteAppParams(params)
	return params
}

// pamLaunchTarget is the credential resolution result for a launch: which
// vault secret to inject and under which account identity.
type pamLaunchTarget struct {
	SecretID string
	Username string
	Domain   string
}

// resolvePamLaunchTarget picks the credential source for an entry: the linked
// credential entry when set (its username/domain override empty entry
// fields), otherwise the entry's own secret and identity columns.
func (s *Service) resolvePamLaunchTarget(ctx context.Context, orgID string, entry *pamLaunchEntry) (pamLaunchTarget, error) {
	target := pamLaunchTarget{
		SecretID: entry.VaultSecretID,
		Username: entry.Username,
		Domain:   entry.Domain,
	}
	if entry.CredentialEntryID == "" {
		return target, nil
	}
	var credSecretID, credUsername, credDomain string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(vault_secret_id::text,''), COALESCE(username,''), COALESCE(domain,'')
		  FROM pam_entries WHERE id = $1 AND org_id = $2`,
		entry.CredentialEntryID, orgID).Scan(&credSecretID, &credUsername, &credDomain)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return target, errors.New("linked credential entry not found")
		}
		return target, err
	}
	target.SecretID = credSecretID
	if credUsername != "" {
		target.Username = credUsername
	}
	if credDomain != "" {
		target.Domain = credDomain
	}
	return target, nil
}

// pamLaunchEntry carries the pam_entries columns the launch path needs.
type pamLaunchEntry struct {
	ID                string
	Name              string
	EntryType         string
	Hostname          string
	Port              int
	Username          string
	Domain            string
	URL               string
	Settings          map[string]interface{}
	VaultSecretID     string
	CredentialEntryID string
	GuacConnectionID  string
	RequireApproval   bool
	RecordSession     bool
	// RequireModerator: a session on the entry waits until a moderator has
	// joined to watch it (entry_moderation.go).
	RequireModerator  bool
	ReachMode         string
	ZitiInterceptPort int
	// AdminBypass names the gates this launch passed only because the caller
	// is an administrator ("grant", "approval"); empty otherwise. Set by the
	// launch handler, never loaded, and carried to pam.entry_connected.
	AdminBypass []string
	// External is set by the launch handler when the caller is an external
	// user (pinExternalPamPolicy), never loaded: the session gets its own
	// broker connection and identity, is recorded, and runs hardened (I5, I7).
	External bool
	// ModerationID is the moderation this launch claimed, set by
	// claimPamModeration and never loaded. The session row records it, so
	// its moderator watches and ends that session and no other.
	ModerationID string
}

// pamAdminBypass names the gates an administrator's launch of entry passes
// only because the caller is an administrator: "grant" when no connect grant
// (user, role or group) would have admitted them, "approval" when the entry
// requires an approval, which administrators never spend.
//
// Administrators pass both gates on every launch path, and the audit event
// said nothing about it: an administrator connecting to an entry nobody
// granted them read the same as an operator using their grant. Called only
// for administrators. A failed grant lookup counts as a bypass, so an error
// records the bypass rather than hiding it.
func (s *Service) pamAdminBypass(ctx context.Context, orgID string, entry *pamLaunchEntry, userID string, roles []string) []string {
	gates := []string{}
	allowed, err := s.pamEntryAllowed(ctx, orgID, entry.ID, userID, roles, "connect")
	if err != nil {
		s.logger.Warn("pamAdminBypass: grant lookup failed; recording the launch as a grant bypass",
			zap.String("entry_id", entry.ID), zap.Error(err))
		allowed = false
	}
	if !allowed {
		gates = append(gates, "grant")
	}
	if entry.RequireApproval {
		gates = append(gates, "approval")
	}
	return gates
}

// dialTarget returns the host:port guacd should open the protocol connection
// to. In ziti reach mode this is the broker's Ziti intercept address (the
// ziti-tunnel carries it over the overlay to the edge-router-hosted target); in
// direct mode it is the entry's real target. Falls back to the real target if a
// ziti entry somehow has no intercept port assigned.
//
// The intercept host is a NON-loopback Ziti IP (pamZitiInterceptHost) rather
// than 127.0.0.1: ziti-edge-tunnel runs in TUN mode and cannot intercept
// loopback traffic (the kernel short-circuits 127.0.0.0/8 before it reaches the
// tun device), so guacd dialing 127.0.0.1 got connection-refused. Dialing a
// tun-routed address lets the tunnel capture it and dial the service. The
// per-entry intercept config must advertise this same address.
func (e *pamLaunchEntry) dialTarget() (host string, port int) {
	if e.ReachMode == "ziti" && e.ZitiInterceptPort > 0 {
		return pamZitiInterceptHost, e.ZitiInterceptPort
	}
	return e.Hostname, e.Port
}

// handlePamConnect — POST /pam/entries/:id/connect (connect grant or admin).
//
// Passwordless launch: resolves the entry's credential inside the service,
// pushes it into the per-entry Guacamole connection, and returns only the
// connect URL. Website entries return their URL (no brokering). 403s when a
// required approval is missing — the UI then offers "request access".
func (s *Service) handlePamConnect(c *gin.Context) {
	s.connectPamEntry(c, c.Param("id"), pamConnectHooks{})
}

// pamConnectHooks let a caller that reaches the entry path from elsewhere (the
// route-based Guacamole connect) add its own gate and ledger around the launch
// without a second copy of the decision.
type pamConnectHooks struct {
	// BeforeLaunch runs after every gate of the entry path has passed and
	// before a credential is resolved. Returning false means the hook has
	// written the response and the launch does not happen.
	BeforeLaunch func(c *gin.Context, entry *pamLaunchEntry) bool
	// AfterLaunch runs once the session is brokered and ledgered.
	AfterLaunch func(c *gin.Context, entry *pamLaunchEntry, res *pamSessionResult)
	// Response is merged into the success body.
	Response gin.H
}

// connectPamEntry is the entry launch: ACL, approval, overlay check, then the
// shared launch core. handlePamConnect is this with no hooks; the route-based
// connect adds its moderation gate and its own session ledger through them.
func (s *Service) connectPamEntry(c *gin.Context, entryID string, hooks pamConnectHooks) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	caller, ok := s.resolvePamCaller(c, org.ID)
	if !ok {
		return // resolvePamCaller already wrote the error
	}
	userID, isAdmin := caller.UserID, caller.Admin

	entry, typeInfo, ok := s.loadPamLaunchEntry(c, org.ID, entryID)
	if !ok {
		return // loadPamLaunchEntry already wrote the error
	}
	pinExternalPamPolicy(&entry, caller)

	if isAdmin {
		entry.AdminBypass = s.pamAdminBypass(ctx, org.ID, &entry, userID, pamCallerRoles(c))
	} else {
		allowed, aclErr := s.pamEntryAllowed(ctx, org.ID, entryID, userID, pamCallerRoles(c), "connect")
		if aclErr != nil {
			s.logger.Error("connectPamEntry: ACL check failed", zap.Error(aclErr))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check permissions"})
			return
		}
		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "not permitted"})
			return
		}
	}
	if s.refuseIneffectiveExternal(c, org.ID, userID) {
		return
	}
	if s.refuseClosedTarget(c, org.ID, caller, entryID) {
		return
	}

	// Does this launch stay on the overlay? Asked before the approval gate, so
	// a refusal does not spend an approval, before the website short-circuit,
	// and before launchPamSession resolves a credential, because a refusal
	// must not have decrypted a vault secret on its way to being refused — and
	// because the website path never reaches launchPamSession at all, so a
	// check placed there would miss the one entry type that brokers nothing.
	// An external user's launch is held to it whatever PAM_REQUIRE_ZTNA says.
	if v := s.checkPamZTNA(c, org.ID, userID, entryID, entry.ReachMode, typeInfo.Protocol, caller.External); v.Refuse {
		c.JSON(http.StatusForbidden, gin.H{"error": v.Reason, "code": v.Code})
		return
	}
	if s.refuseExternalLaunch(c, &entry) {
		return
	}
	// The moderation gate, asked before the approval gate so a launch that
	// has to wait for its moderator does not spend an approval.
	if s.refuseUnmoderatedLaunch(c, org.ID, &entry, userID) {
		return
	}

	// Approval gate — single-use, atomically consumed. Admins (the approvers)
	// bypass their own gate; an external user always needs one (I5).
	if entry.RequireApproval && !isAdmin {
		consumed, gateErr := s.checkAndConsumePamApproval(ctx, entryID, userID)
		if gateErr != nil {
			s.logger.Error("connectPamEntry: approval check failed", zap.Error(gateErr))
			c.JSON(http.StatusForbidden, gin.H{"error": "session requires approval"})
			return
		}
		if !consumed {
			c.JSON(http.StatusForbidden, gin.H{"error": "session requires approval", "approval_required": true})
			return
		}
	}

	if hooks.BeforeLaunch != nil && !hooks.BeforeLaunch(c, &entry) {
		return
	}

	// Website entries: no brokering — hand back the URL. The password (if
	// any) stays in the vault, retrievable only via the audited reveal path.
	if typeInfo.Protocol == "" {
		s.recordPamLaunch(c, org.ID, &entry, "", "", false, "", "")
		c.JSON(http.StatusOK, gin.H{"launch_type": "url", "url": entry.URL, "entry_id": entryID})
		return
	}

	// The launch spends the moderation it waited for; one moderation admits
	// one session.
	if !s.claimPamModeration(c, org.ID, &entry, userID) {
		return
	}

	// Everything from broker selection onward is the shared launch core, reused
	// by the Windows-app launch path.
	res, fail := s.launchPamSession(c, org.ID, &entry, typeInfo.Protocol, nil, "pam-"+entry.ID, entry.GuacConnectionID,
		func(ctx context.Context, connID string) {
			if _, err := s.db.Pool.Exec(ctx,
				`UPDATE pam_entries SET guacamole_connection_id = $1, updated_at = NOW() WHERE id = $2 AND org_id = $3`,
				connID, entry.ID, org.ID); err != nil {
				s.logger.Warn("connectPamEntry: persist connection id failed", zap.Error(err))
			}
		})
	if fail != nil {
		s.releasePamModeration(org.ID, &entry)
		fail.writeJSON(c)
		return
	}
	if hooks.AfterLaunch != nil {
		hooks.AfterLaunch(c, &entry, res)
	}

	body := gin.H{
		"launch_type":         "guacamole",
		"connect_url":         res.ConnectURL,
		"connection_id":       res.ConnID,
		"entry_id":            entryID,
		"session_id":          res.SessionID,
		"credential_injected": res.Injected,
		"recorded":            entry.RecordSession,
		"reach_mode":          entry.ReachMode,
	}
	if entry.External {
		body["session_policy"] = externalSessionPolicy()
	}
	for k, v := range hooks.Response {
		body[k] = v
	}
	c.JSON(http.StatusOK, body)
}

// pamSessionResult is the outcome of a successful brokered launch.
type pamSessionResult struct {
	ConnectURL string
	ConnID     string
	SessionID  string
	Injected   bool
	GuacUser   string
	// RecordingPath is the file guacd writes when the entry records, else "".
	RecordingPath string
}

// pamLaunchFailure is why a brokered launch did not happen.
//
// The launch core used to answer its own failures with c.JSON. Two of its three
// callers are JSON APIs, so that was right for them and wrong for the third:
// `GET /temp-access/:token` is an HTML route an outside party opens in a
// browser, and a vendor whose broker was misconfigured got a raw object
// reading {"error":"the OpenZiti PAM broker is not configured"} — a page that
// is both unusable and a description of this deployment's internals to somebody
// with no account here.
//
// So the core decides WHAT failed and each caller decides how to say it: the
// authenticated APIs render Message and Code, the anonymous page renders
// neither. Returning the failure rather than writing it is also what makes the
// distinction impossible to forget — a caller cannot ignore a value the
// compiler makes it name.
type pamLaunchFailure struct {
	Status int
	// Code is stable and machine-readable. It reaches an authenticated caller
	// and the server log; never the anonymous redemption page.
	Code string
	// Message is operator-facing detail, on the same terms as Code.
	Message string
}

// writeJSON answers an authenticated caller, which is entitled to the detail.
func (f *pamLaunchFailure) writeJSON(c *gin.Context) {
	body := gin.H{"error": f.Message}
	if f.Code != "" {
		body["code"] = f.Code
	}
	c.JSON(f.Status, body)
}

// launchPamSession runs the post-gate brokered-launch core shared by
// entry-connect (handlePamConnect) and Windows-app launch (handleWindowsAppLaunch):
// broker selection → credential resolution → vault decrypt → params (entry
// settings + extraSettings, with RemoteApp GFX forcing) → Guacamole connection
// (named connName, id persisted via persistConnID) → connect URL → session
// ledger. The caller has already loaded the host `entry` and passed ACL +
// approval (+ placement for apps).
//
// extraSettings are server-controlled parameters merged over the entry's stored
// settings (the RemoteApp keys for an app launch); connName is the deterministic
// Guacamole connection name; existingConnID is the id a prior launch persisted.
//
// Returns (result, true) on success. On any failure it has already written the
// error response to c and returns (nil, false) — the caller just returns.
func (s *Service) launchPamSession(
	c *gin.Context, orgID string, entry *pamLaunchEntry, protocol string,
	extraSettings map[string]string, connName, existingConnID string,
	persistConnID func(ctx context.Context, connID string),
) (*pamSessionResult, *pamLaunchFailure) {
	ctx := c.Request.Context()
	userID := c.GetString("user_id")

	// Route to the broker matching the connection's per-entry choice: the
	// dedicated OpenZiti broker for reach_mode='ziti' (its guacd rides the
	// overlay), the direct broker otherwise. Fail closed when that broker isn't
	// configured — never launch a ziti connection through the direct broker
	// (it can't see the overlay loopback ports) or vice-versa.
	broker := s.brokerFor(entry.ReachMode)
	if broker == nil {
		if entry.ReachMode == "ziti" {
			return nil, &pamLaunchFailure{http.StatusServiceUnavailable,
				"ziti_broker_unconfigured", "the OpenZiti PAM broker is not configured"}
		}
		return nil, &pamLaunchFailure{http.StatusServiceUnavailable,
			"broker_unconfigured", "no session broker is configured"}
	}
	// A ziti-reach entry also needs a live overlay to carry the target hop;
	// without it the loopback intercept dials nothing. Fail closed with a code.
	if entry.ReachMode == "ziti" && s.ziti() == nil {
		return nil, &pamLaunchFailure{http.StatusServiceUnavailable, "ziti_unavailable",
			"OpenZiti overlay is unavailable for this Ziti-reach connection"}
	}
	// An external user's session (I5, I7). The launch paths asked this before
	// spending an approval; asked again here because this core is what every
	// path shares. The session gets a broker connection of its own, never the
	// entry's shared one: its parameters are what make it the session I7
	// describes, and the shared connection's are rewritten by whoever launches
	// next, before this user's browser has opened it.
	if _, refusal := s.externalLaunchRefusal(entry); refusal != nil {
		if errors.Is(refusal, externalid.ErrBrokerIdentityRequired) {
			return nil, &pamLaunchFailure{http.StatusServiceUnavailable, "external_broker_identity_required", refusal.Error()}
		}
		return nil, &pamLaunchFailure{http.StatusServiceUnavailable, "external_recording_unavailable", refusal.Error()}
	}
	if entry.External {
		connName, existingConnID, persistConnID = connName+"-x-"+userID, "", nil
	}

	// Resolve the credential source (own secret or linked credential entry).
	target, err := s.resolvePamLaunchTarget(ctx, orgID, entry)
	if err != nil {
		s.logger.Warn("launchPamSession: credential resolution failed",
			zap.String("entry_id", logsafe.Clean(entry.ID)), zap.Error(err))
		return nil, &pamLaunchFailure{http.StatusConflict, "credential_unresolved", err.Error()}
	}

	// Decrypt server-side. The plaintext never enters any response or log.
	var cred []byte
	var secretType string
	if target.SecretID != "" && s.vaultSvc != nil {
		bctx := orgctx.WithBypassRLS(ctx)
		cred, err = s.vaultSvc.Use(bctx, orgID, target.SecretID)
		if err != nil {
			s.logger.Warn("launchPamSession: vault credential unavailable",
				zap.String("secret_id", target.SecretID), zap.Error(err))
			return nil, &pamLaunchFailure{http.StatusForbidden, "credential_unavailable",
				"credential unavailable"}
		}
		// bctx carries an explicit bypass, so the tenant term is the only scoping
		// on this read; the directive it replaces named the bypass as the reason.
		_ = s.db.Pool.QueryRow(bctx,
			`SELECT type FROM vault_secrets WHERE id=$1 AND org_id=$2`, target.SecretID, orgID).Scan(&secretType)
	}

	recName := fmt.Sprintf("pam-%s-%d", entry.ID, time.Now().UnixMilli())
	recPath := ""
	recFile := ""
	if entry.RecordSession {
		recPath = s.config.GuacamoleRecordingPath
		recFile = filepath.Join(recPath, recName)
	}

	// Merge server-controlled extraSettings over the entry's stored settings so
	// reserved-key filtering AND RemoteApp GFX forcing (buildPamGuacParams)
	// apply uniformly to app-derived params.
	settings := entry.Settings
	if len(extraSettings) > 0 {
		settings = make(map[string]interface{}, len(entry.Settings)+len(extraSettings))
		for k, v := range entry.Settings {
			settings[k] = v
		}
		for k, v := range extraSettings {
			settings[k] = v
		}
	}

	params := buildPamGuacParams(secretType, target.Username, target.Domain, cred,
		settings, entry.RecordSession, recPath, recName)
	if entry.External {
		hardenExternalGuacParams(params)
	}
	injected := len(cred) > 0
	// Zero the plaintext immediately after buildPamGuacParams copies it into
	// the params map (string copies are GC-managed; same caveat as M3).
	for i := range cred {
		cred[i] = 0
	}

	dialHost, dialPort := entry.dialTarget()
	var connID string
	if entry.External {
		connID, err = s.ensureExternalGuacConnection(ctx, connName, protocol, dialHost, dialPort, params, broker)
	} else {
		connID, err = s.ensureGuacConnection(ctx, connName, existingConnID, protocol, dialHost, dialPort, params, broker, persistConnID)
	}
	if err != nil {
		s.logger.Error("launchPamSession: guacamole connection failed",
			zap.String("entry_id", logsafe.Clean(entry.ID)), zap.Error(err))
		return nil, &pamLaunchFailure{http.StatusInternalServerError, "session_prepare_failed",
			"failed to prepare session"}
	}

	if injected {
		s.logAuditEvent(c, "pam.credential_injected", entry.ID, "pam_entry",
			map[string]interface{}{
				"entry_id":  entry.ID,
				"secret_id": target.SecretID,
				"user_id":   userID,
				// Credential value intentionally omitted.
			})
	}

	// Build the browser URL before recording the launch so the per-user Guacamole
	// identity (if enabled) can be persisted on the session row for later revoke.
	connectURL, guacUser := s.connectURLForBroker(ctx, broker, orgID, userID, connID, realClientIP(c))
	if entry.External && guacUser == "" {
		// The per-user identity could not be set up and the URL carries the
		// shared token, which opens every connection on the broker. It is
		// dropped, not handed to an external user.
		refusal := externalid.ErrBrokerIdentityRequired
		s.logAuditEvent(c, "pam.launch_denied", entry.ID, "pam_entry", map[string]interface{}{
			"entry_id": entry.ID, "user_id": userID, "code": externalid.Code(refusal), "external": true,
		})
		return nil, &pamLaunchFailure{http.StatusServiceUnavailable, "external_broker_identity_required", refusal.Error()}
	}

	sessionID := s.recordPamLaunch(c, orgID, entry, protocol, connID, injected, guacUser, recFile)

	return &pamSessionResult{
		ConnectURL: connectURL, ConnID: connID, SessionID: sessionID,
		Injected: injected, GuacUser: guacUser, RecordingPath: recFile,
	}, nil
}

// decodePamSettings unmarshals a settings JSONB blob, tolerating NULL/garbage.
func decodePamSettings(raw []byte) map[string]interface{} {
	settings := map[string]interface{}{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &settings)
	}
	return settings
}

// ensureGuacConnection creates or refreshes a Guacamole connection by
// deterministic name with the given (credential-bearing) params, decoupled
// from any particular catalog table. The name is stable per logical target
// (pam-<entryID> for a session entry, pam-<hostID>-app-<appID> for a published
// app) so two apps on one host each get their own connection instead of
// fighting over one. existingConnID is the id persisted by a prior launch (may
// be stale); persist stores the resulting id. A vanished/duplicate connection
// is transparently recovered by name.
func (s *Service) ensureGuacConnection(
	ctx context.Context, name, existingConnID, protocol, dialHost string, dialPort int,
	params map[string]string, broker *GuacamoleClient, persist func(ctx context.Context, connID string),
) (string, error) {
	if existingConnID != "" {
		if err := broker.UpdateConnection(existingConnID, name, protocol, dialHost, dialPort, params); err == nil {
			return existingConnID, nil
		}
		s.logger.Warn("ensureGuacConnection: update failed; recreating",
			zap.String("name", name), zap.String("guac_conn_id", existingConnID))
	}
	newID, err := broker.CreateConnection(name, protocol, dialHost, dialPort, params)
	if err != nil {
		// The connection name is deterministic. If a prior launch created it but
		// we never persisted the id (failed/cross-context persist, or a stale id
		// that no longer resolves), Guacamole rejects the duplicate name. Recover
		// by finding the existing connection by name and updating it in place —
		// makes ensure idempotent regardless of persisted state.
		existingID := s.findGuacConnectionIDByName(ctx, broker, name)
		if existingID == "" {
			return "", err
		}
		if uerr := broker.UpdateConnection(existingID, name, protocol, dialHost, dialPort, params); uerr != nil {
			s.logger.Warn("ensureGuacConnection: update of existing connection failed",
				zap.String("name", name), zap.Error(uerr))
		}
		newID = existingID
	}
	if persist != nil {
		persist(ctx, newID)
	}
	return newID, nil
}

// ensureExternalGuacConnection gives an external user's session its own
// broker connection, created or updated with this launch's parameters, or
// fails. Unlike ensureGuacConnection it never falls back to a connection whose
// update failed: the parameters are the session's controls (I7), and a stale
// set is not this launch's.
func (s *Service) ensureExternalGuacConnection(
	ctx context.Context, name, protocol, dialHost string, dialPort int,
	params map[string]string, broker *GuacamoleClient,
) (string, error) {
	if id := s.findGuacConnectionIDByName(ctx, broker, name); id != "" {
		if err := broker.UpdateConnection(id, name, protocol, dialHost, dialPort, params); err != nil {
			return "", err
		}
		return id, nil
	}
	return broker.CreateConnection(name, protocol, dialHost, dialPort, params)
}

// findGuacConnectionIDByName returns the Guacamole identifier of the connection
// with the given name, or "" if not found or on error. Used to recover the
// deterministic pam-<entryID> connection when its id wasn't persisted.
func (s *Service) findGuacConnectionIDByName(ctx context.Context, broker *GuacamoleClient, name string) string {
	conns, err := broker.ListConnections(ctx)
	if err != nil {
		s.logger.Warn("findGuacConnectionIDByName: list connections failed", zap.Error(err))
		return ""
	}
	for _, c := range conns {
		if c.Name == name {
			return c.ID
		}
	}
	return ""
}

// recordPamLaunch writes the pam_entry_sessions ledger row, bumps the entry's
// launch counters, and emits the pam.entry_connected audit event. Best-effort:
// a ledger failure must not block the session. Returns the session row id.
//
// The row records the gates an administrator passed only by being one
// (admin_bypass, migration v217), so the lifecycle sweep can tell a session a
// grant opened, which ends with the grant, from one an administrator opened
// without any.
//
// recordingPath is where the broker records the session, empty when nothing
// records it. It is written with the row, so everything the launch tells --
// the sponsor's notification, the pam.session.started event -- reads a
// session that already says whether it is recorded.
func (s *Service) recordPamLaunch(c *gin.Context, orgID string, entry *pamLaunchEntry, protocol, guacConnID string, injected bool, guacUsername, recordingPath string) string {
	ctx := c.Request.Context()
	userID := c.GetString("user_id")

	var sessionID string
	if err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol, guac_connection_id, credential_injected, guac_username, admin_bypass, recording_path, moderation_id)
		VALUES ($1, $2, NULLIF($3,'')::uuid, NULLIF($4,''), NULLIF($5,''), $6, NULLIF($7,''), $8, NULLIF($9,''), NULLIF($10,'')::uuid)
		RETURNING id`,
		orgID, entry.ID, userID, protocol, guacConnID, injected, guacUsername, adminBypassed(entry.AdminBypass), recordingPath,
		entry.ModerationID).Scan(&sessionID); err != nil {
		s.logger.Warn("recordPamLaunch: session ledger insert failed",
			zap.String("entry_id", entry.ID), zap.Error(err))
	}

	if _, err := s.db.Pool.Exec(ctx, `
		UPDATE pam_entries SET last_connected_at = NOW(), connect_count = connect_count + 1
		 WHERE id = $1 AND org_id = $2`, entry.ID, orgID); err != nil {
		s.logger.Warn("recordPamLaunch: counter update failed", zap.Error(err))
	}

	s.logAuditEvent(c, "pam.entry_connected", entry.ID, "pam_entry", map[string]interface{}{
		"entry_id":            entry.ID,
		"entry_name":          entry.Name,
		"entry_type":          entry.EntryType,
		"protocol":            protocol,
		"user_id":             userID,
		"credential_injected": injected,
		"recorded":            entry.RecordSession,
		"admin_bypass":        len(entry.AdminBypass) > 0,
		"admin_bypassed":      adminBypassed(entry.AdminBypass),
	})
	// An external user's sponsor is told the session started (I6).
	if entry.External && sessionID != "" {
		s.notifySponsorOfSession(ctx, orgID, userID, entry, sessionID)
	}
	if sessionID != "" {
		s.pamSessionStarted(orgID, sessionID, userID, entry, protocol, recordingPath != "")
	}
	return sessionID
}

// adminBypassed renders the bypassed gates for the audit event: always a
// list, so a filter on the field never has to tell null from empty.
func adminBypassed(gates []string) []string {
	if gates == nil {
		return []string{}
	}
	return gates
}

// ---- Approval lifecycle (pre-connect gate) ----

// checkAndConsumePamApproval atomically consumes the most recent approved,
// unexpired pam_entry_access_requests row for (entry, user). Same single-use
// pattern as the M3 guacamole gate. RLS scopes the statement via the request
// context's app.org_id.
func (s *Service) checkAndConsumePamApproval(ctx context.Context, entryID, userID string) (bool, error) {
	var id string
	err := s.db.Pool.QueryRow(ctx,
		//orgscope:ignore RLS on pam_entry_access_requests is enforced via the request context's app.org_id setting
		`UPDATE pam_entry_access_requests SET status = 'consumed'
		  WHERE id = (
		        SELECT id FROM pam_entry_access_requests
		         WHERE entry_id      = $1
		           AND requester_id  = $2
		           AND status        = 'approved'
		           AND (expires_at IS NULL OR expires_at > NOW())
		         ORDER BY created_at DESC
		         LIMIT 1
		  )
		  RETURNING id`,
		entryID, userID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// handlePamRequestAccess — POST /pam/entries/:id/request {reason}.
// The requester must hold the connect grant (or be admin — pointless but
// harmless); the approval is an additional, single-use gate on top.
func (s *Service) handlePamRequestAccess(c *gin.Context) {
	s.createPamAccessRequest(c, c.Param("id"))
}

// createPamAccessRequest files a pending pam_entry_access_requests row for the
// caller on entryID and answers 201 {request_id}. Shared by the entry route
// and the route-based Guacamole request, which resolves its entry first.
func (s *Service) createPamAccessRequest(c *gin.Context, entryID string) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body) // reason is optional

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	if !s.pamCallerIsAdmin(c) {
		allowed, aclErr := s.pamEntryAllowed(ctx, org.ID, entryID, userID, pamCallerRoles(c), "connect")
		if aclErr != nil || !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "not permitted"})
			return
		}
	}

	expiresAt := time.Now().Add(time.Hour)
	var requestID string
	err = s.db.Pool.QueryRow(ctx, `
		INSERT INTO pam_entry_access_requests (org_id, entry_id, requester_id, reason, status, expires_at)
		SELECT $1, id, $3::uuid, NULLIF($4,''), 'pending', $5 FROM pam_entries WHERE id = $2 AND org_id = $1
		RETURNING id`,
		org.ID, entryID, userID, body.Reason, expiresAt).Scan(&requestID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
			return
		}
		s.logger.Error("createPamAccessRequest: insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create access request"})
		return
	}

	s.logAuditEvent(c, "pam.access_requested", requestID, "pam_entry_access_request",
		map[string]interface{}{
			"entry_id": entryID, "requester_id": userID,
			"expires_at": expiresAt.Format(time.RFC3339),
		})
	s.notifySponsorOfLaunchRequest(ctx, org.ID, userID, entryID, requestID, body.Reason)
	c.JSON(http.StatusCreated, gin.H{"request_id": requestID})
}

// handlePamApproveRequest — POST /pam/entry-requests/:id/approve (admin).
func (s *Service) handlePamApproveRequest(c *gin.Context) {
	s.decidePamRequest(c, "approved", "pam.access_approved")
}

// handlePamDenyRequest — POST /pam/entry-requests/:id/deny (admin).
func (s *Service) handlePamDenyRequest(c *gin.Context) {
	s.decidePamRequest(c, "denied", "pam.access_denied")
}

func (s *Service) decidePamRequest(c *gin.Context, newStatus, auditAction string) {
	s.decidePamRequestAs(c, newStatus, auditAction, false)
}

// decidePamRequestAs decides a pending launch request. asSponsor is the
// sponsor's route: the request must be one of the caller's own external
// users', whichever the decision.
//
// An external (vendor) user's launch is approved by their sponsor (section
// 5.6 of the third-party access framework), on either route: an
// administrator who is not the sponsor can deny it but not approve it. The
// rule is in the statement, so it is atomic with the status check.
func (s *Service) decidePamRequestAs(c *gin.Context, newStatus, auditAction string, asSponsor bool) {
	requestID := c.Param("id")
	approverID := c.GetString("user_id")

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Four-eyes: an admin who filed a PAM access request must not approve their
	// OWN request. Deny is allowed (a requester can effectively withdraw), but
	// approval requires a different person. Enforced in SQL via requester_id
	// <> approver so it is atomic with the status check.
	guard := ""
	if newStatus == "approved" {
		guard = ` AND r.requester_id <> NULLIF($2,'')::uuid
		  AND NOT EXISTS (SELECT 1 FROM users u
		                   WHERE u.id = r.requester_id AND u.org_id = r.org_id AND u.user_type = 'external'
		                     AND u.sponsor_user_id IS DISTINCT FROM NULLIF($2,'')::uuid)`
	}
	if asSponsor {
		guard += ` AND EXISTS (SELECT 1 FROM users u
		                        WHERE u.id = r.requester_id AND u.org_id = r.org_id AND u.user_type = 'external'
		                          AND u.sponsor_user_id = NULLIF($2,'')::uuid)`
	}

	tag, err := s.db.Pool.Exec(ctx,
		`UPDATE pam_entry_access_requests r
		    SET status = $1, approver_id = NULLIF($2,'')::uuid, decided_at = NOW()
		  WHERE r.id = $3 AND r.org_id = $4 AND r.status = 'pending'`+guard,
		newStatus, approverID, requestID, org.ID)
	if err != nil {
		s.logger.Error("decidePamRequest: update failed",
			zap.String("request_id", logsafe.Clean(requestID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update request"})
		return
	}
	if tag.RowsAffected() == 0 {
		// Say why, for a request that is there and pending; anything else, and
		// on the sponsor's route a request that is not one of the caller's
		// external users', is not found.
		var requesterID, requesterType, sponsorID string
		_ = s.db.Pool.QueryRow(ctx,
			`SELECT r.requester_id::text, COALESCE(u.user_type, ''), COALESCE(u.sponsor_user_id::text, '')
			   FROM pam_entry_access_requests r
			   LEFT JOIN users u ON u.id = r.requester_id AND u.org_id = r.org_id
			  WHERE r.id = $1 AND r.org_id = $2 AND r.status = 'pending'`,
			requestID, org.ID).Scan(&requesterID, &requesterType, &sponsorID)
		external := requesterType == externalid.TypeExternal
		switch {
		case requesterID == "", asSponsor && (!external || sponsorID != approverID):
			c.JSON(http.StatusNotFound, gin.H{"error": "request not found or not pending"})
		case newStatus == "approved" && requesterID == approverID:
			c.JSON(http.StatusForbidden, gin.H{"error": "you cannot approve your own access request (four-eyes)"})
		case newStatus == "approved" && external && sponsorID != approverID:
			c.JSON(http.StatusForbidden, gin.H{
				"error": "an external user's launch is approved by their sponsor",
				"code":  "external_launch_needs_sponsor",
			})
		default:
			c.JSON(http.StatusNotFound, gin.H{"error": "request not found or not pending"})
		}
		return
	}

	as := "administrator"
	if asSponsor {
		as = "sponsor"
	}
	s.logAuditEvent(c, auditAction, requestID, "pam_entry_access_request",
		map[string]interface{}{"request_id": requestID, "approver_id": approverID, "new_status": newStatus, "as": as})
	s.notifyPamLaunchDecision(ctx, org.ID, requestID, newStatus)
	c.JSON(http.StatusOK, gin.H{"request_id": requestID, "status": newStatus})
}

// handlePamSponsorApproveRequest — POST /pam/sponsored/entry-requests/:id/approve.
// The sponsor of an external user approves one of their launch requests.
func (s *Service) handlePamSponsorApproveRequest(c *gin.Context) {
	s.decidePamRequestAs(c, "approved", "pam.access_approved", true)
}

// handlePamSponsorDenyRequest — POST /pam/sponsored/entry-requests/:id/deny.
func (s *Service) handlePamSponsorDenyRequest(c *gin.Context) {
	s.decidePamRequestAs(c, "denied", "pam.access_denied", true)
}

// handlePamListSponsoredRequests — GET /pam/sponsored/entry-requests: the
// pending, unexpired launch requests of the external users the caller
// sponsors. Empty for anyone who sponsors no one.
func (s *Service) handlePamListSponsoredRequests(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT r.id, r.entry_id, e.name, e.entry_type, r.requester_id::text,
		       r.reason, r.status, r.approver_id::text, r.decided_at, r.expires_at, r.created_at
		  FROM pam_entry_access_requests r
		  JOIN pam_entries e ON e.id = r.entry_id AND e.org_id = r.org_id
		  JOIN users u ON u.id = r.requester_id AND u.org_id = r.org_id
		 WHERE r.org_id = $1 AND r.status = 'pending' AND r.expires_at > NOW()
		   AND u.user_type = 'external' AND u.sponsor_user_id = NULLIF($2,'')::uuid
		 ORDER BY r.created_at DESC`, org.ID, c.GetString("user_id"))
	if err != nil {
		s.logger.Error("handlePamListSponsoredRequests: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list requests"})
		return
	}
	defer rows.Close()
	c.JSON(http.StatusOK, gin.H{"requests": scanPamAccessRequests(rows, s.logger)})
}

// PamAccessRequest is the API row for the approval queues.
type PamAccessRequest struct {
	ID          string     `json:"id"`
	EntryID     string     `json:"entry_id"`
	EntryName   string     `json:"entry_name"`
	EntryType   string     `json:"entry_type"`
	RequesterID string     `json:"requester_id"`
	Reason      string     `json:"reason,omitempty"`
	Status      string     `json:"status"`
	ApproverID  *string    `json:"approver_id,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

func scanPamAccessRequests(rows pgx.Rows, logger *zap.Logger) []PamAccessRequest {
	requests := []PamAccessRequest{}
	for rows.Next() {
		var r PamAccessRequest
		var reason *string
		if err := rows.Scan(&r.ID, &r.EntryID, &r.EntryName, &r.EntryType, &r.RequesterID,
			&reason, &r.Status, &r.ApproverID, &r.DecidedAt, &r.ExpiresAt, &r.CreatedAt); err != nil {
			logger.Warn("scanPamAccessRequests: scan failed", zap.Error(err))
			continue
		}
		if reason != nil {
			r.Reason = *reason
		}
		requests = append(requests, r)
	}
	return requests
}

// handlePamListRequests — GET /pam/entry-requests (admin): pending queue.
func (s *Service) handlePamListRequests(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT r.id, r.entry_id, e.name, e.entry_type, r.requester_id::text,
		       r.reason, r.status, r.approver_id::text, r.decided_at, r.expires_at, r.created_at
		  FROM pam_entry_access_requests r
		  JOIN pam_entries e ON e.id = r.entry_id
		 WHERE r.org_id = $1 AND r.status = 'pending'
		 ORDER BY r.created_at DESC`, org.ID)
	if err != nil {
		s.logger.Error("handlePamListRequests: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list requests"})
		return
	}
	defer rows.Close()
	c.JSON(http.StatusOK, gin.H{"requests": scanPamAccessRequests(rows, s.logger)})
}

// handlePamListMyRequests — GET /pam/my-entry-requests: the caller's own
// requests, newest first, all statuses.
func (s *Service) handlePamListMyRequests(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT r.id, r.entry_id, e.name, e.entry_type, r.requester_id::text,
		       r.reason, r.status, r.approver_id::text, r.decided_at, r.expires_at, r.created_at
		  FROM pam_entry_access_requests r
		  JOIN pam_entries e ON e.id = r.entry_id
		 WHERE r.org_id = $1 AND r.requester_id::text = $2
		 ORDER BY r.created_at DESC
		 LIMIT 100`, org.ID, userID)
	if err != nil {
		s.logger.Error("handlePamListMyRequests: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list requests"})
		return
	}
	defer rows.Close()
	c.JSON(http.StatusOK, gin.H{"requests": scanPamAccessRequests(rows, s.logger)})
}

// ---- Session ledger ----

// PamEntrySession is the API row for the launch ledger.
type PamEntrySession struct {
	ID                 string     `json:"id"`
	EntryID            string     `json:"entry_id"`
	EntryName          string     `json:"entry_name"`
	UserID             *string    `json:"user_id,omitempty"`
	Protocol           *string    `json:"protocol,omitempty"`
	CredentialInjected bool       `json:"credential_injected"`
	RecordingAvailable bool       `json:"recording_available"`
	StartedAt          time.Time  `json:"started_at"`
	EndedAt            *time.Time `json:"ended_at,omitempty"`
	Status             string     `json:"status"`
}

// handlePamListSessions — GET /pam/sessions (admin): recent launches.
func (s *Service) handlePamListSessions(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	rows, err := s.db.Pool.Query(ctx, `
		SELECT s.id, s.entry_id, e.name, s.user_id::text, s.protocol,
		       s.credential_injected, (COALESCE(s.recording_path,'') <> ''),
		       s.started_at, s.ended_at, s.status
		  FROM pam_entry_sessions s
		  JOIN pam_entries e ON e.id = s.entry_id
		 WHERE s.org_id = $1
		 ORDER BY s.started_at DESC
		 LIMIT 200`, org.ID)
	if err != nil {
		s.logger.Error("handlePamListSessions: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sessions"})
		return
	}
	defer rows.Close()

	sessions := []PamEntrySession{}
	for rows.Next() {
		var r PamEntrySession
		if err := rows.Scan(&r.ID, &r.EntryID, &r.EntryName, &r.UserID, &r.Protocol,
			&r.CredentialInjected, &r.RecordingAvailable, &r.StartedAt, &r.EndedAt, &r.Status); err != nil {
			s.logger.Warn("handlePamListSessions: scan failed", zap.Error(err))
			continue
		}
		sessions = append(sessions, r)
	}
	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

// handlePamEndSession — POST /pam/sessions/:id/end. The launcher (or an
// admin) marks a ledger row ended; purely bookkeeping — Guacamole session
// termination is the existing admin force-terminate surface.
func (s *Service) handlePamEndSession(c *gin.Context) {
	sessionID := c.Param("id")
	userID := c.GetString("user_id")
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	query := `UPDATE pam_entry_sessions SET status = 'ended', ended_at = NOW()
	           WHERE id = $1 AND org_id = $2 AND status = 'active'`
	args := []interface{}{sessionID, org.ID}
	if !s.pamCallerIsAdmin(c) {
		query += ` AND user_id::text = $3`
		args = append(args, userID)
	}

	tag, err := s.db.Pool.Exec(ctx, query, args...)
	if err != nil {
		s.logger.Error("handlePamEndSession: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to end session"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "active session not found"})
		return
	}
	s.pamSessionEnded(org.ID, sessionID, sessionEndRequested, userID)

	// Best-effort JIT revoke of the per-user connection READ grant on the broker
	// that served this session (per-user identities path only).
	var connID, guacUser, reach string
	if qerr := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(pes.guac_connection_id,''), COALESCE(pes.guac_username,''),
		       COALESCE(e.reach_mode,'')
		  FROM pam_entry_sessions pes JOIN pam_entries e ON e.id = pes.entry_id
		 WHERE pes.id = $1 AND pes.org_id = $2`, sessionID, org.ID).Scan(&connID, &guacUser, &reach); qerr == nil {
		if connID != "" && guacUser != "" {
			if broker := s.brokerFor(reach); broker != nil && broker.perUserIdentities {
				if rerr := broker.revokeConnectionRead(ctx, guacUser, connID); rerr != nil {
					s.logger.Warn("handlePamEndSession: revoke connection READ failed",
						zap.String("guac_user", guacUser), zap.String("conn_id", connID), zap.Error(rerr))
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"id": sessionID, "status": "ended"})
}
