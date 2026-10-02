package access

// The PAM controls an external (vendor) user's session runs under, whatever
// the entry says: invariants I5 and I7 of the third-party access framework and
// its decision D7(b).
//
//   - I5. The launch approval and the recording are on, and the target hop is
//     on the overlay with PAM_REQUIRE_ZTNA read as "enforce", whatever the entry
//     and the global gate say. No administrator bypass applies, whatever roles
//     the token claims. No path hands the user a credential: reveal,
//     break-glass, an SSH certificate and cloud keys are refused.
//   - I7. Clipboard, drive, file transfer and printing are off, and the entry's
//     settings cannot turn them on or weaken the recording. The session is
//     also capped at externalid.MaxPamSession by the lifecycle sweep.
//
// Everything that makes the session what I5 says (its own broker connection,
// its own broker identity, a recording path) is checked before the launch
// approval is spent, and a launch that cannot have them is refused rather than
// run without them.

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/externalid"
)

// pamCaller is who is launching, as every PAM launch path needs it.
type pamCaller struct {
	UserID string
	// Admin is whether the administrator bypass applies. Never for an
	// external user: I2 keeps the admin role off them, and if a token claimed
	// it anyway, I5 still holds.
	Admin bool
	// External is whether the caller is an external (vendor) user.
	External bool
}

// resolvePamCaller reads the caller's type. When the type cannot be read it
// answers 500 and reports false: a launch does not go ahead under the looser
// rules because the stricter ones could not be looked up.
func (s *Service) resolvePamCaller(c *gin.Context, orgID string) (pamCaller, bool) {
	userID := c.GetString("user_id")
	external, err := externalid.IsExternal(c.Request.Context(), s.db.Pool, orgID, userID)
	if err != nil {
		s.logger.Error("could not read whether the PAM caller is external", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check permissions"})
		return pamCaller{}, false
	}
	return pamCaller{UserID: userID, Admin: !external && s.pamCallerIsAdmin(c), External: external}, true
}

// pinExternalPamPolicy sets on the launch what I5 makes true for an external
// caller whatever the entry's row says: a launch approval, a recording, and
// the session hardening of I7. A no-op for anyone else.
func pinExternalPamPolicy(entry *pamLaunchEntry, caller pamCaller) {
	if !caller.External {
		return
	}
	entry.External = true
	entry.RequireApproval = true
	entry.RecordSession = true
}

// pamExternalSessionParams are the broker parameters an external user's
// session runs with, whatever the entry's settings say (I7): no clipboard in
// either direction, no drive redirection, no file transfer over the drive or
// SFTP, no printing. They are applied after everything else, so no stored
// setting can open them.
var pamExternalSessionParams = map[string]string{
	"disable-copy":          "true",
	"disable-paste":         "true",
	"enable-drive":          "false",
	"disable-download":      "true",
	"disable-upload":        "true",
	"enable-sftp":           "false",
	"sftp-disable-download": "true",
	"sftp-disable-upload":   "true",
	"enable-printing":       "false",
}

// pamExternalStrippedParams are settings that would leave an external user's
// recording without what it is for (I5): the screen, the pointer or the
// touches. buildPamGuacParams already keeps the recording's path, name and
// keystrokes out of the settings' reach.
var pamExternalStrippedParams = []string{
	"recording-exclude-output",
	"recording-exclude-mouse",
	"recording-exclude-touch",
}

// hardenExternalGuacParams applies I7 to an external user's broker parameters.
func hardenExternalGuacParams(params map[string]string) {
	for _, k := range pamExternalStrippedParams {
		delete(params, k)
	}
	for k, v := range pamExternalSessionParams {
		params[k] = v
	}
}

// externalSessionPolicy is what an external user's launch answers about the
// controls it ran under, so the console shows what is enforced rather than
// what the entry says.
func externalSessionPolicy() gin.H {
	return gin.H{
		"approval":      true,
		"recorded":      true,
		"overlay":       true,
		"clipboard":     false,
		"drive":         false,
		"file_transfer": false,
		"printing":      false,
		"max_minutes":   int(externalid.MaxPamSession.Minutes()),
	}
}

// refuseExternalPam answers an external caller's refusal on a PAM path with
// the refusal's code, and audits it as action: the refusal is on the trail
// with the rest of the denied PAM decisions, not only in the response.
func (s *Service) refuseExternalPam(c *gin.Context, action, targetID, targetType string, status int, refusal error, details map[string]interface{}) {
	code := externalid.Code(refusal)
	audit := map[string]interface{}{"user_id": c.GetString("user_id"), "code": code, "external": true}
	for k, v := range details {
		audit[k] = v
	}
	s.logAuditEvent(c, action, targetID, targetType, audit)
	c.JSON(status, gin.H{"error": refusal.Error(), "code": code})
}

// externalLaunchRefusal is what stops an external user's launch before it
// starts: the broker must give the session its own identity (the shared token
// opens every connection on the broker), and the recording must have
// somewhere to go. Asked before the launch approval is spent and before a
// credential is resolved. Nil when the launch may go ahead, and always for a
// caller who is not external. The broker itself being absent is
// launchPamSession's to report.
func (s *Service) externalLaunchRefusal(entry *pamLaunchEntry) (int, error) {
	if !entry.External {
		return 0, nil
	}
	if broker := s.brokerFor(entry.ReachMode); broker != nil && !broker.perUserIdentities {
		return http.StatusServiceUnavailable, externalid.ErrBrokerIdentityRequired
	}
	if s.config == nil || s.config.GuacamoleRecordingPath == "" {
		return http.StatusServiceUnavailable, externalid.ErrRecordingUnavailable
	}
	return 0, nil
}

// refuseExternalLaunch answers externalLaunchRefusal's refusal, audited as
// pam.launch_denied, and reports whether it refused.
func (s *Service) refuseExternalLaunch(c *gin.Context, entry *pamLaunchEntry) bool {
	status, refusal := s.externalLaunchRefusal(entry)
	if refusal == nil {
		return false
	}
	s.refuseExternalPam(c, "pam.launch_denied", entry.ID, "pam_entry", status, refusal,
		map[string]interface{}{"entry_id": entry.ID})
	return true
}

// refuseExternalCaller answers refusal to an external caller on a path closed
// to them (I5): a credential shown (reveal, break-glass) or issued (an SSH
// certificate, cloud keys). It is audited as action, which names the path's
// own denial event. Reports whether it wrote a response: true for an external
// caller, and also when the caller's type could not be read (a 500, not a
// launch under looser rules).
func (s *Service) refuseExternalCaller(c *gin.Context, orgID string, refusal error, action, targetID, targetType string, details map[string]interface{}) bool {
	caller, ok := s.resolvePamCaller(c, orgID)
	if !ok {
		return true
	}
	if !caller.External {
		return false
	}
	s.refuseExternalPam(c, action, targetID, targetType, http.StatusForbidden, refusal, details)
	return true
}

// presentPamEntryToExternal makes an entry, as an external user is shown it,
// say what their launch will do rather than what the row says (I5): a launch
// approval and a recording, and no reveal or break-glass, so the console
// offers neither a Connect that skips the approval step nor a Reveal that
// answers 403.
func presentPamEntryToExternal(e *PamEntry) {
	e.RequireApproval = true
	e.RecordSession = true
	e.AllowReveal = false
	e.BreakGlassEnabled = false
	if e.Actions == nil {
		return
	}
	actions := make([]string, 0, len(e.Actions))
	for _, a := range e.Actions {
		if a != "reveal" {
			actions = append(actions, a)
		}
	}
	e.Actions = actions
}

// refuseClosedTarget is invariant I11 at a launch: an external user whose
// vendor organization is on a closed list launches only an entry opened to
// the vendor, whatever grant they hold. It answers 403
// external_target_not_open, audited as pam.launch_denied, and reports true
// when it wrote a response (a 500 when the list could not be read).
func (s *Service) refuseClosedTarget(c *gin.Context, orgID string, caller pamCaller, entryID string) bool {
	if !caller.External {
		return false
	}
	err := externalid.CheckTargetOpen(c.Request.Context(), s.db.Pool, orgID, caller.UserID, "pam_entry", entryID)
	if err == nil {
		return false
	}
	if errors.Is(err, externalid.ErrTargetNotOpen) {
		s.refuseExternalPam(c, "pam.launch_denied", entryID, "pam_entry", http.StatusForbidden, err,
			map[string]interface{}{"entry_id": entryID})
		return true
	}
	s.logger.Error("could not read the caller's vendor list", zap.Error(err))
	c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check permissions"})
	return true
}

// closedListEntries is the set of PAM entries open to an external caller's
// vendor organization when it is on a closed list (I11), for the lists an
// external user reads; nil when no list applies, which hides nothing.
func (s *Service) closedListEntries(ctx context.Context, orgID string, caller pamCaller) (map[string]bool, error) {
	if !caller.External {
		return nil, nil
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT v.closed_list, COALESCE(t.target_id::text, '')
		  FROM users u
		  JOIN vendor_organizations v ON v.id = u.vendor_org_id AND v.org_id = u.org_id
		  LEFT JOIN vendor_org_targets t
		         ON t.vendor_org_id = v.id AND t.org_id = v.org_id AND t.target_type = 'pam_entry'
		 WHERE u.id = $1::uuid AND u.org_id = $2 AND u.user_type = 'external'`, caller.UserID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var open map[string]bool
	for rows.Next() {
		var closed bool
		var target string
		if err := rows.Scan(&closed, &target); err != nil {
			return nil, err
		}
		if !closed {
			return nil, nil
		}
		if open == nil {
			open = map[string]bool{}
		}
		if target != "" {
			open[target] = true
		}
	}
	return open, rows.Err()
}
