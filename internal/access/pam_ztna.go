package access

import (
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
)

// PAM over ZTNA — the decision, and an honest account of which half of it this
// file can make.
//
// A brokered privileged session has two legs:
//
//	user  → broker    the connect URL the console opens
//	broker → target   guacd's dial to the machine being administered
//
// The SECOND leg is decided here, per launch, from pam_entries.reach_mode, and
// it is decided completely: with the gate enforcing, a launch that would dial
// the target directly is refused before any credential is resolved, and an
// entry cannot be created or updated into that state. Migration v82 made
// 'direct' the column default, so this is not a rare case to catch — it is what
// an entry created without a deliberate choice does.
//
// The FIRST leg is not decided here, and pretending otherwise would be the
// worse outcome. Nothing in an HTTP request proves the caller reached this
// service over the overlay; a header saying so is set by whoever is calling.
// That leg is closed by the broker being published as a Ziti service and at no
// other address, so the connect URL's host routes for a machine running the
// client and for nothing else — a property of the deployment, not of a check.
// What this code does about it is refuse to start unless the configuration that
// property needs is present (config.ValidateProduction), and route every
// enforced launch through the overlay broker rather than the direct one, so the
// URL that comes back is the overlay-only one.
//
// The gate is tri-state like the others (PAM_SESSION_RISK_GATE,
// POSTURE_DEVICE_TRUST_GATE, ABAC_ENFORCE) and observe mode audits what enforce
// would refuse, because an operator turning this on needs to know how many of
// their entries are 'direct' before it starts refusing them.

// ztnaMode is the parsed PAM_REQUIRE_ZTNA setting.
type ztnaMode int

const (
	ztnaOff ztnaMode = iota
	ztnaObserve
	ztnaEnforce
)

// pamZTNAMode reads the configured mode. An unrecognised value is "off": this
// gate refuses privileged sessions, and a typo must not do that silently — the
// value is echoed by ReportModeGates and by the ops cockpit, where "off" next
// to a setting the operator believes says "enforce" is visible.
func (s *Service) pamZTNAMode() ztnaMode {
	if s.config == nil {
		return ztnaOff
	}
	switch strings.ToLower(strings.TrimSpace(s.config.PAMRequireZTNA)) {
	case "enforce":
		return ztnaEnforce
	case "observe":
		return ztnaObserve
	default:
		return ztnaOff
	}
}

// pamZTNAModeName renders the mode for the broker-status probe the launcher
// reads. It reports what the service will DO — an unrecognised value is "off",
// the same reading pamZTNAMode gives it — rather than echoing the raw setting,
// so the console cannot show "enforce" over a gate that is not enforcing.
func (s *Service) pamZTNAModeName() string {
	switch s.pamZTNAMode() {
	case ztnaEnforce:
		return "enforce"
	case ztnaObserve:
		return "observe"
	default:
		return "off"
	}
}

// ztnaVerdict is the outcome of the reach check for one launch.
type ztnaVerdict struct {
	// Refuse is true when the launch must not proceed.
	Refuse bool
	// WouldRefuse is true when enforcement is not on but would have refused.
	WouldRefuse bool
	// Reason names what is wrong, in the words the operator needs.
	Reason string
	// Code is the machine-readable reason the console switches on.
	Code string
}

// pamReachIsOverlayOnly reports whether a launch of this entry stays on the
// overlay for its target hop.
//
// Website entries are not overlay-only and are not a special case worth
// excusing: the launch hands a raw URL to a browser and brokers nothing, so
// there is no hop to put on the overlay and no session to record beyond the
// click. Under enforcement they are refused with that said plainly, and the
// remedy — publish the site as an overlay service or a proxy route, both of
// which this product has — is named in the message rather than left to be
// guessed.
func pamReachIsOverlayOnly(reachMode, protocol string) (ok bool, code, reason string) {
	if protocol == "" {
		return false, "ztna_required_website_entry",
			"this is a website entry: it returns a URL for the browser to open and brokers no session, " +
				"so nothing about it travels the overlay. Publish the site as an OpenZiti service or as a " +
				"proxy route and reach it that way, or turn PAM_REQUIRE_ZTNA back to observe"
	}
	if !strings.EqualFold(strings.TrimSpace(reachMode), "ziti") {
		return false, "ztna_required_direct_reach",
			"this entry reaches its target directly rather than over the OpenZiti overlay " +
				"(reach_mode=" + valueOrDirect(reachMode) + "), so the session would open a socket to the " +
				"target's real address from the broker's network. Set the entry's reach mode to ziti and give " +
				"it an overlay service"
	}
	return true, "", ""
}

// valueOrDirect renders an empty reach_mode as what it behaves as. The column
// is NOT NULL DEFAULT 'direct', but a row read through a COALESCE can still
// arrive empty, and "reach_mode=" with nothing after it tells the reader less
// than the truth does.
func valueOrDirect(v string) string {
	if strings.TrimSpace(v) == "" {
		return "direct (unset)"
	}
	return v
}

// checkPamZTNA decides whether this launch may proceed, and audits the decision.
//
// It is called before credential resolution, not after: a refused launch must
// not have decrypted a vault secret or pushed it into a Guacamole connection on
// its way to being refused.
func (s *Service) checkPamZTNA(c *gin.Context, orgID, userID, entryID, reachMode, protocol string) ztnaVerdict {
	mode := s.pamZTNAMode()
	if mode == ztnaOff {
		return ztnaVerdict{}
	}
	ok, code, reason := pamReachIsOverlayOnly(reachMode, protocol)
	if ok {
		return ztnaVerdict{}
	}

	enforcing := mode == ztnaEnforce
	s.auditPamZTNA(c, userID, entryID, reachMode, code, enforcing)
	s.logger.Warn("PAM launch does not stay on the overlay",
		zap.String("entry_id", logsafe.Clean(entryID)),
		zap.String("reach_mode", logsafe.Clean(reachMode)),
		zap.String("code", code),
		zap.Bool("enforced", enforcing))

	if enforcing {
		return ztnaVerdict{Refuse: true, Reason: reason, Code: code}
	}
	return ztnaVerdict{WouldRefuse: true, Reason: reason, Code: code}
}

// auditPamZTNA records the decision on the audit trail.
//
// Observe mode writes too, and that is the point of observe mode: an operator
// sizing this change needs the list of entries that would stop working, and a
// count they can only get by the attempts being recorded.
func (s *Service) auditPamZTNA(c *gin.Context, userID, entryID, reachMode, code string, enforced bool) {
	action := "pam.ztna.would_deny"
	if enforced {
		action = "pam.ztna.denied"
	}
	s.logAuditEvent(c, action, entryID, "pam_entry", map[string]interface{}{
		"user_id":    userID,
		"reach_mode": reachMode,
		"code":       code,
		"enforced":   enforced,
	})
}
