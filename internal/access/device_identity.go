package access

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// A DEVICE IS AN IDENTITY ON THE OVERLAY, AND ITS TRUST IS ITS OWN.
//
// Every enrolled agent got an OpenZiti identity, named after the agent and
// carrying #openidx-agent and nothing else: it could reach remote support
// and no application. Access attributes (groups, assigned applications,
// #device-trusted) lived on the USER's identity, so "device trusted" meant
// "this person has some trusted device", one device's compliance changed
// what every device of theirs could reach, and posture's change to that
// attribute was overwritten by the next user sync.
//
// The device identity is now the one that reaches applications. It is named
// dev-<agent_id>, recorded in ziti_identities with agent_id, and carries:
//   #openidx-agent #device-<agent_id> #user-<user_id>
//   the user's groups, assigned applications, JIT grants and org marker
//   #device-trusted — from THIS agent's compliance, under the posture gate
// The user identity keeps groups and applications for clientless (BrowZer)
// access and never carries #device-trusted: a resource that requires a
// trusted device is reachable from a compliant device and from nothing else.
// A device whose posture fails loses the attribute and its live circuits.

func deviceIdentityName(agentID string) string { return "dev-" + agentID }

// deviceAttributesFrom composes a device identity's attributes. userAttrs are
// the enrolling user's attributes as buildUserAttributes gives them; the
// user-only markers are dropped and the device's own are added.
func deviceAttributesFrom(agentID, userID string, userAttrs []string, trusted bool) []string {
	out := []string{"openidx-agent", "device-" + agentID}
	if userID != "" {
		out = append(out, "user-"+userID)
	}
	for _, a := range userAttrs {
		switch a {
		case "device-trusted", "browzer-users", "openidx-agent":
			// Trust is the device's own; BrowZer is the clientless path.
			// enrolled-users stays: the dark Tier 1 services dial by it.
			continue
		}
		out = append(out, a)
	}
	if trusted {
		out = append(out, "device-trusted")
	}
	return out
}

type deviceIdentityRow struct {
	agentID, zitiID, userID, orgID, compliance, status string
}

func (zm *ZitiManager) loadDeviceIdentityRow(ctx context.Context, agentID string) (deviceIdentityRow, error) {
	var r deviceIdentityRow
	err := zm.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx), `
		SELECT agent_id, COALESCE(ziti_identity_id,''), COALESCE(enrolled_by_user_id::text,''),
		       COALESCE(org_id::text,''), COALESCE(compliance_status,''), COALESCE(status,'')
		  FROM enrolled_agents WHERE agent_id = $1`, agentID).Scan(
		&r.agentID, &r.zitiID, &r.userID, &r.orgID, &r.compliance, &r.status)
	return r, err
}

// deviceTrustFromCompliance applies the posture gate: off never grants,
// observe only logs what it would do, enforce grants on compliance.
func (zm *ZitiManager) deviceTrustFromCompliance(agentID, compliance string) bool {
	mode := ""
	if zm.cfg != nil {
		mode = strings.ToLower(strings.TrimSpace(zm.cfg.PostureDeviceTrustGate))
	}
	want := compliance == "compliant"
	switch mode {
	case "enforce":
		return want
	case "observe":
		zm.logger.Info("posture tier (observe): would set device-trust from compliance",
			zap.String("agent_id", agentID), zap.Bool("trusted", want), zap.String("compliance", compliance))
	}
	return false
}

// DeviceAttributes is what the agent's identity should carry now.
func (zm *ZitiManager) DeviceAttributes(ctx context.Context, agentID string) ([]string, error) {
	r, err := zm.loadDeviceIdentityRow(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("device identity: load agent %s: %w", agentID, err)
	}
	var userAttrs []string
	if r.userID != "" {
		if ua, uerr := zm.buildUserAttributes(orgctx.WithBypassRLS(ctx), r.userID); uerr == nil {
			userAttrs = ua
		} else {
			zm.logger.Warn("device identity: user attributes unavailable; device carries its own only",
				zap.String("agent_id", agentID), zap.Error(uerr))
		}
	}
	trusted := r.status == "active" && zm.deviceTrustFromCompliance(agentID, r.compliance)
	return deviceAttributesFrom(agentID, r.userID, userAttrs, trusted), nil
}

// SyncDeviceIdentity writes the agent's identity its attributes and name, and
// records it in ziti_identities. An agent without an identity is left alone.
func (zm *ZitiManager) SyncDeviceIdentity(ctx context.Context, agentID string) error {
	r, err := zm.loadDeviceIdentityRow(ctx, agentID)
	if err != nil {
		return fmt.Errorf("device identity: load agent %s: %w", agentID, err)
	}
	if r.zitiID == "" {
		return nil
	}
	attrs, err := zm.DeviceAttributes(ctx, agentID)
	if err != nil {
		return err
	}
	// An identity created before this release is named after the agent;
	// the rename is a PATCH and needs no re-enrolment.
	if err := zm.PatchIdentityName(ctx, r.zitiID, deviceIdentityName(agentID)); err != nil {
		zm.logger.Debug("device identity: rename skipped", zap.String("agent_id", agentID), zap.Error(err))
	}
	if err := zm.PatchIdentityRoleAttributes(ctx, r.zitiID, attrs); err != nil {
		return fmt.Errorf("device identity: patch attributes for %s: %w", agentID, err)
	}
	attrsJSON, _ := json.Marshal(attrs)
	if r.orgID != "" {
		if _, err := zm.db.Pool.Exec(orgctx.WithBypassRLS(ctx), `
			INSERT INTO ziti_identities (ziti_id, name, identity_type, user_id, agent_id, enrolled, attributes, group_attrs_synced_at, org_id)
			VALUES ($1, $2, 'Device', NULLIF($3,'')::uuid, $4, true, $5, NOW(), $6::uuid)
			ON CONFLICT (agent_id) WHERE agent_id IS NOT NULL DO UPDATE
			   SET ziti_id = EXCLUDED.ziti_id, name = EXCLUDED.name, user_id = EXCLUDED.user_id,
			       attributes = EXCLUDED.attributes, group_attrs_synced_at = NOW(), updated_at = NOW()`,
			r.zitiID, deviceIdentityName(agentID), r.userID, agentID, attrsJSON, r.orgID); err != nil {
			// The name is unique: an older row for the same name (a user
			// identity cannot share it; a legacy device row can) is reconciled
			// by name instead.
			if _, err2 := zm.db.Pool.Exec(orgctx.WithBypassRLS(ctx), `
				UPDATE ziti_identities SET agent_id = $1, ziti_id = $2, attributes = $3, group_attrs_synced_at = NOW(), updated_at = NOW()
				 WHERE name = $4 AND agent_id IS NULL`, agentID, r.zitiID, attrsJSON, deviceIdentityName(agentID)); err2 != nil {
				zm.logger.Warn("device identity: could not record the identity row",
					logsafe.String("agent_id", agentID), zap.Error(err), zap.NamedError("by_name", err2))
			}
		}
	}
	return nil
}

// SeverDeviceCircuits ends every live session and circuit of the agent's
// identity. A device whose posture failed keeps nothing it already had.
func (zm *ZitiManager) SeverDeviceCircuits(ctx context.Context, agentID string) {
	r, err := zm.loadDeviceIdentityRow(ctx, agentID)
	if err != nil || r.zitiID == "" {
		return
	}
	zm.TerminateIdentitySessions(ctx, r.zitiID)
	zm.logger.Info("device identity: live circuits severed",
		zap.String("agent_id", agentID), zap.String("ziti_id", logsafe.Clean(r.zitiID)))
}

// syncDeviceIdentitiesForUser re-patches every device the user enrolled, so
// a change to their groups or assignments reaches their devices too.
func (zm *ZitiManager) syncDeviceIdentitiesForUser(ctx context.Context, userID string) {
	rows, err := zm.db.Pool.Query(orgctx.WithBypassRLS(ctx), `
		SELECT agent_id FROM enrolled_agents
		 WHERE enrolled_by_user_id = $1::uuid AND status = 'active' AND COALESCE(ziti_identity_id,'') <> ''`, userID)
	if err != nil {
		return
	}
	var agents []string
	for rows.Next() {
		var a string
		if rows.Scan(&a) == nil {
			agents = append(agents, a)
		}
	}
	rows.Close()
	for _, a := range agents {
		if err := zm.SyncDeviceIdentity(ctx, a); err != nil {
			zm.logger.Warn("device identity: sync for user's device failed", zap.String("agent_id", a), zap.Error(err))
		}
	}
}

// deviceSyncStaleAfter is how old a device identity's recorded attributes may
// be before the poller re-patches them, the same bound the user sync uses.
const deviceSyncStaleAfter = 5 * time.Minute

// syncStaleDeviceIdentities is the poller's share: devices with an identity
// but no ziti_identities row (enrolled before this release), and rows older
// than deviceSyncStaleAfter. At most a page per cycle.
func (zm *ZitiManager) syncStaleDeviceIdentities(ctx context.Context) {
	rows, err := zm.db.Pool.Query(orgctx.WithBypassRLS(ctx), `
		SELECT ea.agent_id FROM enrolled_agents ea
		  LEFT JOIN ziti_identities zi ON zi.agent_id = ea.agent_id
		 WHERE ea.status = 'active' AND COALESCE(ea.ziti_identity_id,'') <> ''
		   AND (zi.id IS NULL OR zi.group_attrs_synced_at IS NULL OR zi.group_attrs_synced_at < NOW() - $1::interval)
		 ORDER BY zi.group_attrs_synced_at NULLS FIRST
		 LIMIT 50`, deviceSyncStaleAfter.String())
	if err != nil {
		zm.logger.Debug("device identity: stale scan failed", zap.Error(err))
		return
	}
	var agents []string
	for rows.Next() {
		var a string
		if rows.Scan(&a) == nil {
			agents = append(agents, a)
		}
	}
	rows.Close()
	for _, a := range agents {
		if err := zm.SyncDeviceIdentity(ctx, a); err != nil {
			zm.logger.Warn("device identity: stale sync failed", zap.String("agent_id", a), zap.Error(err))
		}
	}
	if len(agents) > 0 {
		zm.logger.Info("device identity: synced", zap.Int("devices", len(agents)))
	}
}
