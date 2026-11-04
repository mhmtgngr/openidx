package access

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Agent authentication for the public agent surface.
//
// /api/v1/access/agent/* is registered OUTSIDE the JWT middleware, because an
// agent has no tenant JWT — it authenticates with the credentials enrollment
// handed it. Four comments in this package say so, and three handlers name
// /agent/report as the endpoint whose pattern they copy:
//
//	windows_apps_discovery.go:61  "Auth is X-Agent-ID + X-Auth-Token (same as /agent/report)"
//	remote_support_api.go:538     "The agent proves ownership with X-Agent-ID + X-Auth-Token (same as the agent...)"
//	service.go:1071               "authenticated via the same X-Agent-ID + X-Auth-Token pattern as /agent/report"
//	agent_api.go:143              "posture report (carries X-Agent-ID + auth token), and config (same)"
//
// /agent/report and /agent/config had no such check. They took the agent id out
// of the request — the JSON body, a header, a query parameter — and trusted it.
// The reference implementation everything else was written against did not
// exist, and that is not a thing three separate copies of the same lookup can
// tell you: it is what one shared function makes impossible to get wrong again.
//
// So the lookup lives here once, and Service.verifyAgentToken and
// RemoteSupportHandler.verifyAgentAuth delegate to it.

// agentStatusRevoked is the enrolled_agents.status an administrator's revoke
// writes, from the fleet console and from a user's own device list alike.
const agentStatusRevoked = "revoked"

// verifyEnrolledAgent reports whether token is the credential enrollment issued
// for agentID, by comparing its SHA-256 against enrolled_agents.auth_token_hash,
// and returns the tenant the agent belongs to and its status.
//
// ok is true only for an agent that may still act as one. A revoked agent
// presenting its own, correct token comes back with ok=false, its tenant and
// status "revoked": revoking a device sets the status and leaves the token hash
// in place, so before this check the token went on working on every agent route
// after the revoke. Returning ok=false rather than leaving the status for each
// caller to test means a caller that forgets the status refuses the device
// with a 401 instead of letting it in. A caller that does test it answers 403,
// which is how the Go agent learns it was revoked. The status is returned only
// when the token matched, so a caller without the credential cannot learn
// whether an agent was revoked. Every other status passes: a suspended agent
// still needs its config, which tells it to block, and its reports are how it
// becomes compliant again.
//
// Since v197 the fleet is per-tenant and enrolled_agents is belted. An agent
// callback still arrives with no tenant context -- its credential is the agent
// token, not a tenant JWT -- so this ONE read runs under an explicit RLS
// bypass keyed by the globally-unique agent_id, and the row's own org_id is
// what the caller puts on the request context. Everything after this read is
// tenant-scoped; nothing after it is allowed to bypass.
//
// With no database — unit tests and dev builds that construct a handler without
// one — any non-empty token is accepted with an empty tenant, matching what the
// two existing verifiers have always done. Nothing is persisted on that path.
func verifyEnrolledAgent(ctx context.Context, db *database.PostgresDB, agentID, token string) (orgID, status string, ok bool) {
	if agentID == "" || token == "" {
		return "", "", false
	}
	if db == nil || db.Pool == nil {
		return "", "", true // dev mode: any non-empty token, as the other agent surfaces do
	}
	var stored string
	//orgscope:ignore agent credential check: keyed by the globally-unique agent_id before any tenant is resolvable; the row's own org_id is what scopes everything after
	if err := db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		`SELECT auth_token_hash, org_id::text, status FROM enrolled_agents WHERE agent_id = $1`,
		agentID).Scan(&stored, &orgID, &status); err != nil {
		return "", "", false
	}
	// The comparison runs in constant time so that how long a refusal takes
	// says nothing about how much of the presented hash matched the stored one.
	if stored == "" || subtle.ConstantTimeCompare([]byte(sha256Hex(token)), []byte(stored)) != 1 {
		return "", "", false
	}
	if status == agentStatusRevoked {
		return orgID, status, false
	}
	return orgID, status, true
}

// refuseRevokedAgent answers an agent whose credential is correct but whose
// enrolment has been revoked, and audits the refusal in the agent's tenant.
//
// Every agent route answers it the same way, 403 with code agent_revoked. The
// Go agent maps a 403 from /agent/config to ErrAgentRevoked
// (agent/internal/transport/client.go GetConfig) and shows its user that the
// device was revoked (agent/internal/control/device_state.go). A 401 would be
// shown as a server it could not reach, which retrying will never fix.
//
// audit is the handler that owns the agent-lifecycle audit stream. It may be
// nil where a surface is built without one, and the refusal is still answered.
func refuseRevokedAgent(c *gin.Context, audit *AgentAPIHandler, orgID, agentID string) {
	if audit != nil {
		ctx := c.Request.Context()
		if orgID != "" {
			ctx = orgctx.With(ctx, orgctx.Org{ID: orgID})
		}
		audit.logAuditEvent("agent.auth_failed", agentID, "denied", "agent revoked")
		audit.logAuditEventToDB(ctx, "agent.auth_failed", agentID, "denied", "agent revoked")
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "agent revoked", "code": "agent_revoked"})
}

// agentCredentials reads the agent id and token a request presents.
//
// Two spellings for the token, because the product ships two agents and they
// send different ones. X-Auth-Token is the canonical spelling — it is what the
// remote-support and Windows-app endpoints read, what every comment describes,
// and what the Android agent sends (agent-android/core ServerApi.kt:170,187).
// The Go agent sends the same credential as `Authorization: Bearer` on exactly
// these two endpoints (agent/internal/transport/client.go:103,129).
//
// Accepting both is not laxity. It is the set of spellings the product already
// emits: reading only one would lock every deployed agent of the other kind out
// of posture reporting, which is a control failing closed on the devices it is
// meant to measure.
func agentCredentials(c *gin.Context) (agentID, token string) {
	agentID = strings.TrimSpace(c.GetHeader("X-Agent-ID"))
	token = strings.TrimSpace(c.GetHeader("X-Auth-Token"))
	if token == "" {
		if auth := strings.TrimSpace(c.GetHeader("Authorization")); len(auth) > 7 &&
			strings.EqualFold(auth[:7], "bearer ") {
			token = strings.TrimSpace(auth[7:])
		}
	}
	return agentID, token
}

// requireEnrolledAgent authenticates the calling agent, puts the agent's tenant
// on the request context, and returns the agent id.
//
// On failure it answers and returns ok=false; the caller must return. A revoked
// agent is answered 403 (see refuseRevokedAgent), anything else 401. The
// refusal is audited with the id that was claimed, because a report arriving
// for an agent id with the wrong credential is the shape of someone probing the
// fleet, and the endpoint is public.
//
// The tenant on the context is what makes every fleet query after this point
// tenant-scoped under the v197 belt without a bypass: the agent proved it
// holds the credential for a row, and that row names its tenant.
func (h *AgentAPIHandler) requireEnrolledAgent(c *gin.Context) (string, bool) {
	agentID, token := agentCredentials(c)
	orgID, status, ok := verifyEnrolledAgent(c.Request.Context(), h.db, agentID, token)
	if status == agentStatusRevoked {
		refuseRevokedAgent(c, h, orgID, agentID)
		return "", false
	}
	if !ok {
		h.logAuditEvent("agent.auth_failed", agentID, "denied", "invalid agent credentials")
		h.logAuditEventToDB(c.Request.Context(), "agent.auth_failed", agentID, "denied",
			"invalid agent credentials")
		h.recordAgentAuthFailure(c.Request.Context(), agentID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid agent credentials"})
		return "", false
	}
	h.clearAgentAuthFailures(c.Request.Context(), agentID)
	if orgID != "" {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: orgID}))
	}
	return agentID, true
}

// orgIDFrom is the tenant on ctx, or "" when none is attached. Fleet queries
// use it as their org_id predicate; with "" the predicate matches nothing,
// which under the belt is also what RLS would have returned.
func orgIDFrom(ctx context.Context) string {
	org, err := orgctx.From(ctx)
	if err != nil {
		return ""
	}
	return org.ID
}

// authFailPersistentThreshold is the run of refused requests after which the
// refusal is a state worth one record of its own. A running agent asks for its
// config and posts a report each cycle, so this is a few cycles: it rides out a
// racing re-enrolment and still names the device the same day.
const authFailPersistentThreshold = 6

// recordAgentAuthFailure counts a refused request against the row the caller
// named, and writes agent.auth_failed_persistent once, when the run of refusals
// first reaches authFailPersistentThreshold.
//
// Each refusal was already audited as agent.auth_failed, hourly, forever; a
// device whose credential had drifted was a stream of identical records nobody
// read, and nothing on the row said so. Only an agent_id that names a row is
// counted, under the row's own tenant: a probe with an invented id writes
// nothing here. Best-effort: the 401 is the answer whatever happens below.
func (h *AgentAPIHandler) recordAgentAuthFailure(ctx context.Context, agentID string) {
	if agentID == "" || h.db == nil || h.db.Pool == nil {
		return
	}
	var orgID string
	var count int
	//orgscope:ignore keyed by the globally-unique agent_id before any tenant is resolvable, as verifyEnrolledAgent; the row's own org_id is returned and scopes the audit record
	err := h.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx), `
		UPDATE enrolled_agents
		   SET auth_failed_at = NOW(), auth_fail_count = auth_fail_count + 1
		 WHERE agent_id = $1 AND status <> $2
		RETURNING org_id::text, auth_fail_count`, agentID, agentStatusRevoked).Scan(&orgID, &count)
	if err != nil {
		return // no such agent, or a revoked one (answered 403 elsewhere)
	}
	if count != authFailPersistentThreshold {
		return
	}
	actx := ctx
	if orgID != "" {
		actx = orgctx.With(ctx, orgctx.Org{ID: orgID})
	}
	detail := "the server has refused this device's credential on consecutive requests; " +
		"it is not reporting and has no device trust until it is enrolled again"
	h.logAuditEvent("agent.auth_failed_persistent", agentID, "denied", detail)
	h.logAuditEventToDB(actx, "agent.auth_failed_persistent", agentID, "denied", detail)
}

// clearAgentAuthFailures ends a run of refusals once the agent's credential is
// accepted again. The predicate keeps it a no-op write for a healthy device.
func (h *AgentAPIHandler) clearAgentAuthFailures(ctx context.Context, agentID string) {
	if agentID == "" || h.db == nil || h.db.Pool == nil {
		return
	}
	_, _ = h.db.Pool.Exec(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore the caller just proved the credential for this globally-unique agent_id; the row is its own
		`UPDATE enrolled_agents SET auth_fail_count = 0 WHERE agent_id = $1 AND auth_fail_count <> 0`, agentID)
}

// credentialRefusedThreshold is how many refusals in a row the console needs
// before it calls a device's credential refused rather than offline. Lower
// than the audit's threshold: the console only describes the row, and a
// device refused twice running is already not reporting.
const credentialRefusedThreshold = 2

// credentialRefused reports whether a device should be shown as one whose
// credential the server refuses: a run of refusals with no accepted request
// since, on a device that is not revoked (a revoked device is shown as
// revoked).
func credentialRefused(authFailCount int, status string) bool {
	return authFailCount >= credentialRefusedThreshold && status != agentStatusRevoked
}
