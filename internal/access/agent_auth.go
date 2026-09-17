package access

import (
	"context"
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

// verifyEnrolledAgent reports whether token is the credential enrollment issued
// for agentID, by comparing its SHA-256 against enrolled_agents.auth_token_hash,
// and returns the tenant the agent belongs to.
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
func verifyEnrolledAgent(ctx context.Context, db *database.PostgresDB, agentID, token string) (orgID string, ok bool) {
	if agentID == "" || token == "" {
		return "", false
	}
	if db == nil || db.Pool == nil {
		return "", true // dev mode: any non-empty token, as the other agent surfaces do
	}
	var stored string
	//orgscope:ignore agent credential check: keyed by the globally-unique agent_id before any tenant is resolvable; the row's own org_id is what scopes everything after
	if err := db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		`SELECT auth_token_hash, org_id::text FROM enrolled_agents WHERE agent_id = $1`,
		agentID).Scan(&stored, &orgID); err != nil {
		return "", false
	}
	if stored == "" || sha256Hex(token) != stored {
		return "", false
	}
	return orgID, true
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
// On failure it answers 401 and returns ok=false; the caller must return. The
// refusal is audited with the id that was claimed, because a report arriving
// for an agent id with the wrong credential is the shape of someone probing the
// fleet, and the endpoint is public.
//
// The tenant on the context is what makes every fleet query after this point
// tenant-scoped under the v197 belt without a bypass: the agent proved it
// holds the credential for a row, and that row names its tenant.
func (h *AgentAPIHandler) requireEnrolledAgent(c *gin.Context) (string, bool) {
	agentID, token := agentCredentials(c)
	orgID, ok := verifyEnrolledAgent(c.Request.Context(), h.db, agentID, token)
	if !ok {
		h.logAuditEvent("agent.auth_failed", agentID, "denied", "invalid agent credentials")
		h.logAuditEventToDB(c.Request.Context(), "agent.auth_failed", agentID, "denied",
			"invalid agent credentials")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid agent credentials"})
		return "", false
	}
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
