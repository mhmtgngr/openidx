package identity

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/webhooks"
)

// This file is what survived handler.go.
//
// handler.go held a complete second user-and-group CRUD surface -- fourteen
// exported Handle* methods -- that no router had ever mounted. service.go's
// lowercase handlers serve those paths and always have. tools/routereach found
// it, and the file is gone.
//
// What it cost was not the dead lines. handler.go was the ONLY caller of the
// two emitters below, so six of the event types the webhook subscription form
// offers had never been published by any install: user.updated, group.created,
// group.updated, group.deleted, group.member_added and group.member_removed.
// An operator wiring an integration to "somebody left this group" got a
// subscription, a delivery log that stayed empty, and no way to tell that from
// a quiet week. The emitters now run from the handlers that are actually
// mounted.

// getActorID extracts the actor ID from the Gin context.
func getActorID(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return "system"
}

// auditCtx is the request context a service call should run under: it carries
// the acting user and the client IP so audit_events records who did it and
// from where.
//
// Handlers that pass c.Request.Context() straight through still work, but every
// event they produce is attributed to "system" with no IP — which is to say the
// row exists and answers nothing. Prefer this at any call site that mutates
// identities, credentials, group membership, roles or federation.
func auditCtx(c *gin.Context) context.Context {
	return ContextWithActor(c.Request.Context(), getActorID(c), c.ClientIP())
}

// publishCtx returns a context detached from the request lifecycle (so a client
// disconnect can't cancel the webhook write) that still carries the request's
// org. Webhook subscriptions are RLS-scoped, so without the org the publish
// would see zero subscriptions and silently emit nothing for the tenant.
func publishCtx(ctx context.Context) context.Context {
	return orgctx.Detached(ctx)
}

// emitUserLifecycleEvent publishes a user event to the tenant's webhook
// subscriptions. ctx must be the request context so the publish is scoped to
// the acting tenant (see publishCtx). eventType comes from
// webhooks.EventCatalogue, which catalogue_test.go holds against every Publish
// call in the tree.
func (s *Service) emitUserLifecycleEvent(ctx context.Context, eventType, userID, actorID string) {
	if s.webhookService == nil {
		return
	}
	s.webhookService.Publish(publishCtx(ctx), eventType, map[string]interface{}{
		"user_id":  userID,
		"actor_id": actorID,
	})
}

// emitGroupLifecycleEvent publishes a group event. Membership changes carry the
// member as well: a downstream system granting or revoking access on a
// group.member_added needs to know who joined, not only which group changed.
func (s *Service) emitGroupLifecycleEvent(ctx context.Context, eventType, groupID, actorID string, member ...string) {
	if s.webhookService == nil {
		return
	}
	payload := map[string]interface{}{
		"group_id": groupID,
		"actor_id": actorID,
	}
	if len(member) > 0 && member[0] != "" {
		payload["user_id"] = member[0]
	}
	s.webhookService.Publish(publishCtx(ctx), eventType, payload)
}

// emitRoleLifecycleEvent publishes a role event. role.updated was declared as a
// webhook type and never sent by anything; the audit trail recorded a
// "role.updated" event of its own, which is not the same thing and is not
// delivered anywhere.
func (s *Service) emitRoleLifecycleEvent(ctx context.Context, eventType, roleID, actorID string) {
	if s.webhookService == nil {
		return
	}
	s.webhookService.Publish(publishCtx(ctx), eventType, map[string]interface{}{
		"role_id":  roleID,
		"actor_id": actorID,
	})
}

// emitAccountLocked announces a lockout. Compile-time reference to the
// catalogue constant keeps the name in one place.
func (s *Service) emitAccountLocked(ctx context.Context, userID string, failures int) {
	if s.webhookService == nil {
		return
	}
	s.webhookService.Publish(publishCtx(ctx), webhooks.EventUserLocked, map[string]interface{}{
		"user_id":        userID,
		"failed_logins":  failures,
		"locked_by":      "lockout_policy",
		"actor_id":       "system",
		"lockout_reason": "consecutive failed sign-ins reached the configured threshold",
	})
}
