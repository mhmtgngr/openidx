package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/pamgrant"
)

// A PAM entry connection is a governance request type, resource_type
// 'pam_entry' (section 6.9 of the third-party access framework, decision D3).
// The request goes through the same approval policies, steps and audit as a
// role or a group; fulfilling it writes a 'connect' grant on the entry that
// ends with the request's window (migration v216 gives the grant its request
// id). The entry's own launch approval, where the entry asks for one, stays a
// separate decision taken at connect: this grant says the user may reach the
// entry in this window, the launch approval says someone knows they are
// connecting now.
//
// Who may ask is who already sees the entry: a standing grant of any action on
// it, held directly, through a role or through a group. That is the
// eligibility the PAM entry list shows (section 6.1: what is permanent is
// eligibility, not privilege), and it keeps an entry nobody showed the
// requester from being probed by id.

// pamEntryRefusal is a pam_entry request the API turns down, with its status
// and stable code.
type pamEntryRefusal struct {
	status int
	code   string
	msg    string
}

var (
	refusePamEntryNotFound = &pamEntryRefusal{http.StatusNotFound, "pam_entry_not_found",
		"PAM entry not found"}
	refusePamEntryHeld = &pamEntryRefusal{http.StatusConflict, "pam_entry_already_granted",
		"you can already connect to this PAM entry"}
	refusePamEntryDuration = &pamEntryRefusal{http.StatusBadRequest, "pam_entry_duration_required",
		"a PAM entry request needs a duration: the connect grant it writes ends with it"}
)

// callerRoles are the role names the caller's token carries, which is what a
// role-principal PAM grant names.
func callerRoles(c *gin.Context) []string {
	if raw, ok := c.Get("roles"); ok {
		if roles, ok := raw.([]string); ok {
			return roles
		}
	}
	return nil
}

// checkPamEntryRequest validates a pam_entry request and returns the entry's
// name, which goes on the request in place of whatever the requester typed:
// an approver reads what the requester will reach. An entry that does not
// exist and one the requester cannot see answer the same 404.
func (s *Service) checkPamEntryRequest(ctx context.Context, orgID, userID string, roles []string, entryID, duration string) (string, *pamEntryRefusal, error) {
	if _, err := uuid.Parse(entryID); err != nil {
		return "", refusePamEntryNotFound, nil
	}
	var name string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT name FROM pam_entries WHERE id = $1 AND org_id = $2`, entryID, orgID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", refusePamEntryNotFound, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("read the PAM entry: %w", err)
	}
	visible, err := pamgrant.Holds(ctx, s.db.Pool, orgID, entryID, userID, roles, "")
	if err != nil {
		return "", nil, fmt.Errorf("check the requester's grants on the entry: %w", err)
	}
	if !visible {
		return "", refusePamEntryNotFound, nil
	}
	connectable, err := pamgrant.Holds(ctx, s.db.Pool, orgID, entryID, userID, roles, "connect")
	if err != nil {
		return "", nil, fmt.Errorf("check the requester's grants on the entry: %w", err)
	}
	if connectable {
		return "", refusePamEntryHeld, nil
	}
	if duration == "" {
		return "", refusePamEntryDuration, nil
	}
	return name, nil, nil
}

// grantPamEntryConnect writes the connect grant a fulfilled pam_entry request
// gives: the requester, the entry, until the request's window ends, carrying
// the request's id. A retried fulfilment writes nothing twice
// (pam_entry_grants_request_key). For an external user the v215 trigger cuts
// the end to the account's.
func (s *Service) grantPamEntryConnect(ctx context.Context, orgID string, request *AccessRequest) error {
	if request.ExpiresAt == nil {
		return fmt.Errorf("pam_entry request %s has no expires_at (an unbounded connect grant)", request.ID)
	}
	tag, err := s.db.Pool.Exec(ctx, `
		INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions, expires_at, request_id)
		SELECT $1, e.id, 'user', $3, ARRAY['connect'], $4, $5::uuid
		  FROM pam_entries e WHERE e.id = $2::uuid AND e.org_id = $1
		ON CONFLICT (request_id) WHERE request_id IS NOT NULL DO NOTHING`,
		orgID, request.ResourceID, request.RequesterID, request.ExpiresAt, request.ID)
	if err != nil {
		return fmt.Errorf("grant connect on PAM entry for request %s: %w", request.ID, err)
	}
	if tag.RowsAffected() == 0 {
		var granted bool
		if err := s.db.Pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM pam_entry_grants WHERE request_id = $1::uuid AND org_id = $2)`,
			request.ID, orgID).Scan(&granted); err != nil {
			return fmt.Errorf("read the grant of request %s: %w", request.ID, err)
		}
		if !granted {
			return fmt.Errorf("the PAM entry of request %s no longer exists", request.ID)
		}
		return nil
	}
	details, _ := json.Marshal(map[string]any{
		"request_id": request.ID, "entry_id": request.ResourceID, "actions": []string{"connect"},
		"expires_at": request.ExpiresAt,
	})
	if _, err := s.db.Pool.Exec(ctx,
		`INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, actor_ip, target_id, target_type, details, created_at, org_id)
		 VALUES (gen_random_uuid(), 'access', 'provisioning', 'pam.grant_created', 'success', $1, '0.0.0.0', $2, 'pam_entry', $3, NOW(), $4)`,
		request.RequesterID, request.ResourceID, string(details), orgID); err != nil {
		s.logger.Warn("Failed to write pam.grant_created audit event",
			logsafe.String("request_id", request.ID), zap.Error(err))
	}
	return nil
}
