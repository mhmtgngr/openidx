package governance

// Telling people about access requests (section 6.10 of the third-party access
// framework). Governance decided requests and told no one: an approver learned
// of a request by opening their queue, and a requester of a decision, or of
// their access ending, by noticing. Now:
//
//   - the approvers of the step a request is waiting at are told, when it is
//     filed and when an earlier step is satisfied (approval_pending);
//   - the requester is told when the request is approved and the access
//     granted, when it is denied, within the hour before the access ends, and
//     when it ends or the request expires unanswered (request_update);
//   - the same moments go to the tenant's webhook subscribers as
//     access_request.created, .approved, .denied, .expiring and .ended, for a
//     SIEM.
//
// Best-effort throughout: a decision stands whether or not anyone could be
// told, and a failure is logged. A notification honours its recipient's
// preference (notifications.Service). A webhook is published under the
// request's own organization and nothing else, so a sweep running across
// tenants reaches only that tenant's subscribers.

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/notifications"
	"github.com/openidx/openidx/internal/webhooks"
)

// requestFacts is what a notification and an event say about a request.
type requestFacts struct {
	ID, OrgID, RequesterID, Requester, ResourceType, ResourceID, ResourceName, Status string
	// ExpiresAt is the end of the access's window; nil for access with none.
	ExpiresAt *time.Time
}

// loadRequestFacts reads a request for telling people about it.
func (s *Service) loadRequestFacts(ctx context.Context, orgID, requestID string) (requestFacts, error) {
	f := requestFacts{ID: requestID, OrgID: orgID}
	err := s.db.Pool.QueryRow(ctx, `
		SELECT r.requester_id::text, COALESCE(NULLIF(u.email, ''), u.username, r.requester_id::text),
		       r.resource_type, r.resource_id::text, COALESCE(r.resource_name, ''), r.status, r.expires_at
		  FROM access_requests r
		  LEFT JOIN users u ON u.id = r.requester_id AND u.org_id = r.org_id
		 WHERE r.id = $1 AND r.org_id = $2`, requestID, orgID).
		Scan(&f.RequesterID, &f.Requester, &f.ResourceType, &f.ResourceID, &f.ResourceName, &f.Status, &f.ExpiresAt)
	return f, err
}

func (f requestFacts) what() string {
	if f.ResourceName != "" {
		return fmt.Sprintf("%s (%s)", f.ResourceName, f.ResourceType)
	}
	return f.ResourceType
}

func (f requestFacts) payload() map[string]interface{} {
	p := map[string]interface{}{
		"request_id": f.ID, "requester_id": f.RequesterID, "resource_type": f.ResourceType,
		"resource_id": f.ResourceID, "resource_name": f.ResourceName, "status": f.Status,
	}
	if f.ExpiresAt != nil {
		p["expires_at"] = f.ExpiresAt.UTC()
	}
	return p
}

// publishRequestEvent publishes an access-request event to the request's
// organization's webhook subscribers, and nobody else's: the context carries
// that organization and no row-level-security bypass, whatever the caller's
// context held.
func (s *Service) publishRequestEvent(f requestFacts, eventType string) {
	if s.webhooks == nil {
		return
	}
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: f.OrgID})
	if err := s.webhooks.Publish(ctx, eventType, f.payload()); err != nil {
		s.logger.Warn("publish an access request event failed", zap.String("event", eventType), zap.Error(err))
	}
}

// notifyStepApprovers tells the approvers still pending at step that a
// request is waiting for them.
func (s *Service) notifyStepApprovers(ctx context.Context, f requestFacts, step int) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT approver_id::text FROM access_request_approvals
		 WHERE request_id = $1 AND org_id = $2 AND step_order = $3 AND decision = 'pending'`,
		f.ID, f.OrgID, step)
	if err != nil {
		s.logger.Warn("notify approvers: listing them failed", zap.Error(err))
		return
	}
	var approvers []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			approvers = append(approvers, id)
		}
	}
	rows.Close()
	notif := notifications.NewService(s.db, s.logger)
	for _, approver := range approvers {
		if err := notif.CreateMultiChannelNotification(ctx, approver, f.OrgID, notifications.TypeApprovalPending,
			"An access request is waiting for your approval",
			fmt.Sprintf("%s asks for %s.", f.Requester, f.what()), "/access-requests",
			map[string]interface{}{"request_id": f.ID, "step": step}); err != nil {
			s.logger.Warn("notify an approver failed", zap.String("approver_id", approver), zap.Error(err))
		}
	}
}

// notifyRequester tells the requester what became of their request.
func (s *Service) notifyRequester(ctx context.Context, f requestFacts, title, body, kind string) {
	if err := notifications.NewService(s.db, s.logger).CreateMultiChannelNotification(ctx, f.RequesterID, f.OrgID,
		notifications.TypeRequestUpdate, title, body, "/access-requests",
		map[string]interface{}{"request_id": f.ID, "kind": kind}); err != nil {
		s.logger.Warn("notify the requester failed", zap.String("request_id", f.ID), zap.Error(err))
	}
}

// requestFiled tells the first step's approvers about a new request and
// publishes access_request.created. A request that was auto-approved is told
// as approved instead.
func (s *Service) requestFiled(ctx context.Context, orgID, requestID string) {
	f, err := s.loadRequestFacts(ctx, orgID, requestID)
	if err != nil {
		s.logger.Warn("a filed request could not be read back to tell anyone", zap.Error(err))
		return
	}
	s.publishRequestEvent(f, webhooks.EventAccessRequestCreated)
	switch f.Status {
	case "pending":
		_, active, _, err := s.approvalProgress(ctx, requestID, orgID)
		if err == nil && active > 0 {
			s.notifyStepApprovers(ctx, f, active)
		}
	case "fulfilled":
		s.requestGranted(ctx, f)
	}
}

// requestAdvanced tells the approvers of the step a request moved on to.
func (s *Service) requestAdvanced(ctx context.Context, orgID, requestID string, step int) {
	f, err := s.loadRequestFacts(ctx, orgID, requestID)
	if err != nil {
		s.logger.Warn("an advanced request could not be read back to tell anyone", zap.Error(err))
		return
	}
	s.notifyStepApprovers(ctx, f, step)
}

// requestGranted tells the requester the access is theirs and publishes
// access_request.approved.
func (s *Service) requestGranted(ctx context.Context, f requestFacts) {
	s.notifyRequester(ctx, f, "Your access request was approved",
		fmt.Sprintf("You now have %s.", f.what()), "approved")
	s.publishRequestEvent(f, webhooks.EventAccessRequestApproved)
}

// requestApproved is requestGranted for a request known by id.
func (s *Service) requestApproved(ctx context.Context, orgID, requestID string) {
	f, err := s.loadRequestFacts(ctx, orgID, requestID)
	if err != nil {
		s.logger.Warn("an approved request could not be read back to tell anyone", zap.Error(err))
		return
	}
	s.requestGranted(ctx, f)
}

// requestDenied tells the requester and publishes access_request.denied.
func (s *Service) requestDenied(ctx context.Context, orgID, requestID string) {
	f, err := s.loadRequestFacts(ctx, orgID, requestID)
	if err != nil {
		s.logger.Warn("a denied request could not be read back to tell anyone", zap.Error(err))
		return
	}
	s.notifyRequester(ctx, f, "Your access request was denied",
		fmt.Sprintf("Your request for %s was denied.", f.what()), "denied")
	s.publishRequestEvent(f, webhooks.EventAccessRequestDenied)
}

// requestEnded tells the requester their access ended, or their request
// expired unanswered, and publishes access_request.ended.
func (s *Service) requestEnded(ctx context.Context, orgID, requestID, why string) {
	f, err := s.loadRequestFacts(ctx, orgID, requestID)
	if err != nil {
		s.logger.Warn("an ended request could not be read back to tell anyone", zap.Error(err))
		return
	}
	title, body := "Your access ended", fmt.Sprintf("Your access to %s ended with its window.", f.what())
	if why == "unanswered" {
		title, body = "Your access request expired", fmt.Sprintf("Nobody answered your request for %s in time.", f.what())
	}
	s.notifyRequester(ctx, f, title, body, why)
	s.publishRequestEvent(f, webhooks.EventAccessRequestEnded)
}

// warnEndingAccess warns each requester whose access ends within the hour,
// once: access_request.expiring goes to the tenant's webhook subscribers, and
// the requester is notified unless they switched those notifications off. The
// request is claimed first, by stamping expiry_warned_at in the statement that
// selects it, so a warning goes out once whatever happens after.
func (s *Service) warnEndingAccess(ctx context.Context) {
	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore install-wide sweep over every tenant's fulfilled requests; each row's own org_id scopes what follows
		`UPDATE access_requests SET expiry_warned_at = NOW()
		  WHERE status = 'fulfilled' AND expires_at IS NOT NULL AND expiry_warned_at IS NULL
		    AND expires_at > NOW() AND expires_at <= NOW() + INTERVAL '1 hour'
		  RETURNING id::text, org_id::text`)
	if err != nil {
		s.logger.Warn("expiry warning sweep: could not claim the requests to warn", zap.Error(err))
		return
	}
	type ending struct{ id, org string }
	var due []ending
	for rows.Next() {
		var e ending
		if err := rows.Scan(&e.id, &e.org); err != nil {
			s.logger.Warn("expiry warning sweep: scan failed", zap.Error(err))
			continue
		}
		due = append(due, e)
	}
	rows.Close()
	for _, e := range due {
		f, err := s.loadRequestFacts(ctx, e.org, e.id)
		if err != nil || f.ExpiresAt == nil {
			s.logger.Warn("an ending request could not be read back to warn anyone", zap.Error(err))
			continue
		}
		s.notifyRequester(ctx, f, "Your access ends soon",
			fmt.Sprintf("Your access to %s ends at %s UTC.", f.what(), f.ExpiresAt.UTC().Format("15:04")), "expiring")
		s.publishRequestEvent(f, webhooks.EventAccessRequestExpiring)
	}
}
