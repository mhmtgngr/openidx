package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/scimclient"
	"go.uber.org/zap"
)

// This file implements the outbound-SCIM WORKER: a background loop that drains
// the scim_provisioning_queue outbox and applies each operation to its target
// via internal/scimclient, with at-least-once delivery, exponential backoff,
// and dead-lettering. It mirrors the SIEM-forwarder outbox pattern already in
// the tree (poll -> claim -> deliver -> advance/retry).

// userSnapshot is the local user shape enqueued into the outbox payload. It is
// the minimal set of fields needed to build a SCIM User; the identity layer
// fills it at enqueue time so a later local delete cannot race the worker.
type userSnapshot struct {
	ID             string `json:"id"`
	UserName       string `json:"user_name"`
	Email          string `json:"email"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
	DisplayName    string `json:"display_name"`
	Active         bool   `json:"active"`
	Department     string `json:"department"`
	EmployeeNumber string `json:"employee_number"`
}

// groupSnapshot is the local group shape enqueued into the outbox payload.
type groupSnapshot struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	MemberIDs   []string `json:"member_ids"`
}

// OutboundWorkerConfig tunes the worker loop.
type OutboundWorkerConfig struct {
	PollInterval time.Duration
	BatchSize    int
}

func outboundWorkerConfigDefaults() OutboundWorkerConfig {
	return OutboundWorkerConfig{PollInterval: 10 * time.Second, BatchSize: 50}
}

// StartOutboundWorker launches the outbound-SCIM provisioning worker. It is a
// no-op-safe background goroutine: with no configured targets the queue is
// empty and it simply idles. Bypasses RLS so it can drain items across orgs.
func (s *Service) StartOutboundWorker(ctx context.Context) {
	cfg := outboundWorkerConfigDefaults()
	w := &outboundWorker{svc: s, cfg: cfg, logger: s.logger.With(zap.String("component", "scim-out-worker"))}
	w.logger.Info("outbound SCIM worker starting",
		zap.Duration("poll", cfg.PollInterval), zap.Int("batch", cfg.BatchSize))
	go w.run(orgctx.WithBypassRLS(ctx))
}

type outboundWorker struct {
	svc    *Service
	cfg    OutboundWorkerConfig
	logger *zap.Logger
}

func (w *outboundWorker) run(ctx context.Context) {
	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				n, err := w.drainBatch(ctx)
				if err != nil {
					w.logger.Warn("outbound SCIM drain failed; will retry", zap.Error(err))
					break
				}
				if n == 0 {
					break // queue empty; wait for next tick
				}
			}
		}
	}
}

// claimedItem is one outbox row the worker is processing.
type claimedItem struct {
	id           int64
	targetID     string
	orgID        string
	resourceType string
	localID      string
	operation    string
	payload      []byte
	attempts     int
}

// drainBatch claims up to BatchSize ready items (atomically, skipping locked
// rows so multiple workers/replicas don't collide) and processes each.
func (w *outboundWorker) drainBatch(ctx context.Context) (int, error) {
	rows, err := w.svc.db.Pool.Query(ctx, `
        UPDATE scim_provisioning_queue q
           SET state = 'processing', updated_at = NOW()
         WHERE q.id IN (
             SELECT id FROM scim_provisioning_queue
              WHERE state = 'pending' AND next_attempt_at <= NOW()
              ORDER BY id ASC
              LIMIT $1
              FOR UPDATE SKIP LOCKED
         )
        RETURNING q.id, q.target_id, COALESCE(q.org_id::text,''),
                  q.resource_type, q.local_id::text, q.operation, q.payload, q.attempts`,
		w.cfg.BatchSize)
	if err != nil {
		return 0, fmt.Errorf("claim batch: %w", err)
	}
	var items []claimedItem
	for rows.Next() {
		var it claimedItem
		if err := rows.Scan(&it.id, &it.targetID, &it.orgID, &it.resourceType,
			&it.localID, &it.operation, &it.payload, &it.attempts); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan claimed item: %w", err)
		}
		items = append(items, it)
	}
	rows.Close()

	for _, it := range items {
		w.processItem(ctx, it)
	}
	return len(items), nil
}

// processItem applies one operation and updates queue + record state. Errors
// are recorded and retried with backoff until maxQueueAttempts, then the item
// is dead-lettered.
func (w *outboundWorker) processItem(ctx context.Context, it claimedItem) {
	err := w.apply(ctx, it)
	if err == nil {
		_, _ = w.svc.db.Pool.Exec(ctx,
			`UPDATE scim_provisioning_queue SET state='done', updated_at=NOW() WHERE id=$1`, it.id)
		return
	}

	attempts := it.attempts + 1
	// Terminal client errors (bad request / unprocessable) won't succeed on
	// retry, so dead-letter immediately rather than burning the backoff budget.
	terminal := isTerminalSCIMError(err)
	if terminal || attempts >= maxQueueAttempts {
		state := QueueDead
		w.logger.Warn("outbound SCIM op dead-lettered",
			zap.String("target", it.targetID), zap.String("op", it.operation),
			zap.String("resource", it.resourceType), zap.String("local_id", it.localID),
			zap.Int("attempts", attempts), zap.Bool("terminal", terminal), zap.Error(err))
		_, _ = w.svc.db.Pool.Exec(ctx,
			`UPDATE scim_provisioning_queue SET state=$2, attempts=$3, last_error=$4, updated_at=NOW() WHERE id=$1`,
			it.id, state, attempts, err.Error())
		w.markRecordError(ctx, it, err)
		return
	}

	// Exponential backoff: 2^attempts seconds, capped at 1h.
	backoff := time.Duration(1<<uint(attempts)) * time.Second
	if backoff > time.Hour {
		backoff = time.Hour
	}
	_, _ = w.svc.db.Pool.Exec(ctx, `
        UPDATE scim_provisioning_queue
           SET state='pending', attempts=$2, last_error=$3,
               next_attempt_at = NOW() + $4::interval, updated_at=NOW()
         WHERE id=$1`,
		it.id, attempts, err.Error(), fmt.Sprintf("%d seconds", int(backoff.Seconds())))
}

// apply performs the actual SCIM call for one item.
func (w *outboundWorker) apply(ctx context.Context, it claimedItem) error {
	client, deprovisionAction, err := w.clientFor(ctx, it.targetID)
	if err != nil {
		return err
	}

	switch it.resourceType {
	case "user":
		return w.applyUser(ctx, client, deprovisionAction, it)
	case "group":
		return w.applyGroup(ctx, client, it)
	default:
		return fmt.Errorf("unknown resource type %q", it.resourceType)
	}
}

func (w *outboundWorker) applyUser(ctx context.Context, client *scimclient.Client, deprovisionAction string, it claimedItem) error {
	var snap userSnapshot
	if err := json.Unmarshal(it.payload, &snap); err != nil {
		return terminalError{fmt.Errorf("bad user payload: %w", err)}
	}
	rec, err := w.loadRecord(ctx, it.targetID, "user", it.localID)
	if err != nil {
		return err
	}

	switch it.operation {
	case OpCreate, OpUpdate, OpActivate:
		scimUser := buildSCIMUser(snap)
		scimUser.Active = it.operation != OpDeactivate
		hash := payloadHash(scimUser)

		if rec != nil && rec.remoteID != "" {
			// Skip a no-op update.
			if it.operation == OpUpdate && rec.lastHash == hash {
				return nil
			}
			if _, err := client.ReplaceUser(ctx, rec.remoteID, scimUser); err != nil {
				if scimclient.IsNotFound(err) {
					// Remote resource vanished; recreate.
					return w.createUser(ctx, client, it, scimUser, hash)
				}
				return err
			}
			return w.upsertRecord(ctx, it, rec.remoteID, RecordActive, hash)
		}
		return w.createUser(ctx, client, it, scimUser, hash)

	case OpDeactivate:
		if rec == nil || rec.remoteID == "" {
			return nil // nothing provisioned; nothing to deprovision
		}
		if deprovisionAction == "delete" {
			if err := client.DeleteUser(ctx, rec.remoteID); err != nil {
				return err
			}
		} else {
			if err := client.SetUserActive(ctx, rec.remoteID, false); err != nil {
				if scimclient.IsNotFound(err) {
					return w.upsertRecord(ctx, it, rec.remoteID, RecordDeprovisioned, rec.lastHash)
				}
				return err
			}
		}
		return w.upsertRecord(ctx, it, rec.remoteID, RecordDeprovisioned, rec.lastHash)

	case OpDelete:
		if rec == nil || rec.remoteID == "" {
			return nil
		}
		if err := client.DeleteUser(ctx, rec.remoteID); err != nil {
			return err
		}
		return w.upsertRecord(ctx, it, rec.remoteID, RecordDeprovisioned, rec.lastHash)

	default:
		return terminalError{fmt.Errorf("unknown user operation %q", it.operation)}
	}
}

func (w *outboundWorker) createUser(ctx context.Context, client *scimclient.Client, it claimedItem, scimUser *scimclient.User, hash string) error {
	created, err := client.CreateUser(ctx, scimUser)
	if err != nil {
		return err
	}
	return w.upsertRecord(ctx, it, created.ID, RecordActive, hash)
}

func (w *outboundWorker) applyGroup(ctx context.Context, client *scimclient.Client, it claimedItem) error {
	var snap groupSnapshot
	if err := json.Unmarshal(it.payload, &snap); err != nil {
		return terminalError{fmt.Errorf("bad group payload: %w", err)}
	}
	rec, err := w.loadRecord(ctx, it.targetID, "group", it.localID)
	if err != nil {
		return err
	}
	scimGroup := &scimclient.Group{DisplayName: snap.DisplayName, ExternalID: snap.ID}
	hash := payloadHash(scimGroup)

	switch it.operation {
	case OpCreate, OpUpdate:
		if rec != nil && rec.remoteID != "" {
			if it.operation == OpUpdate && rec.lastHash == hash {
				return nil
			}
			if _, err := client.ReplaceGroup(ctx, rec.remoteID, scimGroup); err != nil {
				if scimclient.IsNotFound(err) {
					created, cerr := client.CreateGroup(ctx, scimGroup)
					if cerr != nil {
						return cerr
					}
					return w.upsertRecord(ctx, it, created.ID, RecordActive, hash)
				}
				return err
			}
			return w.upsertRecord(ctx, it, rec.remoteID, RecordActive, hash)
		}
		created, err := client.CreateGroup(ctx, scimGroup)
		if err != nil {
			return err
		}
		return w.upsertRecord(ctx, it, created.ID, RecordActive, hash)

	case OpDelete, OpDeactivate:
		if rec == nil || rec.remoteID == "" {
			return nil
		}
		if err := client.DeleteGroup(ctx, rec.remoteID); err != nil {
			return err
		}
		return w.upsertRecord(ctx, it, rec.remoteID, RecordDeprovisioned, rec.lastHash)

	default:
		return terminalError{fmt.Errorf("unknown group operation %q", it.operation)}
	}
}

// provRecord is the in-memory view of a scim_provisioning_records row.
type provRecord struct {
	remoteID string
	status   string
	lastHash string
}

func (w *outboundWorker) loadRecord(ctx context.Context, targetID, resourceType, localID string) (*provRecord, error) {
	var r provRecord
	var remote, hash *string
	err := w.svc.db.Pool.QueryRow(ctx, `
        SELECT COALESCE(remote_id,''), status, last_payload_hash
          FROM scim_provisioning_records
         WHERE target_id=$1 AND resource_type=$2 AND local_id=$3`,
		targetID, resourceType, localID).Scan(&remote, &r.status, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // no record yet
	}
	if err != nil {
		return nil, fmt.Errorf("load record: %w", err)
	}
	if remote != nil {
		r.remoteID = *remote
	}
	if hash != nil {
		r.lastHash = *hash
	}
	return &r, nil
}

func (w *outboundWorker) upsertRecord(ctx context.Context, it claimedItem, remoteID, status, hash string) error {
	_, err := w.svc.db.Pool.Exec(ctx, `
        INSERT INTO scim_provisioning_records
            (org_id, target_id, resource_type, local_id, remote_id, status, last_payload_hash)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (target_id, resource_type, local_id)
        DO UPDATE SET remote_id=EXCLUDED.remote_id, status=EXCLUDED.status,
                      last_payload_hash=EXCLUDED.last_payload_hash,
                      last_error=NULL, updated_at=NOW()`,
		nullIfEmpty(it.orgID), it.targetID, it.resourceType, it.localID,
		nullIfEmpty(remoteID), status, nullIfEmpty(hash))
	if err != nil {
		return fmt.Errorf("upsert record: %w", err)
	}
	return nil
}

func (w *outboundWorker) markRecordError(ctx context.Context, it claimedItem, cause error) {
	_, _ = w.svc.db.Pool.Exec(ctx, `
        INSERT INTO scim_provisioning_records
            (org_id, target_id, resource_type, local_id, status, last_error)
        VALUES ($1,$2,$3,$4,'error',$5)
        ON CONFLICT (target_id, resource_type, local_id)
        DO UPDATE SET status='error', last_error=EXCLUDED.last_error, updated_at=NOW()`,
		nullIfEmpty(it.orgID), it.targetID, it.resourceType, it.localID, cause.Error())
}

// clientFor builds a scimclient for a target, resolving its bearer token.
func (w *outboundWorker) clientFor(ctx context.Context, targetID string) (*scimclient.Client, string, error) {
	var baseURL, authType, deprovisionAction string
	if err := w.svc.db.Pool.QueryRow(ctx,
		`SELECT base_url, auth_type, deprovision_action FROM scim_target_apps WHERE id=$1`, targetID).
		Scan(&baseURL, &authType, &deprovisionAction); err != nil {
		return nil, "", fmt.Errorf("load target %s: %w", targetID, err)
	}
	token, err := w.svc.bearerTokenFor(ctx, targetID)
	if err != nil {
		return nil, "", fmt.Errorf("resolve token for target %s: %w", targetID, err)
	}
	client, err := scimclient.New(scimclient.Config{BaseURL: baseURL, Bearer: token})
	if err != nil {
		return nil, "", err
	}
	return client, deprovisionAction, nil
}

// buildSCIMUser maps a local user snapshot to a SCIM 2.0 User resource.
func buildSCIMUser(snap userSnapshot) *scimclient.User {
	u := &scimclient.User{
		Schemas:     []string{scimclient.SchemaUser},
		ExternalID:  snap.ID,
		UserName:    snap.UserName,
		DisplayName: snap.DisplayName,
		Active:      snap.Active,
	}
	if snap.FirstName != "" || snap.LastName != "" {
		u.Name = &scimclient.Name{
			GivenName:  snap.FirstName,
			FamilyName: snap.LastName,
			Formatted:  joinName(snap.FirstName, snap.LastName),
		}
	}
	if u.DisplayName == "" {
		u.DisplayName = joinName(snap.FirstName, snap.LastName)
	}
	if snap.Email != "" {
		u.Emails = []scimclient.Email{{Value: snap.Email, Primary: true, Type: "work"}}
	}
	if snap.Department != "" || snap.EmployeeNumber != "" {
		u.Enterprise = &scimclient.EnterpriseUser{
			Department:     snap.Department,
			EmployeeNumber: snap.EmployeeNumber,
		}
	}
	return u
}

func joinName(first, last string) string {
	switch {
	case first != "" && last != "":
		return first + " " + last
	case first != "":
		return first
	default:
		return last
	}
}

// terminalError marks a non-retryable failure (bad payload / unprocessable);
// the worker dead-letters it immediately.
type terminalError struct{ err error }

func (e terminalError) Error() string { return e.err.Error() }
func (e terminalError) Unwrap() error { return e.err }

// isTerminalSCIMError reports whether err should skip retries. Explicit
// terminalError wrappers and SCIM 4xx client errors (except 429) are terminal.
func isTerminalSCIMError(err error) bool {
	var te terminalError
	if errors.As(err, &te) {
		return true
	}
	var ae *scimclient.APIError
	if errors.As(err, &ae) {
		// 400/409/422 are payload problems that won't self-heal; 401/403 are
		// auth problems the operator must fix; retrying floods the target. 404
		// is handled as success upstream. 429/5xx are transient -> retry.
		switch ae.StatusCode {
		case 400, 401, 403, 409, 422:
			return true
		}
	}
	return false
}
