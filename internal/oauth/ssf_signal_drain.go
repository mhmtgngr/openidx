package oauth

import (
	"context"
	"encoding/json"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/ssfsignal"
)

// THE DRAINER: the half of ssfsignal that holds the key.
//
// A severing path in another binary wrote a row to ssf_pending_events
// (migration v196, internal/common/ssfsignal). This turns each row into signed
// SETs on every stream in that tenant that asked for the event, through the
// same EmitCAEPEvent the in-process callers use, and the existing push worker
// delivers them. It is the SSF push worker's shape -- ticker, claim with UPDATE
// ... RETURNING under SKIP LOCKED, no leader -- because the argument for that
// shape is the same: the row lock IS the coordination, any number of replicas
// drain safely, and a leader would add an availability gap for an ordering
// guarantee nobody asked for.
//
// AT-LEAST-ONCE, and the direction is stated. The row is marked published
// after EmitCAEPEvent returns; a crash between the two re-drains the row and
// enqueues the SET again. A receiver may therefore see one event twice, and
// RFC 8935 receivers are required to treat a repeated jti as already handled.
// The other direction -- marking first and then failing to emit -- would lose a
// security signal silently, which is the failure this whole item exists to
// remove.

const (
	ssfSignalBatch      = 50
	ssfSignalMaxAttempt = 10
	ssfSignalStaleAfter = 5 * time.Minute
)

// StartSSFSignalDrainer starts the background drain. It runs under bypass-RLS
// the way StartSSFPushWorker does: one worker serves every tenant, and each
// claimed row carries its own org_id onward into EmitCAEPEvent's fan-out.
func (s *Service) StartSSFSignalDrainer(ctx context.Context) {
	go s.runSSFSignalDrain(orgctx.WithBypassRLS(ctx))
	s.logger.Info("SSF signal drainer starting")
}

func (s *Service) runSSFSignalDrain(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				n, err := s.drainSSFSignals(ctx)
				if err != nil {
					s.logger.Warn("SSF signal drain failed; the rows stay pending and are retried", zap.Error(err))
					break
				}
				if n == 0 {
					break
				}
			}
		}
	}
}

type ssfPendingSignal struct {
	id           int64
	orgID        string
	eventType    string
	subjectID    string
	subjectEmail string
	claims       []byte
}

// drainSSFSignals claims one batch, emits each, and marks each published.
// It returns how many rows it claimed, so the caller keeps draining while the
// backlog is deep and sleeps when it is not.
func (s *Service) drainSSFSignals(ctx context.Context) (int, error) {
	// A drainer that died mid-batch left rows claimed and unpublished. After
	// the grace they are anybody's again; attempts already counted the try.
	if _, err := s.db.Pool.Exec(ctx, `
		--orgscope:ignore install-wide drain: rows are handed back by state alone, never by org
		UPDATE ssf_pending_events SET claimed_at = NULL
		 WHERE published_at IS NULL AND claimed_at IS NOT NULL AND claimed_at < NOW() - $1::interval`,
		ssfSignalStaleAfter.String()); err != nil {
		return 0, err
	}

	rows, err := s.db.Pool.Query(ctx, `
		--orgscope:ignore install-wide drain: one worker serves every tenant, claims by state alone, and each claimed row carries its own org_id onward
		UPDATE ssf_pending_events p SET claimed_at = NOW(), attempts = attempts + 1
		 WHERE p.id IN (
		     SELECT id FROM ssf_pending_events
		      WHERE published_at IS NULL AND claimed_at IS NULL AND attempts < $2
		      ORDER BY id ASC LIMIT $1 FOR UPDATE SKIP LOCKED)
		RETURNING p.id, p.org_id::text, p.event_type, p.subject_id, p.subject_email, p.claims`,
		ssfSignalBatch, ssfSignalMaxAttempt)
	if err != nil {
		return 0, err
	}
	var batch []ssfPendingSignal
	for rows.Next() {
		var p ssfPendingSignal
		if err := rows.Scan(&p.id, &p.orgID, &p.eventType, &p.subjectID, &p.subjectEmail, &p.claims); err != nil {
			rows.Close()
			return 0, err
		}
		batch = append(batch, p)
	}
	rows.Close()

	for _, p := range batch {
		var claims map[string]interface{}
		if len(p.claims) > 0 {
			if err := json.Unmarshal(p.claims, &claims); err != nil {
				s.logger.Warn("SSF signal carries unreadable claims; emitting without them",
					zap.Int64("id", p.id), zap.Error(err))
				claims = nil
			}
		}
		// THE DRAINER EMITS ONLY WHAT IT KNOWS. The row's event_type is a string
		// a producer wrote; resolving it through this switch to the package's
		// own constant means a poisoned or mistyped row cannot make the issuer
		// sign a SET for an event URI nobody advertised. It is also what lets
		// the advertised-events census see this path: that census reads the
		// constant passed to EmitCAEPEvent, and a variable would be invisible.
		var n int
		switch p.eventType {
		case ssfsignal.AccountDisabled:
			n = s.EmitCAEPEvent(ctx, p.orgID, EventAccountDisabled, p.subjectEmail, p.subjectID, claims)
		default:
			s.logger.Warn("SSF signal names an event type this drainer does not emit; marking it published with zero streams",
				zap.Int64("id", p.id), zap.String("event_type", p.eventType))
		}
		if _, err := s.db.Pool.Exec(ctx, `
			--orgscope:ignore marking a row this drain already claimed above, addressed by its own id
			UPDATE ssf_pending_events SET published_at = NOW(), streams_enqueued = $2 WHERE id = $1`,
			p.id, n); err != nil {
			// The SETs are enqueued; the row will be re-drained and they will be
			// enqueued again. That is the at-least-once direction, chosen above.
			s.logger.Warn("SSF signal emitted but not marked published; it will be emitted again",
				zap.Int64("id", p.id), zap.Error(err))
		}
	}
	return len(batch), nil
}
