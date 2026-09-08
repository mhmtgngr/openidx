package audit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The tamper-evident audit log, made real.
//
// internal/audit/logger.go has carried the primitives since the beginning --
// HMAC-SHA256 over a canonical form, a previous-hash link, a chain walk that
// names the first break -- and nothing has ever called them. There was nowhere
// to store a hash until migration v181, and no code to produce one. Four
// published claims (the docs index, the architecture page, the audit reference
// page and the README's readiness checklist) rested on that.
//
// WHY A SEALER AND NOT A HASH ON INSERT. A hash chain has to be built in one
// serialized order per chain. Sixteen different statements across this tree
// INSERT into audit_events, several of them inside request transactions that
// are already holding row locks, and giving each of them a per-org lock would
// put a serialization point in the middle of login. So rows land unsealed and
// this sweep chains them, exactly as the Elasticsearch reconciler backfills
// indexed_at. The cost is real and is reported rather than hidden: an event is
// tamper-evident once sealed, VerifyChain returns the unsealed count alongside
// the verdict, and the sealer's lag is therefore visible to the person reading
// the evidence rather than assumed away.
//
// WHAT IT DETECTS. Any edit to a sealed row (every stored column is in the
// canonical form, so there is no field to change quietly), any deleted sealed
// row (the gap in chain_seq cannot be closed without recomputing every later
// hash, which requires the secret), and any inserted row backdated into a
// sealed run (it cannot be given a chain_seq that is both free and correctly
// linked). What it does not detect is an edit to a row that has not been sealed
// yet, or an attacker who holds the HMAC secret -- which is why the secret is
// configured separately from the database credentials and belongs in a
// different trust domain from the audit store.

// chainBatchSize is how many rows one sealing pass chains per org. Small enough
// that the advisory lock is held briefly, large enough that a busy install
// catches up quickly.
const chainBatchSize = 500

// chainGrace is how long a row is left alone before sealing. A statement that
// began before the sweep started can commit a row with an earlier timestamp
// after it has passed; that row simply gets a later chain_seq, which is correct
// but reads oddly in evidence. The grace makes it rare rather than impossible,
// because the chain's integrity does not depend on timestamp order.
const chainGrace = 30 * time.Second

// chainColumns is the projection every chain operation reads. It is one
// constant because the sealer and the verifier must hash the identical set of
// columns: if they drift, verification fails on rows nobody touched, which is
// the failure that teaches people to switch the check off.
// Every nullable column is COALESCEd to the empty string, deliberately: a NULL
// and an empty string have to canonicalise to the same bytes, or the same row
// would hash differently depending on which one the writer happened to store
// and the chain would break on rows nobody touched. The cost is that swapping
// one for the other is invisible to the chain, which is also the one edit that
// changes nothing an auditor can read.
const chainColumns = `id, timestamp, COALESCE(org_id::text, ''), COALESCE(actor_id, ''),
	                   COALESCE(actor_type, ''), event_type, category, action,
	                   COALESCE(target_type, ''), COALESCE(resource_id, ''), COALESCE(target_id, ''),
	                   outcome, COALESCE(actor_ip, ''), COALESCE(session_id, ''), COALESCE(request_id, ''),
	                   COALESCE(details::text, ''), COALESCE(prev_hash, ''), COALESCE(event_hash, '')`

// scanChainRow reads one row of chainColumns into an AuditEvent.
func scanChainRow(rows pgx.Rows) (*AuditEvent, error) {
	var e AuditEvent
	var actorType, outcome string
	var ts time.Time
	err := rows.Scan(&e.ID, &ts, &e.TenantID, &e.ActorID, &actorType, &e.EventType, &e.Category,
		&e.Action, &e.ResourceType, &e.ResourceID, &e.TargetID, &outcome, &e.IP, &e.SessionID,
		&e.RequestID, &e.Details, &e.PreviousHash, &e.Hash)
	if err != nil {
		return nil, err
	}
	e.Timestamp = ts
	e.ActorType = ActorType(actorType)
	e.Outcome = Outcome(outcome)
	return &e, nil
}

// ChainSealer chains audit rows into a per-org tamper-evident sequence.
type ChainSealer struct {
	db     poolQuerier
	logger *Logger
	log    *zap.Logger
}

// poolQuerier is the slice of pgxpool this file uses, named so tests can drive
// the sealer against a transaction.
type poolQuerier interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// NewChainSealer builds a sealer over the audit store. secret is the HMAC key;
// an empty secret is a programming error, not a mode -- callers decide whether
// the chain runs by whether they construct one.
func NewChainSealer(db poolQuerier, secret string, log *zap.Logger) (*ChainSealer, error) {
	if secret == "" {
		return nil, errors.New("audit chain requires a secret")
	}
	if log == nil {
		log = zap.NewNop()
	}
	return &ChainSealer{db: db, logger: NewLogger(secret), log: log}, nil
}

// Start runs the sealing sweep on a ticker until ctx is cancelled.
func (s *ChainSealer) Start(ctx context.Context, interval time.Duration) {
	ctx = orgctx.WithBypassRLS(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.log.Info("audit chain sealer started", zap.Duration("interval", interval))
	for {
		select {
		case <-ctx.Done():
			s.log.Info("audit chain sealer stopped")
			return
		case <-ticker.C:
			if n, err := s.SealAll(ctx); err != nil {
				// A sweep that cannot run is the control not running. It is an
				// error rather than a warning because the evidence the product
				// publishes depends on this, and the unsealed count that
				// verification reports is the other half of the signal.
				s.log.Error("audit chain sealing pass failed", zap.Int("sealed", n), zap.Error(err))
			}
		}
	}
}

// SealAll seals the pending rows of every org that has any, and returns how
// many rows it chained.
func (s *ChainSealer) SealAll(ctx context.Context) (int, error) {
	ctx = orgctx.WithBypassRLS(ctx)
	rows, err := s.db.Query(ctx,
		//orgscope:ignore audit_events cross-org sealing sweep under bypass-RLS; each write below is scoped to the org it came from
		`SELECT DISTINCT org_id FROM audit_events WHERE event_hash IS NULL AND org_id IS NOT NULL AND timestamp < $1`,
		time.Now().Add(-chainGrace))
	if err != nil {
		return 0, fmt.Errorf("find orgs with unsealed audit rows: %w", err)
	}
	var orgs []string
	for rows.Next() {
		var org string
		if err := rows.Scan(&org); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan org: %w", err)
		}
		orgs = append(orgs, org)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("read orgs: %w", err)
	}

	total := 0
	for _, org := range orgs {
		n, err := s.SealOrg(ctx, org)
		total += n
		if err != nil {
			return total, fmt.Errorf("seal org %s: %w", org, err)
		}
	}
	return total, nil
}

// SealOrg chains up to chainBatchSize unsealed rows for one org, in
// (timestamp, id) order, under an advisory lock so two sealers cannot both
// extend the same chain.
func (s *ChainSealer) SealOrg(ctx context.Context, orgID string) (int, error) {
	ctx = orgctx.WithBypassRLS(ctx)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The lock is transaction-scoped, so it is released by the commit or the
	// rollback above whatever happens below.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "audit_chain:"+orgID); err != nil {
		return 0, fmt.Errorf("take the chain lock: %w", err)
	}

	// The tail of the sealed chain. No rows means this org's chain starts here.
	var lastSeq int64
	var lastHash string
	err = tx.QueryRow(ctx,
		`SELECT chain_seq, event_hash FROM audit_events
		  WHERE org_id = $1 AND chain_seq IS NOT NULL ORDER BY chain_seq DESC LIMIT 1`, orgID).
		Scan(&lastSeq, &lastHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("read the chain tail: %w", err)
	}

	rows, err := tx.Query(ctx,
		`SELECT `+chainColumns+` FROM audit_events
		  WHERE org_id = $1 AND event_hash IS NULL AND timestamp < $2
		  ORDER BY timestamp, id LIMIT $3`,
		orgID, time.Now().Add(-chainGrace), chainBatchSize)
	if err != nil {
		return 0, fmt.Errorf("read unsealed rows: %w", err)
	}
	var pending []*AuditEvent
	for rows.Next() {
		e, err := scanChainRow(rows)
		if err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan unsealed row: %w", err)
		}
		pending = append(pending, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("read unsealed rows: %w", err)
	}

	sealed := 0
	for _, e := range pending {
		if err := s.logger.PrepareForStorage(e, lastHash); err != nil {
			return sealed, fmt.Errorf("hash event %s: %w", e.ID, err)
		}
		lastSeq++
		tag, err := tx.Exec(ctx,
			`UPDATE audit_events SET chain_seq = $1, prev_hash = $2, event_hash = $3
			  WHERE id = $4 AND org_id = $5 AND event_hash IS NULL`,
			lastSeq, e.PreviousHash, e.Hash, e.ID, orgID)
		if err != nil {
			return sealed, fmt.Errorf("seal event %s: %w", e.ID, err)
		}
		if tag.RowsAffected() != 1 {
			// Somebody else sealed it between the read and here, which the
			// advisory lock is supposed to prevent. Stop rather than continue
			// with a hash the row does not carry.
			return sealed, fmt.Errorf("event %s was sealed concurrently; the chain lock did not hold", e.ID)
		}
		lastHash = e.Hash
		sealed++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit the sealed batch: %w", err)
	}
	return sealed, nil
}

// ChainVerification is the answer to "is this tenant's audit trail intact".
type ChainVerification struct {
	OrgID string `json:"org_id"`
	// Sealed is how many rows carry a chain position.
	Sealed int64 `json:"sealed_events"`
	// Unsealed is how many do not yet. These are outside the tamper evidence,
	// and reporting the number is the point: a chain that covers 40% of the
	// trail and says only "intact" is a worse answer than no chain.
	Unsealed int64 `json:"unsealed_events"`
	// LastSeq is the tail of the chain, 0 when nothing is sealed.
	LastSeq int64 `json:"last_sequence"`
	// Intact is false when a hash does not verify, a link does not match, or a
	// sealed row is missing from the sequence.
	Intact bool `json:"intact"`
	// Break names the first problem found, empty when Intact.
	Break string `json:"break,omitempty"`
	// BreakEventID is the event the break was found at.
	BreakEventID string `json:"break_event_id,omitempty"`
}

// VerifyChain walks one org's sealed chain in order and reports the first
// break. It reads in pages so a large trail does not have to fit in memory.
func (s *ChainSealer) VerifyChain(ctx context.Context, orgID string) (*ChainVerification, error) {
	ctx = orgctx.WithBypassRLS(ctx)
	out := &ChainVerification{OrgID: orgID, Intact: true}

	if err := s.db.QueryRow(ctx,
		`SELECT COUNT(*) FILTER (WHERE chain_seq IS NOT NULL),
		        COUNT(*) FILTER (WHERE chain_seq IS NULL),
		        COALESCE(MAX(chain_seq), 0)
		   FROM audit_events WHERE org_id = $1`, orgID).
		Scan(&out.Sealed, &out.Unsealed, &out.LastSeq); err != nil {
		return nil, fmt.Errorf("count the chain: %w", err)
	}

	var prevHash string
	var wantSeq int64
	const page = 1000
	for after := int64(0); ; {
		rows, err := s.db.Query(ctx,
			`SELECT chain_seq, `+chainColumns+` FROM audit_events
			  WHERE org_id = $1 AND chain_seq > $2 ORDER BY chain_seq LIMIT $3`,
			orgID, after, page)
		if err != nil {
			return nil, fmt.Errorf("read the chain: %w", err)
		}
		n := 0
		for rows.Next() {
			var seq int64
			var e AuditEvent
			var actorType, outcome string
			var ts time.Time
			if err := rows.Scan(&seq, &e.ID, &ts, &e.TenantID, &e.ActorID, &actorType, &e.EventType,
				&e.Category, &e.Action, &e.ResourceType, &e.ResourceID, &e.TargetID, &outcome,
				&e.IP, &e.SessionID, &e.RequestID, &e.Details, &e.PreviousHash, &e.Hash); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scan a sealed row: %w", err)
			}
			e.Timestamp = ts
			e.ActorType = ActorType(actorType)
			e.Outcome = Outcome(outcome)
			n++
			after = seq
			wantSeq++

			// A gap means a sealed row was deleted. The link check below would
			// catch it too, but saying "missing" is the useful answer.
			if seq != wantSeq {
				out.Intact, out.BreakEventID = false, e.ID
				out.Break = fmt.Sprintf("audit events %d through %d are missing from the chain; the next sealed event is %d (%s)",
					wantSeq, seq-1, seq, e.ID)
				rows.Close()
				return out, nil
			}
			if e.PreviousHash != prevHash {
				out.Intact, out.BreakEventID = false, e.ID
				out.Break = fmt.Sprintf("event %d (%s) links to %q, but the event before it hashes to %q",
					seq, e.ID, e.PreviousHash, prevHash)
				rows.Close()
				return out, nil
			}
			if err := e.VerifyHash(s.logger.secret); err != nil {
				out.Intact, out.BreakEventID = false, e.ID
				out.Break = fmt.Sprintf("event %d (%s) has been altered since it was sealed: %v", seq, e.ID, err)
				rows.Close()
				return out, nil
			}
			prevHash = e.Hash
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("read the chain: %w", err)
		}
		if n < page {
			return out, nil
		}
	}
}
