package audit

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The audit trail's tamper evidence, tested against the real schema.
//
// Until migration v181 there was no column to store a hash in, no code that
// produced one, and four published claims that OpenIDX keeps a tamper-evident
// HMAC hash-chain audit log. The tests that existed covered the primitives in
// internal/audit/logger.go -- and reached them through a ComputeHashForChain
// method the test file declared itself, because nothing in the product ever
// called PrepareForStorage.
//
// These tests are about the property, not the primitive: seal a real trail in
// a real database, then change it the way someone covering their tracks would,
// and require the verification to say so and to name the event.

// Two organizations of the fixture's own, NOT the default org: migration v22
// seeds audit_events for 00000000-...-000000000010, and a test that counted
// "the events I inserted" against that org would be counting the seed as well.
const (
	chOrgA = "00000000-0000-0000-0000-0000000000a1"
	chOrgB = "00000000-0000-0000-0000-0000000000b1"
	chUser = "77777777-0000-0000-0000-0000000000c1"
)

type chainFixture struct {
	t      *testing.T
	db     *database.PostgresDB
	ctx    context.Context
	sealer *ChainSealer
}

func newChainFixture(t *testing.T) *chainFixture {
	t.Helper()
	db, cleanup := setupComplianceSchemaDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := orgctx.WithBypassRLS(context.Background())
	f := &chainFixture{t: t, db: db, ctx: ctx}
	for _, org := range []string{chOrgA, chOrgB} {
		f.exec(`INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)
		        ON CONFLICT (id) DO NOTHING`, org, "chain-"+org[len(org)-2:], "chain-"+org[len(org)-2:])
	}
	f.exec(`INSERT INTO users (id, username, email, org_id) VALUES ($1, 'chain-u', 'chain-u@test.local', $2)
	        ON CONFLICT (id) DO NOTHING`, chUser, chOrgA)

	sealer, err := NewChainSealer(db.Pool, "chain-test-secret", zap.NewNop())
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	f.sealer = sealer
	return f
}

func (f *chainFixture) exec(q string, args ...interface{}) {
	f.t.Helper()
	if _, err := f.db.Pool.Exec(f.ctx, q, args...); err != nil {
		f.t.Fatalf("exec (%s): %v", q, err)
	}
}

// event writes one audit row, backdated past the sealer's grace period so the
// sweep will pick it up. It returns the row's id.
func (f *chainFixture) event(org, action string) string {
	f.t.Helper()
	var id string
	err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO audit_events (id, timestamp, event_type, category, action, outcome,
		                           actor_id, actor_type, actor_ip, target_id, target_type,
		                           resource_id, details, session_id, request_id, created_at, org_id)
		 VALUES (gen_random_uuid(), NOW() - INTERVAL '5 minutes', 'authentication', 'security', $1, 'success',
		         $2, 'user', '198.51.100.7', $2, 'user', 'res-1', '{"note":"seeded"}', 'sess-1', 'req-1',
		         NOW(), $3)
		 RETURNING id`, action, chUser, org).Scan(&id)
	if err != nil {
		f.t.Fatalf("insert audit event: %v", err)
	}
	return id
}

func (f *chainFixture) seal() int {
	f.t.Helper()
	n, err := f.sealer.SealAll(f.ctx)
	if err != nil {
		f.t.Fatalf("seal: %v", err)
	}
	return n
}

func (f *chainFixture) verify(org string) *ChainVerification {
	f.t.Helper()
	v, err := f.sealer.VerifyChain(f.ctx, org)
	if err != nil {
		f.t.Fatalf("verify: %v", err)
	}
	return v
}

func TestSealingChainsEveryEventInOrder(t *testing.T) {
	f := newChainFixture(t)
	for i := 0; i < 5; i++ {
		f.event(chOrgA, fmt.Sprintf("login.attempt.%d", i))
	}

	// SealAll is the sweep the worker runs, so it chains every org that has
	// unsealed rows -- including the events the migration chain seeds for the
	// default org. The count that matters is this org's, below.
	if n := f.seal(); n < 5 {
		t.Fatalf("the sweep sealed %d events, want at least the 5 this test wrote", n)
	}
	v := f.verify(chOrgA)
	if !v.Intact {
		t.Fatalf("a freshly sealed trail did not verify: %s", v.Break)
	}
	if v.Sealed != 5 || v.LastSeq != 5 {
		t.Errorf("sealed=%d last_seq=%d, want 5 and 5", v.Sealed, v.LastSeq)
	}
	if v.Unsealed != 0 {
		t.Errorf("unsealed=%d after a full sweep, want 0", v.Unsealed)
	}

	// Sealing again must be a no-op rather than a second chain over the same rows.
	if n := f.seal(); n != 0 {
		t.Errorf("a second sweep sealed %d rows, want 0", n)
	}
}

func TestAnAlteredAuditRowBreaksTheChain(t *testing.T) {
	f := newChainFixture(t)
	f.event(chOrgA, "login.success")
	target := f.event(chOrgA, "user.deleted")
	f.event(chOrgA, "login.success")
	f.seal()

	// The edit somebody covering their tracks would make: soften the action.
	f.exec(`UPDATE audit_events SET action = 'user.updated' WHERE id = $1`, target)

	v := f.verify(chOrgA)
	if v.Intact {
		t.Fatal("the chain verified after an audit row was rewritten; the tamper evidence is not evident")
	}
	if v.BreakEventID != target {
		t.Errorf("the break was reported at %s, want the altered event %s", v.BreakEventID, target)
	}
	if !strings.Contains(v.Break, "altered") {
		t.Errorf("break text does not say the row was altered: %q", v.Break)
	}
}

func TestADeletedAuditRowBreaksTheChain(t *testing.T) {
	f := newChainFixture(t)
	f.event(chOrgA, "login.success")
	target := f.event(chOrgA, "role.granted")
	f.event(chOrgA, "login.success")
	f.seal()

	// Deleting the row outright is the other half of covering tracks, and the
	// one a per-row hash alone would miss: the surviving rows all still verify.
	f.exec(`DELETE FROM audit_events WHERE id = $1`, target)

	v := f.verify(chOrgA)
	if v.Intact {
		t.Fatal("the chain verified after a sealed audit row was deleted; a hash per row is not a chain")
	}
	if !strings.Contains(v.Break, "missing from the chain") {
		t.Errorf("break text does not name the gap: %q", v.Break)
	}
}

func TestTheChainIsPerOrgAndOneTenantCannotBreakAnother(t *testing.T) {
	f := newChainFixture(t)
	for i := 0; i < 3; i++ {
		f.event(chOrgA, "a.event")
		f.event(chOrgB, "b.event")
	}
	f.seal()

	for _, org := range []string{chOrgA, chOrgB} {
		if v := f.verify(org); !v.Intact || v.LastSeq != 3 {
			t.Fatalf("org %s: intact=%v last_seq=%d, want true and 3 (%s)", org, v.Intact, v.LastSeq, v.Break)
		}
	}

	// Rewrite one of tenant B's rows. Tenant A's evidence must be unaffected --
	// a shared chain would make every tenant's verification fail on somebody
	// else's incident, and rows they cannot even read.
	f.exec(`UPDATE audit_events SET outcome = 'failure' WHERE org_id = $1 AND chain_seq = 2`, chOrgB)

	if v := f.verify(chOrgB); v.Intact {
		t.Error("tenant B's chain verified after tenant B's row was rewritten")
	}
	if v := f.verify(chOrgA); !v.Intact {
		t.Errorf("tenant A's chain broke because of a change to tenant B's rows: %s", v.Break)
	}
}

func TestUnsealedEventsAreReportedRatherThanCountedAsIntact(t *testing.T) {
	f := newChainFixture(t)
	f.event(chOrgA, "login.success")
	f.seal()

	// A row inside the sealer's grace window: real, unchained, and outside the
	// tamper evidence. Reporting "intact" without saying so would overstate
	// what the chain covers, which is the whole failure this feature fixes.
	f.exec(`INSERT INTO audit_events (id, timestamp, event_type, category, action, outcome, created_at, org_id)
	        VALUES (gen_random_uuid(), NOW(), 'authentication', 'security', 'login.success', 'success', NOW(), $1)`, chOrgA)

	v := f.verify(chOrgA)
	if !v.Intact {
		t.Fatalf("an unsealed row broke the chain: %s", v.Break)
	}
	if v.Unsealed != 1 {
		t.Errorf("unsealed=%d, want 1: the sealer's lag has to be visible in the evidence", v.Unsealed)
	}
}

func TestTheChainIsKeyedAndNotJustAHash(t *testing.T) {
	f := newChainFixture(t)
	f.event(chOrgA, "login.success")
	f.event(chOrgA, "login.success")
	f.seal()

	// Someone with write access to audit_events but not the HMAC key cannot
	// re-seal a doctored trail. A verifier holding a different key must reject
	// what this one sealed; if it did not, the "secret" would be decoration.
	other, err := NewChainSealer(f.db.Pool, "a-different-secret", zap.NewNop())
	if err != nil {
		t.Fatalf("second sealer: %v", err)
	}
	v, err := other.VerifyChain(f.ctx, chOrgA)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.Intact {
		t.Error("a chain sealed with one secret verified under another; the HMAC key is not doing anything")
	}
}

// TestEveryStoredColumnIsInTheChain is the test that keeps the chain honest.
//
// A hash that covers most of a row is worse than no hash: verification passes
// and now vouches for the edit. Every column the sealer reads is mutated here,
// one at a time, and each must break the chain. A column added to audit_events
// without being added to canonicalBytes fails this test rather than shipping a
// field an attacker can rewrite for free.
func TestEveryStoredColumnIsInTheChain(t *testing.T) {
	for _, tc := range []struct{ column, value string }{
		{"timestamp", "NOW() - INTERVAL '99 days'"},
		{"event_type", "'authorization'"},
		{"category", "'operational'"},
		{"action", "'something.harmless'"},
		{"outcome", "'failure'"},
		{"actor_id", "'99999999-0000-0000-0000-0000000000ff'"},
		{"actor_type", "'service'"},
		{"actor_ip", "'203.0.113.9'"},
		{"target_id", "'99999999-0000-0000-0000-0000000000fe'"},
		{"target_type", "'application'"},
		{"resource_id", "'res-2'"},
		{"details", `'{"note":"rewritten"}'`},
		{"session_id", "'sess-2'"},
		{"request_id", "'req-2'"},
	} {
		t.Run(tc.column, func(t *testing.T) {
			f := newChainFixture(t)
			id := f.event(chOrgA, "privilege.escalated")
			f.seal()

			f.exec(fmt.Sprintf(`UPDATE audit_events SET %s = %s WHERE id = $1`, tc.column, tc.value), id)

			v := f.verify(chOrgA)
			if v.Intact {
				t.Fatalf("rewriting %s left the chain verifying: that column is not covered by canonicalBytes, so it can be changed for free",
					tc.column)
			}
		})
	}
}
