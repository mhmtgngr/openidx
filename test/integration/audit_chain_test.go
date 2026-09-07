//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// J8 — operate, at the claim an auditor actually leans on.
//
// "Monitor → audit → back up → restore → upgrade" is the last journey the
// Definition of Done lists without automated proof. Its backup, restore and
// upgrade steps are operator drills against a live deployment. Its AUDIT step
// is a claim the product makes in writing — that the trail is tamper-evident —
// and that claim is checkable here, now, against the running services.
//
// internal/audit/chain_test.go proves the sealer's arithmetic. This proves the
// property end to end: that the events the product WRITES are sealed by the
// sealer that is RUNNING, and that the verification endpoint an auditor calls
// notices when one of them changes. Those are different questions, and the
// commit that added this file is there because the first one had a different
// answer than anybody thought: access-service's events were being refused by
// the ingest endpoint and never reached the chain at all.
//
// The doctoring is an UPDATE, deliberately. A tamper-evident log is not a claim
// about who can reach the database — it is the claim that reaching it is not
// enough, because the change shows. So the test does the thing the control
// exists to catch: it edits a sealed row directly, with the same privileges an
// operator or an intruder with database access would have.
func TestTheAuditTrailNoticesWhenItIsAltered(t *testing.T) {
	db := integrationDB(t)
	// t.Cleanup rather than defer, and registered first so it runs LAST:
	// cleanups run after the function's defers and in reverse order, so a
	// `defer db.Close()` would shut the pool before the restore below could
	// use it — which is exactly what happened the first time this ran, leaving
	// the shared trail broken for every test after it.
	t.Cleanup(func() { db.Close() })

	ctx := context.Background()
	token := getAdminToken(t)
	const verifyURL = "http://localhost:8004/api/v1/audit/chain/verify"

	status, before := apiRequest(t, "GET", verifyURL, "", token)
	require.Equal(t, 200, status, "chain verification failed: %v", before)

	// Three preconditions, because without them "intact" means nothing.
	require.Equal(t, true, before["enabled"],
		"the hash chain is not enabled in this stack, so `intact` is an answer about nothing. "+
			"AUDIT_CHAIN_SECRET must be set for audit-service")
	sealed, _ := before["sealed_events"].(float64)
	require.Greater(t, sealed, float64(0),
		"the chain holds no sealed events; this test would pass over an empty trail")
	require.Equal(t, true, before["intact"],
		"the trail is already broken before this test touched it: %v", before)

	// The newest sealed event. The last link is the cheapest to restore exactly,
	// and altering it is as much a break as altering the first.
	var id, action string
	require.NoError(t, db.QueryRow(ctx, `
		SELECT id::text, action FROM audit_events
		WHERE chain_seq IS NOT NULL ORDER BY chain_seq DESC LIMIT 1`).Scan(&id, &action))

	// Restored whatever happens below, so a failing assertion does not leave the
	// shared trail broken for every test that runs after this one.
	t.Cleanup(func() {
		if _, err := db.Exec(context.Background(),
			`UPDATE audit_events SET action = $2 WHERE id = $1::uuid`, id, action); err != nil {
			t.Errorf("could not restore the doctored audit row %s: %v", id, err)
		}
	})

	_, err := db.Exec(ctx,
		`UPDATE audit_events SET action = action || '.doctored' WHERE id = $1::uuid`, id)
	require.NoError(t, err, "could not alter the audit row")

	status, after := apiRequest(t, "GET", verifyURL, "", token)
	require.Equal(t, 200, status, "chain verification failed after the alteration: %v", after)

	assert.Equal(t, false, after["intact"],
		"a sealed audit event was edited in the database and the trail still reports itself intact. "+
			"Tamper-evidence is the whole claim: %v", after)
	assert.Equal(t, id, after["break_event_id"],
		"the trail noticed a break and named the wrong event")
	if breakMsg, _ := after["break"].(string); breakMsg != "" {
		assert.Contains(t, breakMsg, "hash mismatch",
			"the break is reported without saying what is wrong with it: %q", breakMsg)
	} else {
		t.Error("the trail reports a break with no description; an auditor is told something is wrong and not what")
	}

	// And it heals: restoring the row restores the hash input, so the same
	// endpoint says intact again. Without this the test could pass on a chain
	// that reports every trail as broken.
	require.NoError(t, func() error {
		_, e := db.Exec(ctx, `UPDATE audit_events SET action = $2 WHERE id = $1::uuid`, id, action)
		return e
	}(), "restoring the row failed")

	status, restored := apiRequest(t, "GET", verifyURL, "", token)
	require.Equal(t, 200, status, "chain verification failed after the restore: %v", restored)
	assert.Equal(t, true, restored["intact"],
		"the row was put back exactly and the trail still reports a break, so `intact:false` above "+
			"was not evidence of anything: %v", restored)

	fmt.Printf("audit chain: %v sealed events, break detected and cleared on %s\n", before["sealed_events"], id)
}
