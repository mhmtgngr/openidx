//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditURL is the audit service. The chain lives in its process: it seals the
// rows and it answers whether they are still intact.
const auditURL = "http://localhost:8004"

// J8 — operate, at the claim an auditor actually leans on.
//
// "Monitor → audit → back up → restore → upgrade" is the last journey the
// Definition of Done lists without automated proof. Its backup, restore and
// upgrade steps are operator drills against a live deployment. Its AUDIT step
// is a claim the product makes in writing — that the trail is tamper-evident —
// and that claim is checkable here, now, against the running services.
//
// internal/audit/chain_test.go proves the sealer's arithmetic. This proves the
// property end to end: that an event the product WRITES is sealed by the sealer
// that is RUNNING, and that the verification endpoint an auditor calls notices
// when that event changes. Those are different questions, and the commit that
// added this file is there because the first one had a different answer than
// anybody thought: access-service's events were being refused by the ingest
// endpoint and never reached the chain at all.
//
// The doctoring is an UPDATE, deliberately. A tamper-evident log is not a claim
// about who can reach the database — it is the claim that reaching it is not
// enough, because the change shows. So the test does the thing the control
// exists to catch: it edits a sealed row directly, with the same privileges an
// operator or an intruder with database access would have.
//
// WHY IT POSTS ITS OWN EVENT AND WAITS. The first version of this test read the
// newest sealed row and required the trail to already hold one:
//
//	require.Greater(t, sealed, float64(0),
//	    "the chain holds no sealed events; this test would pass over an empty trail")
//
// That precondition is right and the test could not meet it. It ran green on my
// machine because the database there had months of events in it, and red in CI
// on every single run, because CI migrates a fresh database and this file sorts
// first in the package — so at the moment it ran, nothing had written an audit
// event yet, let alone had one sealed. A test that depends on what other tests
// happened to leave behind is not evidence about the product; it is evidence
// about the order of the suite. So it writes the event it verifies.
//
// The wait is the price of doing that honestly. The sealer leaves a row alone
// for chainGrace (30s, internal/audit/chain.go) so a statement that began before
// the sweep cannot commit behind it, then seals on its ticker
// (AUDIT_CHAIN_INTERVAL, 60s by default and 5s in the CI job). Waiting for a
// real sweep is the point: it is what makes this a proof that the sealer which
// is RUNNING sealed a row the product WROTE, rather than a proof about a
// sealer constructed inside a unit test.
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
	verifyURL := auditURL + "/api/v1/audit/chain/verify"

	status, before := apiRequest(t, "GET", verifyURL, "", token)
	require.Equal(t, 200, status, "chain verification failed: %v", before)
	require.Equal(t, true, before["enabled"],
		"the hash chain is not enabled in this stack, so `intact` is an answer about nothing. "+
			"AUDIT_CHAIN_SECRET must be set for audit-service")
	require.Equal(t, true, before["intact"],
		"the trail is already broken before this test touched it: %v", before)

	// --- the event this test will doctor, written through the product's own
	// ingest path: the same endpoint, with the same shape, that
	// internal/access.logAuditEvent posts every credential reveal to.
	marker := fmt.Sprintf("j8.tamper_probe.%d", time.Now().UnixNano())
	status, created := apiRequest(t, "POST", auditURL+"/api/v1/audit/events", `{
		"event_type":  "authorization",
		"category":    "access_proxy",
		"action":      "`+marker+`",
		"outcome":     "success",
		"actor_type":  "service",
		"target_type": "audit_chain",
		"details":     {"written_by": "test/integration/audit_chain_test.go"}
	}`, "")
	require.Equal(t, 201, status,
		"the audit ingest endpoint refused the event this test needs to seal: %v", created)
	id, _ := created["id"].(string)
	require.NotEmpty(t, id, "the ingest endpoint returned no event id: %v", created)

	// --- wait for the running sealer to chain it.
	//
	// Bounded, and the bound is stated in the failure: an unsealed row after
	// this long means the sealer is not running, not that it is slow.
	const sealDeadline = 150 * time.Second
	var seq int64
	deadline := time.Now().Add(sealDeadline)
	for {
		err := db.QueryRow(ctx,
			`SELECT COALESCE(chain_seq, 0) FROM audit_events WHERE id = $1::uuid`, id).Scan(&seq)
		require.NoError(t, err, "the event this test posted is not in audit_events at all: %s", id)
		if seq > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("event %s was written %v ago and the sealer has not chained it. "+
				"The chain sweep is AUDIT_CHAIN_INTERVAL (60s by default) and it ignores rows "+
				"younger than chainGrace (30s), so this should take about a minute — an unsealed "+
				"row after %v means audit-service's sealer is not running.",
				id, sealDeadline, sealDeadline)
		}
		time.Sleep(time.Second)
	}

	status, sealed := apiRequest(t, "GET", verifyURL, "", token)
	require.Equal(t, 200, status, "chain verification failed after the event was sealed: %v", sealed)
	require.Equal(t, true, sealed["intact"],
		"sealing the new event broke the trail before this test doctored anything: %v", sealed)
	count, _ := sealed["sealed_events"].(float64)
	require.Greater(t, count, float64(0),
		"the row carries chain_seq %d and the endpoint reports no sealed events: %v", seq, sealed)

	// The action is what the alteration changes, so it is what gets restored.
	var action string
	require.NoError(t, db.QueryRow(ctx,
		`SELECT action FROM audit_events WHERE id = $1::uuid`, id).Scan(&action))

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

	fmt.Printf("audit chain: event %s sealed at seq %d, break detected and cleared\n", id, seq)
}
