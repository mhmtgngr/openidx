package access

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/common/database"
)

// Listed as quarantined, still holding every service it had.
//
// QuarantineZitiIdentity writes the ledger row FIRST -- it has to, because the
// row is where the identity's original attributes are saved, and after the
// patch they are gone from the controller. Then it strips the attributes on the
// overlay. If that patch fails, the ledger row has to come back out.
//
// That rollback discarded its error. A failed rollback is the worst state this
// function can reach, and it is worse than it first looks: the row says the
// identity is quarantined, so the console shows it as contained AND the release
// path will happily "restore" attributes from a row describing an identity that
// was never stripped -- while on the overlay the identity still reaches
// everything it did before. The caller was told only "patch identity
// attributes: ...", which reads as "nothing happened".

const zitiQuarantineSchema = `
CREATE TABLE IF NOT EXISTS ziti_ai_quarantine (
    identity_id      VARCHAR(255) PRIMARY KEY,
    identity_name    VARCHAR(255),
    saved_attributes JSONB NOT NULL DEFAULT '[]',
    reason           TEXT,
    quarantined_by   VARCHAR(255),
    quarantined_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`

const quarantinedID = "ident-q1"

// quarantineFixture gives a controller that reports the identity's attributes
// and accepts the session listing, with the attribute patch left to each test.
func quarantineFixture(t *testing.T) (*ZitiManager, *zitiStub, *database.PostgresDB, context.Context, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, nil, nil, nil, func() {}
	}
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, zitiQuarantineSchema); err != nil {
		cleanup()
		t.Fatalf("schema: %v", err)
	}

	stub := newZitiStub(t)
	stub.ok("GET /edge/management/v1/identities/"+quarantinedID,
		`{"data":{"id":"`+quarantinedID+`","name":"an-agent","roleAttributes":["fleet","prod-db"]}}`)
	stub.ok("GET /edge/management/v1/identities",
		`{"data":[{"id":"`+quarantinedID+`","name":"an-agent","roleAttributes":["fleet","prod-db"]}]}`)
	stub.ok("GET /edge/management/v1/sessions", `{"data":[]}`)

	return zitiManagerAgainst(t, stub, db), stub, db, ctx, cleanup
}

func TestQuarantineStripsTheIdentityAndKeepsItsAttributesToRestore(t *testing.T) {
	zm, stub, db, ctx, cleanup := quarantineFixture(t)
	if zm == nil {
		return
	}
	defer cleanup()

	stub.on("PATCH /edge/management/v1/identities", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	if _, err := zm.QuarantineZitiIdentity(ctx, quarantinedID, "anomalous dials", "admin"); err != nil {
		t.Fatalf("QuarantineZitiIdentity: %v (controller saw %v)", err, stub.received())
	}
	if !stub.saw("PATCH /edge/management/v1/identities/" + quarantinedID) {
		t.Errorf("the identity's attributes were never stripped on the overlay; calls: %v", stub.received())
	}

	var saved string
	if err := db.Pool.QueryRow(ctx,
		`SELECT saved_attributes::text FROM ziti_ai_quarantine WHERE identity_id = $1`,
		quarantinedID).Scan(&saved); err != nil {
		t.Fatalf("no quarantine row: %v", err)
	}
	// The saved attributes are the only copy: the overlay no longer has them.
	for _, attr := range []string{"fleet", "prod-db"} {
		if !strings.Contains(saved, attr) {
			t.Errorf("saved_attributes = %s, missing %q — releasing this identity would not restore "+
				"the access it had", saved, attr)
		}
	}
}

// The patch fails and the rollback works: no row, and the caller is told the
// quarantine did not happen.
func TestAQuarantineWhoseOverlayPatchFailsLeavesNoLedgerRow(t *testing.T) {
	zm, _, db, ctx, cleanup := quarantineFixture(t)
	if zm == nil {
		return
	}
	defer cleanup()

	// The controller refuses to strip the attributes.
	// (No PATCH handler registered → the stub answers 404.)

	if _, err := zm.QuarantineZitiIdentity(ctx, quarantinedID, "anomalous dials", "admin"); err == nil {
		t.Fatal("the overlay refused the patch and the quarantine reported success")
	}

	var n int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM ziti_ai_quarantine WHERE identity_id = $1`, quarantinedID).Scan(&n); err != nil {
		t.Fatalf("count ledger rows: %v", err)
	}
	if n != 0 {
		t.Errorf("%d ledger row(s) survive a quarantine that never reached the overlay; the console "+
			"shows this identity as contained while it still holds its access", n)
	}
}

// The patch fails AND the rollback fails. The row stays, and the error has to
// say so — this is the state an operator cannot otherwise discover.
func TestAQuarantineThatCannotRollBackSaysTheIdentityStillHasItsAccess(t *testing.T) {
	zm, _, db, ctx, cleanup := quarantineFixture(t)
	if zm == nil {
		return
	}
	defer cleanup()

	if _, err := db.Pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION refuse_quarantine_rollback() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refused by test'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER refuse_quarantine_rollback_trg BEFORE DELETE ON ziti_ai_quarantine
		FOR EACH ROW EXECUTE FUNCTION refuse_quarantine_rollback();`); err != nil {
		t.Fatalf("install refusal trigger: %v", err)
	}

	_, err := zm.QuarantineZitiIdentity(ctx, quarantinedID, "anomalous dials", "admin")
	if err == nil {
		t.Fatal("the quarantine reported success having neither stripped the identity nor rolled back")
	}
	if !strings.Contains(err.Error(), "still holds its") {
		t.Errorf("the error does not say the identity is listed as quarantined while it still holds "+
			"its access on the overlay, which is the one thing nobody can see from the console: %v", err)
	}

	// The row really is stranded — otherwise the message would be describing a
	// state this test never produced.
	var n int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM ziti_ai_quarantine WHERE identity_id = $1`, quarantinedID).Scan(&n); err != nil {
		t.Fatalf("count ledger rows: %v", err)
	}
	if n != 1 {
		t.Errorf("%d ledger rows; the test's premise (the rollback was refused) did not hold", n)
	}
}
