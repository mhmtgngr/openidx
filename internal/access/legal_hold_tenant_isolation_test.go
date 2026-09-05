package access

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Tenant isolation for the legal-hold surface, migration v149.
//
// A legal hold marks a session recording as evidence: while one is active the
// retention sweep must not purge the recording. Releasing a hold is therefore
// not a status change — it is what lets the next sweep DELETE the recording.
//
// Every handler in remote_support_legal_hold.go took a bare session id, so an
// administrator of one tenant could place, read and — the one that matters —
// RELEASE another tenant's litigation hold by naming their session id, and the
// recording it protected was gone at the next sweep. The Guacamole twin does
// the identical job and gated on session visibility, which is how the gap was
// legible at all.
//
// The last case is the point of the file: it does not stop at "the release
// returned 404". It runs the real purge-candidate query afterwards and asserts
// the recording is still NOT a candidate — because a release that is refused
// but leaves the recording purgeable would satisfy the first assertion and
// still destroy the evidence.
//
// The pool is the container superuser, which bypasses RLS, so what these prove
// is the explicit predicate in each query. The belt is proved separately under
// the NOSUPERUSER role by test/integration/cross_org_test.go.
func TestLegalHold_TenantIsolation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	var orgB string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('lh-b','lh-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	// A finalized, unpurged remote-support recording in org A — a purge
	// candidate the moment nothing holds it.
	var sessionA string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO remote_support_sessions
			(agent_id, status, mode, org_id, recording_enabled, recording_finalized_at, recording_storage_key)
		VALUES ($1, 'ended', 'interactive', $2, true, NOW() - INTERVAL '400 days', $3)
		RETURNING id::text`, "lh-agent-"+suffix, orgA, "rec/lh-"+suffix).Scan(&sessionA); err != nil {
		t.Fatalf("seed org A session: %v", err)
	}

	// A second org A session with no hold, for the place case — session A gets
	// its hold seeded directly below, so the release and list cases do not
	// depend on the place handler having worked.
	var sessionA2 string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO remote_support_sessions
			(agent_id, status, mode, org_id, recording_enabled, recording_finalized_at, recording_storage_key)
		VALUES ($1, 'ended', 'interactive', $2, true, NOW() - INTERVAL '400 days', $3)
		RETURNING id::text`, "lh-agent2-"+suffix, orgA, "rec/lh2-"+suffix).Scan(&sessionA2); err != nil {
		t.Fatalf("seed org A second session: %v", err)
	}

	// The active hold, written directly. Under the old handlers the release
	// below matched it on session_id alone, so seeding it here is what makes
	// the destructive case provable rather than a cascade from a failed place.
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO recording_legal_holds (session_id, reason, org_id)
		VALUES ($1::uuid, 'litigation 2026-14', $2)`, sessionA, orgA); err != nil {
		t.Fatalf("seed org A hold: %v", err)
	}

	h := &RemoteSupportHandler{db: db, logger: zap.NewNop()}

	call := func(org, session string, fn gin.HandlerFunc, method, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(method, "/remote-support/sessions/"+session+"/legal-hold", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		c.Request = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
		c.Set("user_id", "00000000-0000-0000-0000-000000000001")
		c.Params = append(c.Params, gin.Param{Key: "id", Value: session})
		fn(c)
		return w
	}

	// purgeCandidate runs the sweeper's own candidate query, restricted to this
	// session. It is the ground truth this whole control exists to move.
	purgeCandidate := func(session string) bool {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(orgctx.WithBypassRLS(ctx), `
			SELECT COUNT(*) FROM remote_support_sessions s
			 WHERE s.id = $1::uuid
			   AND s.recording_finalized_at IS NOT NULL
			   AND s.recording_purged_at IS NULL
			   AND NOT EXISTS (
			       SELECT 1 FROM recording_legal_holds rlh
			        WHERE rlh.session_id = s.id AND rlh.released_at IS NULL
			   )`, session).Scan(&n); err != nil {
			t.Fatalf("purge-candidate query: %v", err)
		}
		return n > 0
	}

	// THE POINT OF THIS FILE, and it runs first so nothing can make it pass by
	// accident.
	t.Run("org B cannot release org A's hold, and the recording stays held", func(t *testing.T) {
		if purgeCandidate(sessionA) {
			t.Fatal("the seeded recording is a purge candidate despite an active hold; the fixture proves nothing")
		}

		w := call(orgB, sessionA, h.HandleReleaseLegalHold, http.MethodDelete, `{"reason":"cleanup"}`)
		if w.Code != http.StatusNotFound {
			t.Fatalf("org B released org A's litigation hold: %d %s", w.Code, w.Body.String())
		}

		// A refusal is not the assertion that matters. What matters is that the
		// recording did not become purgeable — a release that 404s to the caller
		// but still stamps released_at would satisfy the check above and destroy
		// the evidence at the next sweep.
		if purgeCandidate(sessionA) {
			t.Fatal("org A's recording became a purge candidate after org B's release attempt. " +
				"The next retention sweep would delete a recording under litigation hold, " +
				"irreversibly, and the tenant that placed the hold would see only a released_at " +
				"stamped by a user id that is not in their organization")
		}
		var releasedAt *time.Time
		if err := db.Pool.QueryRow(ctx,
			`SELECT released_at FROM recording_legal_holds WHERE session_id = $1::uuid`, sessionA).Scan(&releasedAt); err != nil {
			t.Fatalf("read back the hold: %v", err)
		}
		if releasedAt != nil {
			t.Fatalf("org A's hold is stamped released at %v by org B's request", *releasedAt)
		}
	})

	t.Run("org B cannot read org A's hold reason", func(t *testing.T) {
		// The reason is free text describing an investigation.
		w := call(orgB, sessionA, h.HandleListLegalHolds, http.MethodGet, "")
		if w.Code != http.StatusNotFound {
			t.Fatalf("org B listed org A's holds: %d %s", w.Code, w.Body.String())
		}
	})

	t.Run("org B cannot place a hold on org A's session", func(t *testing.T) {
		w := call(orgB, sessionA2, h.HandlePlaceLegalHold, http.MethodPost, `{"reason":"org B reaching over"}`)
		if w.Code != http.StatusNotFound {
			t.Fatalf("org B placed a hold on org A's session: %d %s", w.Code, w.Body.String())
		}
		if !purgeCandidate(sessionA2) {
			t.Fatal("org B's hold took org A's recording out of the purge list; a tenant must not be " +
				"able to pin another tenant's storage either")
		}
	})

	t.Run("org A places and releases its own hold", func(t *testing.T) {
		// The fix must not turn the control into a refusal for everybody.
		w := call(orgA, sessionA2, h.HandlePlaceLegalHold, http.MethodPost, `{"reason":"litigation 2026-15"}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("org A placing its own hold: %d %s", w.Code, w.Body.String())
		}
		if purgeCandidate(sessionA2) {
			t.Fatal("the recording is still a purge candidate with org A's own active hold on it")
		}
		var org string
		if err := db.Pool.QueryRow(ctx,
			`SELECT org_id::text FROM recording_legal_holds WHERE session_id = $1::uuid`, sessionA2).Scan(&org); err != nil {
			t.Fatalf("read back the hold: %v", err)
		}
		if org != orgA {
			t.Fatalf("the hold is filed under %s, want org A (%s)", org, orgA)
		}

		w = call(orgA, sessionA2, h.HandleReleaseLegalHold, http.MethodDelete, `{"reason":"matter closed"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("org A releasing its own hold: %d %s", w.Code, w.Body.String())
		}
		if !purgeCandidate(sessionA2) {
			t.Fatal("the recording is still held after its owner released the hold; retention would never run")
		}
	})
}
