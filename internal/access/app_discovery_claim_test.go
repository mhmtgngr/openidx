package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// 'discovering' was a one-way door.
//
// handleStartDiscovery read published_apps.status, refused with 409 if it was
// already 'discovering', and then set it with an UPDATE whose error was
// discarded. Only the background worker's terminal write clears that status --
// and every one of those writes discarded its error too, on a goroutine that
// can also simply be killed with the process.
//
// So an app whose discovery outcome was never written stayed 'discovering' for
// ever: the console showed "discovery in progress", every later attempt was
// refused with 409, and there was no way back short of editing the database by
// hand. The claim is now one conditional UPDATE that also takes over a claim
// older than discoveryStallTimeout.

const appPublishSchema = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE published_apps (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	name VARCHAR(255) NOT NULL,
	description TEXT,
	target_url VARCHAR(500) NOT NULL,
	spec_url VARCHAR(500),
	public_host VARCHAR(255),
	landing_path VARCHAR(500),
	status VARCHAR(50) DEFAULT 'pending',
	discovery_started_at TIMESTAMPTZ,
	discovery_completed_at TIMESTAMPTZ,
	discovery_error TEXT,
	discovery_strategies JSONB DEFAULT '[]',
	total_paths_discovered INTEGER DEFAULT 0,
	total_paths_published INTEGER DEFAULT 0,
	created_by UUID,
	created_at TIMESTAMPTZ DEFAULT NOW(),
	updated_at TIMESTAMPTZ DEFAULT NOW(),
	org_id UUID NOT NULL);`

const claimOrgID = "00000000-0000-0000-0000-0000000000d1"

// seedApp inserts one app in the given status, claimed the given interval ago
// ("" leaves discovery_started_at NULL), and returns its id.
func seedApp(t *testing.T, s *Service, ctx context.Context, status, claimedAgo string) string {
	t.Helper()
	started := "NULL"
	if claimedAgo != "" {
		started = "NOW() - INTERVAL '" + claimedAgo + "'"
	}
	var id string
	if err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO published_apps (name, target_url, status, discovery_started_at, org_id)
		VALUES ('an-app', 'http://127.0.0.1:1', $1, `+started+`, $2)
		RETURNING id::text`, status, claimOrgID).Scan(&id); err != nil {
		t.Fatalf("seed app (%s): %v", status, err)
	}
	return id
}

// startDiscovery drives the handler and returns the response.
func startDiscovery(t *testing.T, s *Service, ctx context.Context, appID string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/apps/"+appID+"/discover", nil).WithContext(ctx)
	c.Params = gin.Params{{Key: "appId", Value: appID}}
	s.handleStartDiscovery(c)
	return w
}

func appClaimFixture(t *testing.T) (*Service, context.Context, func()) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, nil, func() {}
	}
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: claimOrgID})
	if _, err := db.Pool.Exec(ctx, appPublishSchema); err != nil {
		cleanup()
		t.Fatalf("create schema: %v", err)
	}
	return &Service{db: db, logger: zap.NewNop()}, ctx, cleanup
}

func TestAnAppStuckDiscoveringCanBeDiscoveredAgain(t *testing.T) {
	s, ctx, cleanup := appClaimFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	// Claimed an hour ago by a run that never wrote its outcome.
	appID := seedApp(t, s, ctx, "discovering", "1 hour")

	if w := startDiscovery(t, s, ctx, appID); w.Code != http.StatusOK && w.Code != http.StatusAccepted {
		t.Fatalf("an app abandoned in 'discovering' an hour ago was refused (%d: %s). Nothing else clears "+
			"that status, so the app can never be discovered again and the console shows "+
			"\"discovery in progress\" for ever.", w.Code, w.Body.String())
	}

	var startedRecently bool
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT discovery_started_at > NOW() - INTERVAL '1 minute' FROM published_apps WHERE id=$1::uuid`,
		appID).Scan(&startedRecently); err != nil {
		t.Fatalf("read the app back: %v", err)
	}
	if !startedRecently {
		t.Error("the stale claim was answered OK but not taken over")
	}
}

func TestADiscoveryAlreadyRunningIsNotDisturbed(t *testing.T) {
	s, ctx, cleanup := appClaimFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	// Claimed a moment ago: a worker is on it.
	appID := seedApp(t, s, ctx, "discovering", "10 seconds")

	w := startDiscovery(t, s, ctx, appID)
	if w.Code != http.StatusConflict {
		t.Errorf("a discovery that started ten seconds ago was answered %d, want 409. Taking a live "+
			"claim means two workers writing the same app's paths.", w.Code)
	}

	var startedRecently bool
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT discovery_started_at < NOW() - INTERVAL '5 seconds' FROM published_apps WHERE id=$1::uuid`,
		appID).Scan(&startedRecently); err != nil {
		t.Fatalf("read the app back: %v", err)
	}
	if !startedRecently {
		t.Error("the live claim's start time was overwritten by the refused request")
	}
}

func TestDiscoveryOnAnotherTenantsAppIsNotFound(t *testing.T) {
	s, ctx, cleanup := appClaimFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	appID := seedApp(t, s, ctx, "pending", "")

	other := orgctx.With(context.Background(), orgctx.Org{ID: "00000000-0000-0000-0000-0000000000d2"})
	if w := startDiscovery(t, s, other, appID); w.Code != http.StatusNotFound {
		t.Errorf("another tenant's app answered %d, want 404: %s", w.Code, w.Body.String())
	}

	// And it was not claimed.
	var status string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT status FROM published_apps WHERE id=$1::uuid`, appID).Scan(&status); err != nil {
		t.Fatalf("read the app back: %v", err)
	}
	if status != "pending" {
		t.Errorf("another tenant's request moved the app to %q", status)
	}
}

// pinDiscovering refuses any write that would move an app out of 'discovering'.
//
// handleStartDiscovery takes the claim synchronously and then hands the app to
// a goroutine. This fixture's target_url refuses connections instantly, so that
// goroutine reaches its terminal write -- status='error' -- in milliseconds,
// and a test reading the status afterwards reads whichever of the two got there
// first. The test below was passing on scheduling luck, and on CI it lost.
//
// The claim is what that test is about, and the claim is the half that is
// synchronous. Pinning the status makes the assertion about the handler rather
// than about the scheduler: the claim passes the trigger, because the claim is
// what writes 'discovering'; the worker's terminal write is refused, which is
// the abandoned-run state the first test in this file already covers.
func pinDiscovering(t *testing.T, s *Service, ctx context.Context) {
	t.Helper()
	if _, err := s.db.Pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION pin_discovering() RETURNS trigger AS $$
		BEGIN
			IF NEW.status IS DISTINCT FROM 'discovering' THEN
				RAISE EXCEPTION 'refused by test: only the claim may write this app''s status';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER pin_discovering_trg BEFORE UPDATE ON published_apps
		FOR EACH ROW EXECUTE FUNCTION pin_discovering();`); err != nil {
		t.Fatalf("install the status pin: %v", err)
	}
}

// A fresh app claims cleanly, and the claim is what the console reads.
func TestStartingDiscoveryClaimsTheApp(t *testing.T) {
	s, ctx, cleanup := appClaimFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	appID := seedApp(t, s, ctx, "pending", "")
	pinDiscovering(t, s, ctx)

	if w := startDiscovery(t, s, ctx, appID); w.Code != http.StatusOK && w.Code != http.StatusAccepted {
		t.Fatalf("starting discovery on a pending app was answered %d: %s", w.Code, w.Body.String())
	}

	var status string
	var claimed bool
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT status, discovery_started_at IS NOT NULL FROM published_apps WHERE id=$1::uuid`,
		appID).Scan(&status, &claimed); err != nil {
		t.Fatalf("read the app back: %v", err)
	}
	if status != "discovering" || !claimed {
		t.Errorf("after starting discovery the app is status=%q claimed=%v", status, claimed)
	}

	// The second request inside the window is refused, so the claim is real.
	if w := startDiscovery(t, s, ctx, appID); w.Code != http.StatusConflict {
		t.Errorf("a second discovery on the same app was answered %d, want 409", w.Code)
	}
}
