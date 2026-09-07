package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// Launching a certification campaign was a check-then-act with the act
// unchecked.
//
// handleLaunchAttestationCampaign read the campaign, refused it if the status
// was not 'draft', generated one attestation item per entitlement in scope, and
// then moved the campaign to 'active' with an Exec whose error was discarded.
//
// So a status write the database refused left a campaign in 'draft' with a
// complete set of items already generated -- and the handler answered "Campaign
// launched". The next launch passed the draft check and generated every item a
// second time: each reviewer saw the same entitlement twice, and a campaign
// whose item count no longer matched its scope could never be reconciled
// against what was actually certified.
//
// Two launches arriving together did the same thing with no failure at all,
// because both read 'draft' before either wrote.
//
// The claim is now one conditional UPDATE, taken before any item exists.

const (
	launchOrg  = "00000000-0000-0000-0000-0000000000f1"
	launchUser = "11111111-0000-0000-0000-0000000000f1"
	launchRole = "22222222-0000-0000-0000-0000000000f1"
)

// launchFixture builds an org with one user holding one role, plus a draft
// role_certification campaign over it -- so a launch generates exactly one item
// and a duplicate launch is visible as a second.
func launchFixture(t *testing.T) (*Service, string, func()) {
	t.Helper()
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return nil, "", func() {}
	}
	gin.SetMode(gin.TestMode)
	ctx := orgctx.WithBypassRLS(context.Background())

	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			cleanup()
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1, 'Org F (launch test)', 'org-f-launch-test')`, launchOrg)
	exec(`INSERT INTO users (id, username, email, enabled, org_id)
	      VALUES ($1, 'launch-user', 'launch-user@test.local', true, $2)`, launchUser, launchOrg)
	exec(`INSERT INTO roles (id, name, org_id) VALUES ($1, 'launch-role', $2)`, launchRole, launchOrg)
	exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1, $2, $3)`, launchUser, launchRole, launchOrg)

	var campaignID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO attestation_campaigns (name, campaign_type, reviewer_strategy, status, org_id)
		VALUES ('Q3 role certification', 'role_certification', 'admin', 'draft', $1)
		RETURNING id::text`, launchOrg).Scan(&campaignID); err != nil {
		cleanup()
		t.Fatalf("seed campaign: %v", err)
	}

	return &Service{db: db, logger: zap.NewNop()}, campaignID, cleanup
}

func launch(t *testing.T, s *Service, campaignID string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/attestation-campaigns/"+campaignID+"/launch", nil).
		WithContext(orgctx.With(context.Background(), orgctx.Org{ID: launchOrg}))
	c.Params = gin.Params{{Key: "id", Value: campaignID}}
	c.Set("roles", []string{"admin"})
	c.Set("user_id", "launch-admin")
	s.handleLaunchAttestationCampaign(c)
	return w
}

func countItems(t *testing.T, s *Service, campaignID string) int {
	t.Helper()
	var n int
	if err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(context.Background()),
		`SELECT COUNT(*) FROM attestation_items WHERE campaign_id = $1::uuid`, campaignID).Scan(&n); err != nil {
		t.Fatalf("count items: %v", err)
	}
	return n
}

func campaignStatus(t *testing.T, s *Service, campaignID string) string {
	t.Helper()
	var status string
	if err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(context.Background()),
		`SELECT status FROM attestation_campaigns WHERE id = $1::uuid`, campaignID).Scan(&status); err != nil {
		t.Fatalf("read the campaign back: %v", err)
	}
	return status
}

func TestLaunchingACampaignClaimsItAndGeneratesItsItemsOnce(t *testing.T) {
	s, campaignID, cleanup := launchFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	w := launch(t, s, campaignID)
	if w.Code != http.StatusOK {
		t.Fatalf("launching a draft campaign answered %d: %s", w.Code, w.Body.String())
	}
	if got := countItems(t, s, campaignID); got != 1 {
		t.Fatalf("the launch generated %d items over one user-role assignment, want 1", got)
	}
	if got := campaignStatus(t, s, campaignID); got != "active" {
		t.Errorf("the campaign is %q after a successful launch, want active", got)
	}

	// A second launch is refused, and generates nothing.
	w2 := launch(t, s, campaignID)
	if w2.Code != http.StatusBadRequest {
		t.Errorf("a second launch answered %d, want 400: %s", w2.Code, w2.Body.String())
	}
	if got := countItems(t, s, campaignID); got != 1 {
		t.Errorf("after a refused second launch the campaign has %d items; every reviewer now sees "+
			"the same entitlement twice and the campaign can never be reconciled against its scope", got)
	}
}

// A campaign the database will not let us claim must not have items generated
// against it. This is the case that used to answer "Campaign launched" over a
// campaign still sitting in 'draft'.
func TestACampaignThatCannotBeClaimedGeneratesNoItems(t *testing.T) {
	s, campaignID, cleanup := launchFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	ctx := orgctx.WithBypassRLS(context.Background())
	if _, err := s.db.Pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION refuse_campaign_claim() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refused by test'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER refuse_campaign_claim_trg BEFORE UPDATE ON attestation_campaigns
		FOR EACH ROW WHEN (NEW.status IS DISTINCT FROM OLD.status)
		EXECUTE FUNCTION refuse_campaign_claim();`); err != nil {
		t.Fatalf("install refusal trigger: %v", err)
	}
	defer s.db.Pool.Exec(ctx, `DROP TRIGGER IF EXISTS refuse_campaign_claim_trg ON attestation_campaigns`)

	w := launch(t, s, campaignID)
	if w.Code == http.StatusOK {
		t.Errorf("the campaign could not be moved out of 'draft' and the launch was answered %d: %s. "+
			"The operator is told the campaign is running while it still shows as a draft, and the "+
			"next launch will generate every item a second time.", w.Code, w.Body.String())
	}
	if got := countItems(t, s, campaignID); got != 0 {
		t.Errorf("%d attestation items were generated for a campaign that was never launched", got)
	}
	if got := campaignStatus(t, s, campaignID); got != "draft" {
		t.Errorf("the campaign is %q, want draft", got)
	}
}

// Two operators pressing Launch at the same moment. No database failure is
// needed for the old shape to double the items: both requests read 'draft'
// before either wrote.
func TestConcurrentLaunchesGenerateOneSetOfItems(t *testing.T) {
	s, campaignID, cleanup := launchFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	const racers = 6
	var mu sync.Mutex
	accepted := 0
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if launch(t, s, campaignID).Code == http.StatusOK {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if accepted != 1 {
		t.Errorf("%d of %d simultaneous launches were accepted; exactly one may be", accepted, racers)
	}
	if got := countItems(t, s, campaignID); got != 1 {
		t.Errorf("%d attestation items exist over one user-role assignment after %d simultaneous "+
			"launches; a reviewer is asked to certify the same entitlement %d times", got, racers, got)
	}
}
