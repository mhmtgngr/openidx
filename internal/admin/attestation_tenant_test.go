package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// attFixture seeds two organizations, a user in each, and one draft campaign
// per organization carrying one pending item.
//
// Every handler runs under orgctx.WithBypassRLS. That is deliberate: v61 belts
// both attestation tables, so with the belt on, a missing org predicate is
// invisible — the database supplies the scope and the test passes whether or
// not the SQL says anything. Under a bypass the belt is off and the query's own
// predicates are the only thing left, which is what these tests are about.
type attFixture struct {
	t    *testing.T
	db   *database.PostgresDB
	svc  *Service
	ctx  context.Context
	orgA string
	orgB string
	// userA2 is a second enabled user of org A: a legitimate delegate.
	userA2 string
	// userB is org B's user: the illegitimate delegate.
	userB       string
	campaignA   string
	campaignB   string
	itemA       string
	itemB       string
	origReviewA string
}

func newAttFixture(t *testing.T) (*attFixture, func()) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return nil, func() {}
	}

	f := &attFixture{
		t:   t,
		db:  db,
		svc: &Service{db: db, logger: zap.NewNop()},
		ctx: orgctx.WithBypassRLS(context.Background()),
	}
	f.orgA = f.seedOrg("att-org-a")
	f.orgB = f.seedOrg("att-org-b")
	f.seedUser("att-a-admin", f.orgA, true)
	f.userA2 = f.seedUser("att-a-reviewer", f.orgA, true)
	f.userB = f.seedUser("att-b-reviewer", f.orgB, true)

	f.campaignA, f.itemA, f.origReviewA = f.seedCampaign(f.orgA, "campaign-a")
	f.campaignB, f.itemB, _ = f.seedCampaign(f.orgB, "campaign-b")
	return f, cleanup
}

func (f *attFixture) seedOrg(slug string) string {
	f.t.Helper()
	var id string
	if err := f.db.Pool.QueryRow(f.ctx,
		"INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text", slug).Scan(&id); err != nil {
		f.t.Fatalf("seed org %s: %v", slug, err)
	}
	return id
}

func (f *attFixture) seedUser(name, org string, enabled bool) string {
	f.t.Helper()
	var id string
	if err := f.db.Pool.QueryRow(f.ctx, `
		INSERT INTO users (username, email, enabled, org_id)
		VALUES ($1::varchar, $1::varchar || '@att.test', $3, $2::uuid) RETURNING id::text`,
		name, org, enabled).Scan(&id); err != nil {
		f.t.Fatalf("seed user %s: %v", name, err)
	}
	return id
}

// seedCampaign creates a draft campaign with one pending item, and returns the
// campaign id, the item id, and the item's reviewer_id as stored.
func (f *attFixture) seedCampaign(org, name string) (string, string, string) {
	f.t.Helper()
	var campaign string
	if err := f.db.Pool.QueryRow(f.ctx, `
		INSERT INTO attestation_campaigns (org_id, name, description, campaign_type, scope, reviewer_strategy, status)
		VALUES ($1::uuid, $2, 'seeded', 'role_certification', '{}'::jsonb, 'manager', 'draft')
		RETURNING id::text`, org, name).Scan(&campaign); err != nil {
		f.t.Fatalf("seed campaign %s: %v", name, err)
	}
	reviewer := f.seedUser(name+"-owner", org, true)
	var item string
	if err := f.db.Pool.QueryRow(f.ctx, `
		INSERT INTO attestation_items (campaign_id, org_id, reviewer_id, resource_type, resource_name, decision)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'role', 'seeded', 'pending')
		RETURNING id::text`, campaign, org, reviewer).Scan(&item); err != nil {
		f.t.Fatalf("seed item for %s: %v", name, err)
	}
	return campaign, item, reviewer
}

// call drives one handler as an admin of org, under a bypass context.
func (f *attFixture) call(org, method, path string, params gin.Params, body any, fn func(*gin.Context)) *httptest.ResponseRecorder {
	f.t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	c.Request = httptest.NewRequest(method, path, rdr).
		WithContext(orgctx.With(orgctx.WithBypassRLS(context.Background()), orgctx.Org{ID: org}))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("roles", []string{"admin"})
	c.Set("user_id", "00000000-0000-0000-0000-000000000001")
	c.Params = params
	fn(c)
	return w
}

func (f *attFixture) itemState(id string) (decision string, reviewer string) {
	f.t.Helper()
	if err := f.db.Pool.QueryRow(f.ctx,
		"SELECT decision, COALESCE(reviewer_id::text, '') FROM attestation_items WHERE id = $1", id,
	).Scan(&decision, &reviewer); err != nil {
		f.t.Fatalf("read item %s: %v", id, err)
	}
	return decision, reviewer
}

// TestAttestationDelegateRequiresAnInOrgReviewer covers the check this handler
// never made.
//
// handleDelegateAttestationItem took delegate_to straight from the request body
// and wrote it onto reviewer_id and delegated_to with no validation at all: not
// that it named a user, not that the user was enabled, not that the user
// belonged to the caller's organization. An administrator could therefore hand
// an access-certification item to a reviewer of another tenant.
//
// The cost is not a disclosure — the delegate cannot see the item, because
// handleListAttestationItems reads reviewers through an org-scoped join, so the
// item renders with a blank reviewer name. The cost is that the item can never
// be decided, and a campaign auto-completes only when its pending count reaches
// zero, so one delegation freezes the certification permanently. That is a
// governance control reporting a state it cannot reach.
func TestAttestationDelegateRequiresAnInOrgReviewer(t *testing.T) {
	f, cleanup := newAttFixture(t)
	if f == nil {
		return
	}
	defer cleanup()

	delegate := func(org, campaign, item, to string) *httptest.ResponseRecorder {
		return f.call(org, http.MethodPost,
			"/attestation-campaigns/"+campaign+"/items/"+item+"/delegate",
			gin.Params{{Key: "id", Value: campaign}, {Key: "itemId", Value: item}},
			map[string]string{"delegate_to": to},
			f.svc.handleDelegateAttestationItem)
	}

	t.Run("a reviewer in another organization is refused", func(t *testing.T) {
		w := delegate(f.orgA, f.campaignA, f.itemA, f.userB)
		if w.Code != http.StatusBadRequest {
			t.Errorf("delegating org A's item to org B's user returned %d, want 400. "+
				"The delegate cannot see the item, so it stays pending for ever and the "+
				"campaign never completes; body = %s", w.Code, w.Body.String())
		}
		if _, reviewer := f.itemState(f.itemA); reviewer != f.origReviewA {
			t.Errorf("reviewer_id is now %q, want the original %q — the item was handed to another tenant",
				reviewer, f.origReviewA)
		}
	})

	t.Run("a uuid naming nobody is refused", func(t *testing.T) {
		w := delegate(f.orgA, f.campaignA, f.itemA, "00000000-0000-0000-0000-0000000000ff")
		if w.Code != http.StatusBadRequest {
			t.Errorf("delegating to a uuid that names no user returned %d, want 400", w.Code)
		}
	})

	t.Run("a value that is not a uuid is refused, not a 500", func(t *testing.T) {
		w := delegate(f.orgA, f.campaignA, f.itemA, "not-a-uuid")
		if w.Code != http.StatusBadRequest {
			t.Errorf("delegating to %q returned %d, want 400", "not-a-uuid", w.Code)
		}
	})

	t.Run("a disabled user of this organization is refused", func(t *testing.T) {
		disabled := f.seedUser("att-a-disabled", f.orgA, false)
		w := delegate(f.orgA, f.campaignA, f.itemA, disabled)
		if w.Code != http.StatusBadRequest {
			t.Errorf("delegating to a disabled user returned %d, want 400 — a disabled "+
				"reviewer stalls the item exactly as a foreign one does", w.Code)
		}
	})

	t.Run("an enabled user of this organization is accepted", func(t *testing.T) {
		w := delegate(f.orgA, f.campaignA, f.itemA, f.userA2)
		if w.Code != http.StatusOK {
			t.Fatalf("delegating to org A's own enabled user returned %d, want 200; "+
				"the org predicate must scope the check, not empty it. body = %s", w.Code, w.Body.String())
		}
		if _, reviewer := f.itemState(f.itemA); reviewer != f.userA2 {
			t.Errorf("reviewer_id = %q, want %q — the delegation did not take effect", reviewer, f.userA2)
		}
	})

	t.Run("another tenant cannot delegate this item", func(t *testing.T) {
		before, _ := f.itemState(f.itemA)
		w := delegate(f.orgB, f.campaignA, f.itemA, f.userB)
		if w.Code == http.StatusOK {
			t.Errorf("org B delegated org A's attestation item (200)")
		}
		if after, _ := f.itemState(f.itemA); after != before {
			t.Errorf("org B changed org A's item (%q -> %q)", before, after)
		}
	})
}

// TestAttestationIsTenantScopedWithoutTheBelt drives the campaign and item
// surfaces under an explicit RLS bypass, so that only the predicates written in
// the SQL are doing the scoping.
func TestAttestationIsTenantScopedWithoutTheBelt(t *testing.T) {
	f, cleanup := newAttFixture(t)
	if f == nil {
		return
	}
	defer cleanup()

	t.Run("the list shows only this organization's campaigns", func(t *testing.T) {
		w := f.call(f.orgA, http.MethodGet, "/attestation-campaigns", nil, nil,
			f.svc.handleListAttestationCampaigns)
		if w.Code != http.StatusOK {
			t.Fatalf("list returned %d: %s", w.Code, w.Body.String())
		}
		var body struct {
			Data []AttestationCampaign `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		for _, ac := range body.Data {
			if ac.ID == f.campaignB {
				t.Errorf("org A's campaign list contains org B's campaign %q", ac.Name)
			}
		}
		if len(body.Data) != 1 {
			t.Errorf("org A sees %d campaigns, want exactly its own 1", len(body.Data))
		}
	})

	// A campaign whose description is NULL used to fall out of the list: the
	// scan into a string failed and the loop's `continue` swallowed it. The
	// create path always writes "", so no campaign made through the API can be
	// in that state — but nothing in the read said so, and a certification
	// disappearing from its own list is not a failure mode to leave standing.
	t.Run("a campaign with no description is still listed", func(t *testing.T) {
		var id string
		if err := f.db.Pool.QueryRow(f.ctx, `
			INSERT INTO attestation_campaigns (org_id, name, campaign_type, scope, reviewer_strategy, status)
			VALUES ($1::uuid, 'no-description', 'role_certification', '{}'::jsonb, 'manager', 'draft')
			RETURNING id::text`, f.orgA).Scan(&id); err != nil {
			t.Fatalf("seed description-less campaign: %v", err)
		}
		w := f.call(f.orgA, http.MethodGet, "/attestation-campaigns", nil, nil,
			f.svc.handleListAttestationCampaigns)
		var body struct {
			Data []AttestationCampaign `json:"data"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		found := false
		for _, ac := range body.Data {
			if ac.ID == id {
				found = true
			}
		}
		if !found {
			t.Error("a campaign with a NULL description is missing from the list it belongs to")
		}
	})

	t.Run("another organization's campaign is not found", func(t *testing.T) {
		w := f.call(f.orgA, http.MethodGet, "/attestation-campaigns/"+f.campaignB,
			gin.Params{{Key: "id", Value: f.campaignB}}, nil, f.svc.handleGetAttestationCampaign)
		if w.Code != http.StatusNotFound {
			t.Errorf("org A read org B's campaign (%d): %s", w.Code, w.Body.String())
		}
	})

	t.Run("progress on another organization's campaign counts nothing", func(t *testing.T) {
		w := f.call(f.orgA, http.MethodGet, "/attestation-campaigns/"+f.campaignB+"/progress",
			gin.Params{{Key: "id", Value: f.campaignB}}, nil, f.svc.handleAttestationProgress)
		var body struct {
			Total int `json:"total"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if body.Total != 0 {
			t.Errorf("org A counted %d of org B's attestation items", body.Total)
		}
	})

	t.Run("another organization's items are not listed", func(t *testing.T) {
		w := f.call(f.orgA, http.MethodGet, "/attestation-campaigns/"+f.campaignB+"/items",
			gin.Params{{Key: "id", Value: f.campaignB}}, nil, f.svc.handleListAttestationItems)
		var body struct {
			Data []AttestationItem `json:"data"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if len(body.Data) != 0 {
			t.Errorf("org A listed %d of org B's attestation items", len(body.Data))
		}
	})

	t.Run("another organization's item cannot be decided", func(t *testing.T) {
		w := f.call(f.orgA, http.MethodPost,
			"/attestation-campaigns/"+f.campaignB+"/items/"+f.itemB+"/decide",
			gin.Params{{Key: "id", Value: f.campaignB}, {Key: "itemId", Value: f.itemB}},
			map[string]string{"decision": "revoked", "comments": "x"},
			f.svc.handleDecideAttestationItem)
		if w.Code != http.StatusNotFound {
			t.Errorf("org A decided org B's certification item (%d): %s", w.Code, w.Body.String())
		}
		if decision, _ := f.itemState(f.itemB); decision != "pending" {
			t.Errorf("org B's item is now %q — another tenant recorded its certification decision", decision)
		}
	})

	t.Run("another organization's campaign cannot be launched", func(t *testing.T) {
		w := f.call(f.orgA, http.MethodPost, "/attestation-campaigns/"+f.campaignB+"/launch",
			gin.Params{{Key: "id", Value: f.campaignB}}, nil, f.svc.handleLaunchAttestationCampaign)
		if w.Code != http.StatusNotFound {
			t.Errorf("org A launched org B's campaign (%d): %s", w.Code, w.Body.String())
		}
		var status string
		_ = f.db.Pool.QueryRow(f.ctx,
			"SELECT status FROM attestation_campaigns WHERE id = $1", f.campaignB).Scan(&status)
		if status != "draft" {
			t.Errorf("org B's campaign is now %q — another tenant launched it", status)
		}
	})

	t.Run("another organization's campaign cannot be edited", func(t *testing.T) {
		w := f.call(f.orgA, http.MethodPut, "/attestation-campaigns/"+f.campaignB,
			gin.Params{{Key: "id", Value: f.campaignB}},
			map[string]string{"name": "renamed by org A"}, f.svc.handleUpdateAttestationCampaign)
		if w.Code != http.StatusNotFound {
			t.Errorf("org A edited org B's campaign (%d): %s", w.Code, w.Body.String())
		}
		var name string
		_ = f.db.Pool.QueryRow(f.ctx,
			"SELECT name FROM attestation_campaigns WHERE id = $1", f.campaignB).Scan(&name)
		if name != "campaign-b" {
			t.Errorf("org B's campaign is now named %q — another tenant renamed it", name)
		}
	})
}
