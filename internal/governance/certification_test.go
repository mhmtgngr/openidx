// Package governance provides unit tests for access certification campaign functionality
package governance

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// mockCertDB is a minimal mock for testing certification campaigns
type mockCertDB struct {
	database.PostgresDB
	campaigns       []CertificationCampaign
	items           []CertificationItem
	queryError      bool
	execError       bool
	createError     bool
	totalItems      int
	reviewedItems   int
	pendingCount    int
	autoRevoked     bool
}

func (m *mockCertDB) QueryRow(ctx context.Context, query string, args ...interface{}) pgxpool.Row {
	return &mockCertRow{m: m, query: query, args: args}
}

func (m *mockCertDB) Query(ctx context.Context, query string, args ...interface{}) (pgxpool.Rows, error) {
	if m.queryError {
		return nil, assert.AnError
	}
	return &mockCertRows{m: m, query: query, args: args}, nil
}

func (m *mockCertDB) Exec(ctx context.Context, query string, args ...interface{}) (interface{}, error) {
	if m.execError {
		return nil, assert.AnError
	}
	if m.createError {
		return nil, assert.AnError
	}
	return &mockCertResult{}, nil
}

type mockCertRow struct {
	m      *mockCertDB
	query  string
	args   []interface{}
	scanned bool
}

func (r *mockCertRow) Scan(dest ...interface{}) error {
	r.scanned = true
	query := r.query

	// Manager resolution
	if contains(query, "SELECT manager_id FROM users") {
		if len(dest) > 0 {
			if p, ok := dest[0].(*string); ok {
				*p = "manager-1"
			}
		}
		return nil
	}

	// Resource owner lookup
	if contains(query, "SELECT owner_id FROM entitlement_metadata") {
		if len(dest) > 0 {
			if p, ok := dest[0].(*string); ok {
				*p = "owner-1"
			}
		}
		return nil
	}

	// Role-based reviewer lookup
	if contains(query, "SELECT user_id FROM user_roles") {
		if len(dest) > 0 {
			if p, ok := dest[0].(*string); ok {
				*p = "role-user-1"
			}
		}
		return nil
	}

	// Campaign lookup
	if contains(query, "SELECT id, name") && contains(query, "certification_campaigns") {
		if len(r.m.campaigns) > 0 && len(dest) >= 16 {
			c := r.m.campaigns[0]
			setString(dest, 0, c.ID)
			setString(dest, 1, c.Name)
			setString(dest, 2, c.Description)
			setString(dest, 3, string(c.Status))
			setBytes(dest, 4, mustMarshalJSON(c.Scope))
			setBytes(dest, 5, mustMarshalJSON(c.Reviewers))
			setTime(dest, 6, c.Deadline)
			setString(dest, 7, c.CreatedBy)
			setTime(dest, 8, c.CreatedAt)
			setTime(dest, 9, c.UpdatedAt)
			setTimePtr(dest, 10, c.StartedAt)
			setTimePtr(dest, 11, c.CompletedAt)
			setInt(dest, 12, c.TotalItems)
			setInt(dest, 13, c.ReviewedItems)
			setBool(dest, 14, c.AutoRevoke)
			setInt(dest, 15, c.GracePeriodDays)
			return nil
		}
		return assert.AnError
	}

	// Status check
	if contains(query, "SELECT status FROM certification_campaigns") {
		if len(r.m.campaigns) > 0 && len(dest) > 0 {
			setString(dest, 0, string(r.m.campaigns[0].Status))
			return nil
		}
		return assert.AnError
	}

	// Pending item count
	if contains(query, "SELECT COUNT(*) FROM certification_items") && contains(query, "decision = 'pending'") {
		if len(dest) > 0 {
			setInt(dest, 0, r.m.pendingCount)
		}
		return nil
	}

	// Total count
	if contains(query, "SELECT COUNT(*) FROM certification_items") {
		if len(dest) > 0 {
			setInt(dest, 0, r.m.totalItems)
		}
		return nil
	}

	// Reviewed count
	if contains(query, "SELECT COUNT(*) FROM certification_items") && contains(query, "decision != 'pending'") {
		if len(dest) > 0 {
			setInt(dest, 0, r.m.reviewedItems)
		}
		return nil
	}

	// Item lookup for review
	if contains(query, "SELECT reviewer_id, decision FROM certification_items") {
		if len(r.m.items) > 0 && len(dest) >= 2 {
			setString(dest, 0, r.m.items[0].ReviewerID)
			setString(dest, 1, string(r.m.items[0].Decision))
			return nil
		}
		return assert.AnError
	}

	// Check admin role
	if contains(query, "SELECT EXISTS") && contains(query, "admin") {
		if len(dest) > 0 {
			setBool(dest, 0, true)
		}
		return nil
	}

	return nil
}

type mockCertRows struct {
	m        *mockCertDB
	query    string
	args     []interface{}
	index    int
	closed   bool
}

func (r *mockCertRows) Close() {
	r.closed = true
}

func (r *mockCertRows) Next() bool {
	r.index++
	// Return at most one row for simplicity
	return r.index == 1
}

func (r *mockCertRows) Scan(dest ...interface{}) error {
	query := r.query

	// Role assignments for generating review items
	if contains(query, "SELECT ur.user_id") && contains(query, "user_roles ur") {
		setString(dest, 0, "user-1")
		setString(dest, 1, "user1")
		setString(dest, 2, "role-1")
		setString(dest, 3, "Admin Role")
		setTime(dest, 4, time.Now().Add(-30*24*time.Hour))
		return nil
	}

	// Campaign items query
	if contains(query, "SELECT id, campaign_id") && contains(query, "certification_items") {
		if len(r.m.items) > 0 {
			item := r.m.items[0]
			setString(dest, 0, item.ID)
			setString(dest, 1, item.CampaignID)
			setString(dest, 2, item.UserID)
			setString(dest, 3, item.ResourceType)
			setString(dest, 4, item.ResourceID)
			setString(dest, 5, item.ReviewerID)
			setString(dest, 6, string(item.Decision))
			setString(dest, 7, item.Comments)
			setTimePtr(dest, 8, item.ReviewedAt)
			setTime(dest, 9, item.CreatedAt)
			return nil
		}
		return assert.AnError
	}

	// Reviewer items query
	if contains(query, "certification_items ci") && contains(query, "users u") && contains(query, "approver_id = $1") {
		setString(dest, 0, "item-1")
		setString(dest, 1, "campaign-1")
		setString(dest, 2, "user-1")
		setString(dest, 3, "User One")
		setString(dest, 4, "role")
		setString(dest, 5, "role-1")
		setString(dest, 6, "Admin Role")
		setString(dest, 7, "reviewer-1")
		setString(dest, 8, "Reviewer One")
		setString(dest, 9, string(DecisionPending))
		setString(dest, 10, "")
		setTimePtr(dest, 11, nil)
		setTime(dest, 12, time.Now())
		return nil
	}

	// Expired campaigns query
	if contains(query, "SELECT id, auto_revoke FROM certification_campaigns") {
		setString(dest, 0, "campaign-1")
		setBool(dest, 1, r.m.autoRevoked)
		return nil
	}

	// Pending items for revocation
	if contains(query, "SELECT id, user_id, resource_type, resource_id FROM certification_items") {
		setString(dest, 0, "item-1")
		setString(dest, 1, "user-1")
		setString(dest, 2, "role")
		setString(dest, 3, "role-1")
		return nil
	}

	// List campaigns
	if contains(query, "SELECT id, name") && contains(query, "certification_campaigns") && !contains(query, "WHERE") {
		if len(r.m.campaigns) > 0 && len(dest) >= 16 {
			c := r.m.campaigns[0]
			setString(dest, 0, c.ID)
			setString(dest, 1, c.Name)
			setString(dest, 2, c.Description)
			setString(dest, 3, string(c.Status))
			setBytes(dest, 4, mustMarshalJSON(c.Scope))
			setBytes(dest, 5, mustMarshalJSON(c.Reviewers))
			setTime(dest, 6, c.Deadline)
			setString(dest, 7, c.CreatedBy)
			setTime(dest, 8, c.CreatedAt)
			setTime(dest, 9, c.UpdatedAt)
			setTimePtr(dest, 10, c.StartedAt)
			setTimePtr(dest, 11, c.CompletedAt)
			setInt(dest, 12, c.TotalItems)
			setInt(dest, 13, c.ReviewedItems)
			setBool(dest, 14, c.AutoRevoke)
			setInt(dest, 15, c.GracePeriodDays)
			return nil
		}
		return assert.AnError
	}

	return nil
}

type mockCertResult struct {
	rowsAffected int64
}

func (m *mockCertResult) RowsAffected() int64 {
	return m.rowsAffected
}

func setBool(dest []interface{}, idx int, val bool) {
	if idx >= len(dest) {
		return
	}
	if p, ok := dest[idx].(*bool); ok {
		*p = val
	}
}

func setTimePtr(dest []interface{}, idx int, val *time.Time) {
	if idx >= len(dest) {
		return
	}
	if p, ok := dest[idx].(**time.Time); ok {
		*p = val
	}
}

func mustMarshalJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestCreateCampaign(t *testing.T) {
	t.Run("valid campaign creation", func(t *testing.T) {
		db := &mockCertDB{
			campaigns: []CertificationCampaign{},
			items:     []CertificationItem{},
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		scope := CampaignScope{
			ResourceTypes: []string{"role"},
			ResourceIDs:   []string{},
			UserIDs:       []string{},
		}

		reviewers := []CampaignReviewer{
			{Type: "manager", ID: ""},
			{Type: "user", ID: "reviewer-1"},
		}

		deadline := time.Now().Add(30 * 24 * time.Hour)

		campaign, err := svc.CreateCampaign(context.Background(),
			"Q1 Access Review",
			"Quarterly review of all admin access",
			"admin-1",
			scope,
			reviewers,
			deadline,
			true, // autoRevoke
			7)   // gracePeriodDays

		require.NoError(t, err)
		assert.NotNil(t, campaign)
		assert.Equal(t, "Q1 Access Review", campaign.Name)
		assert.Equal(t, CampaignStatusDraft, campaign.Status)
		assert.True(t, campaign.AutoRevoke)
		assert.Equal(t, 7, campaign.GracePeriodDays)
		assert.Equal(t, "admin-1", campaign.CreatedBy)
	})

	t.Run("campaign without name fails", func(t *testing.T) {
		db := &mockCertDB{
			campaigns: []CertificationCampaign{},
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		scope := CampaignScope{ResourceTypes: []string{"role"}}
		reviewers := []CampaignReviewer{{Type: "manager", ID: ""}}
		deadline := time.Now().Add(24 * time.Hour)

		_, err := svc.CreateCampaign(context.Background(),
			"", "description", "admin-1", scope, reviewers, deadline, false, 0)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name")
	})

	t.Run("campaign without reviewers fails", func(t *testing.T) {
		db := &mockCertDB{
			campaigns: []CertificationCampaign{},
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		scope := CampaignScope{ResourceTypes: []string{"role"}}
		reviewers := []CampaignReviewer{}
		deadline := time.Now().Add(24 * time.Hour)

		_, err := svc.CreateCampaign(context.Background(),
			"Test", "description", "admin-1", scope, reviewers, deadline, false, 0)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "reviewer")
	})

	t.Run("campaign with past deadline fails", func(t *testing.T) {
		db := &mockCertDB{
			campaigns: []CertificationCampaign{},
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		scope := CampaignScope{ResourceTypes: []string{"role"}}
		reviewers := []CampaignReviewer{{Type: "manager", ID: ""}}
		deadline := time.Now().Add(-1 * time.Hour) // Past

		_, err := svc.CreateCampaign(context.Background(),
			"Test", "description", "admin-1", scope, reviewers, deadline, false, 0)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "future")
	})
}

func TestStartCampaign(t *testing.T) {
	t.Run("start draft campaign generates review items", func(t *testing.T) {
		campaign := &CertificationCampaign{
			ID:          "campaign-1",
			Name:        "Test Campaign",
			Status:      CampaignStatusDraft,
			Scope:       CampaignScope{ResourceTypes: []string{"role"}},
			Reviewers:   []CampaignReviewer{{Type: "manager", ID: ""}},
			Deadline:    time.Now().Add(30 * 24 * time.Hour),
			CreatedBy:   "admin-1",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			AutoRevoke:  true,
			GracePeriodDays: 7,
		}

		db := &mockCertDB{
			campaigns:  []CertificationCampaign{*campaign},
			items:      []CertificationItem{},
			totalItems: 5, // Simulate 5 role assignments found
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		err := svc.StartCampaign(context.Background(), "campaign-1")

		require.NoError(t, err)
		// In a real scenario, items would be generated
	})

	t.Run("cannot start non-draft campaign", func(t *testing.T) {
		campaign := &CertificationCampaign{
			ID:        "campaign-1",
			Name:      "Active Campaign",
			Status:    CampaignStatusActive,
			CreatedAt: time.Now(),
		}

		db := &mockCertDB{
			campaigns: []CertificationCampaign{*campaign},
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		err := svc.StartCampaign(context.Background(), "campaign-1")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not in draft")
	})
}

func TestReviewItem(t *testing.T) {
	t.Run("confirm certification item", func(t *testing.T) {
		item := CertificationItem{
			ID:           "item-1",
			CampaignID:   "campaign-1",
			UserID:       "user-1",
			ResourceType: "role",
			ResourceID:   "role-1",
			ReviewerID:   "reviewer-1",
			Decision:     DecisionPending,
			CreatedAt:    time.Now(),
		}

		db := &mockCertDB{
			items:     []CertificationItem{item},
			totalItems: 10,
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		err := svc.ReviewItem(context.Background(), "item-1", DecisionConfirm, "reviewer-1", "Access still needed")

		require.NoError(t, err)
	})

	t.Run("revoke certification item", func(t *testing.T) {
		item := CertificationItem{
			ID:           "item-1",
			CampaignID:   "campaign-1",
			UserID:       "user-1",
			ResourceType: "role",
			ResourceID:   "role-1",
			ReviewerID:   "reviewer-1",
			Decision:     DecisionPending,
			CreatedAt:    time.Now(),
		}

		db := &mockCertDB{
			items: []CertificationItem{item},
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		err := svc.ReviewItem(context.Background(), "item-1", DecisionRevoke, "reviewer-1", "No longer needed")

		require.NoError(t, err)
	})

	t.Run("modify certification item", func(t *testing.T) {
		item := CertificationItem{
			ID:           "item-1",
			CampaignID:   "campaign-1",
			UserID:       "user-1",
			ResourceType: "role",
			ResourceID:   "role-1",
			ReviewerID:   "reviewer-1",
			Decision:     DecisionPending,
			CreatedAt:    time.Now(),
		}

		db := &mockCertDB{
			items: []CertificationItem{item},
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		err := svc.ReviewItem(context.Background(), "item-1", DecisionModify, "reviewer-1", "Change to read-only")

		require.NoError(t, err)
	})
}

func TestCompletionPercentage(t *testing.T) {
	t.Run("calculate completion percentage", func(t *testing.T) {
		db := &mockCertDB{
			totalItems:    100,
			reviewedItems: 75,
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		pct, err := svc.GetCompletionPercentage(context.Background(), "campaign-1")

		require.NoError(t, err)
		assert.Equal(t, 75.0, pct)
	})

	t.Run("zero items returns zero percent", func(t *testing.T) {
		db := &mockCertDB{
			totalItems: 0,
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		pct, err := svc.GetCompletionPercentage(context.Background(), "campaign-1")

		require.NoError(t, err)
		assert.Equal(t, 0.0, pct)
	})

	t.Run("all items reviewed returns 100 percent", func(t *testing.T) {
		db := &mockCertDB{
			totalItems:    50,
			reviewedItems: 50,
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		pct, err := svc.GetCompletionPercentage(context.Background(), "campaign-1")

		require.NoError(t, err)
		assert.Equal(t, 100.0, pct)
	})
}

func TestCompleteCampaign(t *testing.T) {
	t.Run("complete campaign with all items reviewed", func(t *testing.T) {
		campaign := &CertificationCampaign{
			ID:            "campaign-1",
			Name:          "Test Campaign",
			Status:        CampaignStatusActive,
			TotalItems:    10,
			ReviewedItems: 10,
			CreatedAt:     time.Now(),
		}

		db := &mockCertDB{
			campaigns:    []CertificationCampaign{*campaign},
			pendingCount: 0, // No pending items
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		err := svc.CompleteCampaign(context.Background(), "campaign-1")

		require.NoError(t, err)
	})

	t.Run("cannot complete with pending items", func(t *testing.T) {
		campaign := &CertificationCampaign{
			ID:            "campaign-1",
			Name:          "Test Campaign",
			Status:        CampaignStatusActive,
			TotalItems:    10,
			ReviewedItems: 7,
		}

		db := &mockCertDB{
			campaigns:    []CertificationCampaign{*campaign},
			pendingCount: 3, // 3 pending items
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		err := svc.CompleteCampaign(context.Background(), "campaign-1")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "pending items")
	})
}

func TestProcessExpiredCampaigns(t *testing.T) {
	t.Run("expired campaign with auto-revoke", func(t *testing.T) {
		db := &mockCertDB{
			campaigns: []CertificationCampaign{
				{
					ID:         "campaign-1",
					Name:       "Expired Campaign",
					Status:     CampaignStatusActive,
					Deadline:   time.Now().Add(-1 * time.Hour), // Past
					AutoRevoke: true,
					CreatedAt:  time.Now(),
				},
			},
			items: []CertificationItem{
				{
					ID:           "item-1",
					CampaignID:   "campaign-1",
					UserID:       "user-1",
					ResourceType: "role",
					ResourceID:   "role-1",
					Decision:     DecisionPending,
					CreatedAt:    time.Now(),
				},
			},
			autoRevoked: true,
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		err := svc.ProcessExpiredCampaigns(context.Background())

		require.NoError(t, err)
		// In real scenario, items would be revoked
	})

	t.Run("expired campaign without auto-revoke", func(t *testing.T) {
		db := &mockCertDB{
			campaigns: []CertificationCampaign{
				{
					ID:         "campaign-1",
					Name:       "Expired Campaign",
					Status:     CampaignStatusActive,
					Deadline:   time.Now().Add(-1 * time.Hour),
					AutoRevoke: false,
					CreatedAt:  time.Now(),
				},
			},
			autoRevoked: false,
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		err := svc.ProcessExpiredCampaigns(context.Background())

		require.NoError(t, err)
		// Items should not be revoked
	})
}

func TestDeleteCampaign(t *testing.T) {
	t.Run("delete draft campaign", func(t *testing.T) {
		campaign := &CertificationCampaign{
			ID:        "campaign-1",
			Name:      "Draft Campaign",
			Status:    CampaignStatusDraft,
			CreatedAt: time.Now(),
		}

		db := &mockCertDB{
			campaigns: []CertificationCampaign{*campaign},
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		err := svc.DeleteCampaign(context.Background(), "campaign-1")

		require.NoError(t, err)
	})

	t.Run("cannot delete active campaign", func(t *testing.T) {
		campaign := &CertificationCampaign{
			ID:        "campaign-1",
			Name:      "Active Campaign",
			Status:    CampaignStatusActive,
			CreatedAt: time.Now(),
		}

		db := &mockCertDB{
			campaigns: []CertificationCampaign{*campaign},
		}
		logger := zap.NewNop()
		svc := NewCertificationService(&database.PostgresDB{}, logger)
		svc.db = db

		err := svc.DeleteCampaign(context.Background(), "campaign-1")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "draft")
	})
}

func TestReviewDecision(t *testing.T) {
	t.Run("all review decisions defined", func(t *testing.T) {
		decisions := []ReviewDecision{
			DecisionConfirm,
			DecisionRevoke,
			DecisionModify,
			DecisionPending,
		}

		for _, d := range decisions {
			assert.NotEmpty(t, string(d), "Decision should not be empty")
		}
	})
}

func TestCampaignStatus(t *testing.T) {
	t.Run("all campaign statuses defined", func(t *testing.T) {
		statuses := []CampaignStatus{
			CampaignStatusDraft,
			CampaignStatusActive,
			CampaignStatusCompleted,
			CampaignStatusExpired,
			CampaignStatusCancelled,
		}

		for _, s := range statuses {
			assert.NotEmpty(t, string(s), "Status should not be empty")
		}
	})
}

func TestCampaignScope(t *testing.T) {
	t.Run("campaign scope filters", func(t *testing.T) {
		scope := CampaignScope{
			ResourceTypes: []string{"role", "group", "application"},
			ResourceIDs:   []string{"role-1", "role-2"},
			UserIDs:       []string{"user-1", "user-2"},
			OUPaths:       []string{"/engineering", "/sales"},
			Tags:          []string{"critical", "pii"},
		}

		assert.Equal(t, 3, len(scope.ResourceTypes))
		assert.Equal(t, 2, len(scope.ResourceIDs))
		assert.Equal(t, 2, len(scope.UserIDs))
		assert.Equal(t, 2, len(scope.OUPaths))
		assert.Equal(t, 2, len(scope.Tags))
	})
}

func TestCampaignReviewer(t *testing.T) {
	t.Run("reviewer types", func(t *testing.T) {
		reviewers := []CampaignReviewer{
			{Type: "manager", ID: ""},
			{Type: "user", ID: "reviewer-1"},
			{Type: "role", ID: "compliance-role"},
			{Type: "resource_owner", ID: ""},
		}

		for _, r := range reviewers {
			assert.NotEmpty(t, r.Type, "Reviewer type should not be empty")
		}
	})
}
