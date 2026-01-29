package governance

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestAccessReviewSerialization verifies AccessReview JSON marshaling
func TestAccessReviewSerialization(t *testing.T) {
	now := time.Now()
	review := &AccessReview{
		ID:            "rev-001",
		Name:          "Q1 User Access Review",
		Description:   "Quarterly access certification",
		Type:          ReviewTypeUserAccess,
		Status:        ReviewStatusPending,
		ReviewerID:    "admin-001",
		Scope:         ReviewScope{Users: []string{"user-1", "user-2"}, Groups: []string{"group-1"}},
		StartDate:     now,
		EndDate:       now.AddDate(0, 0, 14),
		CreatedAt:     now,
		TotalItems:    10,
		ReviewedItems: 0,
	}

	data, err := json.Marshal(review)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	var decoded AccessReview
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "rev-001", decoded.ID)
	assert.Equal(t, ReviewTypeUserAccess, decoded.Type)
	assert.Equal(t, ReviewStatusPending, decoded.Status)
	assert.Len(t, decoded.Scope.Users, 2)
	assert.Len(t, decoded.Scope.Groups, 1)
	assert.Equal(t, 10, decoded.TotalItems)
	assert.Equal(t, 0, decoded.ReviewedItems)
	assert.Nil(t, decoded.CompletedAt)
}

// TestReviewTypes verifies all review type constants
func TestReviewTypes(t *testing.T) {
	types := []ReviewType{
		ReviewTypeUserAccess,
		ReviewTypeRoleAssignment,
		ReviewTypeApplicationAccess,
		ReviewTypePrivilegedAccess,
	}

	assert.Len(t, types, 4)
	assert.Equal(t, ReviewType("user_access"), ReviewTypeUserAccess)
	assert.Equal(t, ReviewType("role_assignment"), ReviewTypeRoleAssignment)
	assert.Equal(t, ReviewType("application_access"), ReviewTypeApplicationAccess)
	assert.Equal(t, ReviewType("privileged_access"), ReviewTypePrivilegedAccess)
}

// TestReviewStatuses verifies all review status constants
func TestReviewStatuses(t *testing.T) {
	statuses := []ReviewStatus{
		ReviewStatusPending,
		ReviewStatusInProgress,
		ReviewStatusCompleted,
		ReviewStatusExpired,
		ReviewStatusCanceled,
	}

	assert.Len(t, statuses, 5)
	assert.Equal(t, ReviewStatus("pending"), ReviewStatusPending)
	assert.Equal(t, ReviewStatus("in_progress"), ReviewStatusInProgress)
	assert.Equal(t, ReviewStatus("completed"), ReviewStatusCompleted)
	assert.Equal(t, ReviewStatus("expired"), ReviewStatusExpired)
	assert.Equal(t, ReviewStatus("canceled"), ReviewStatusCanceled)
}

// TestReviewDecisions verifies all decision constants
func TestReviewDecisions(t *testing.T) {
	decisions := []ReviewDecision{
		ReviewDecisionPending,
		ReviewDecisionApproved,
		ReviewDecisionRevoked,
		ReviewDecisionFlagged,
	}

	assert.Len(t, decisions, 4)
	assert.Equal(t, ReviewDecision("pending"), ReviewDecisionPending)
	assert.Equal(t, ReviewDecision("approved"), ReviewDecisionApproved)
	assert.Equal(t, ReviewDecision("revoked"), ReviewDecisionRevoked)
	assert.Equal(t, ReviewDecision("flagged"), ReviewDecisionFlagged)
}

// TestReviewItemSerialization verifies ReviewItem JSON
func TestReviewItemSerialization(t *testing.T) {
	now := time.Now()
	item := &ReviewItem{
		ID:           "item-001",
		ReviewID:     "rev-001",
		UserID:       "user-123",
		ResourceType: "role",
		ResourceID:   "role-admin",
		ResourceName: "Administrator",
		Decision:     ReviewDecisionApproved,
		DecidedBy:    "admin-001",
		DecidedAt:    &now,
		Comments:     "Access justified",
	}

	data, err := json.Marshal(item)
	assert.NoError(t, err)

	var decoded ReviewItem
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "item-001", decoded.ID)
	assert.Equal(t, "role", decoded.ResourceType)
	assert.Equal(t, ReviewDecisionApproved, decoded.Decision)
	assert.Equal(t, "admin-001", decoded.DecidedBy)
	assert.NotNil(t, decoded.DecidedAt)
	assert.Equal(t, "Access justified", decoded.Comments)
}

// TestPolicySerialization verifies Policy JSON
func TestPolicySerialization(t *testing.T) {
	policy := &Policy{
		ID:          "pol-001",
		Name:        "SoD: Finance",
		Description: "Separation of duties for finance roles",
		Type:        PolicyTypeSoD,
		Rules: []PolicyRule{
			{
				ID:        "rule-1",
				Condition: map[string]interface{}{"role1": "approver", "role2": "requester"},
				Effect:    "deny",
				Priority:  1,
			},
		},
		Enabled:  true,
		Priority: 10,
	}

	data, err := json.Marshal(policy)
	assert.NoError(t, err)

	var decoded Policy
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "pol-001", decoded.ID)
	assert.Equal(t, PolicyTypeSoD, decoded.Type)
	assert.True(t, decoded.Enabled)
	assert.Len(t, decoded.Rules, 1)
	assert.Equal(t, "deny", decoded.Rules[0].Effect)
}

// TestPolicyTypes verifies all policy type constants
func TestPolicyTypes(t *testing.T) {
	types := []PolicyType{
		PolicyTypeSoD,
		PolicyTypeRiskBased,
		PolicyTypeTimebound,
		PolicyTypeLocation,
	}

	assert.Len(t, types, 4)
	assert.Equal(t, PolicyType("separation_of_duty"), PolicyTypeSoD)
	assert.Equal(t, PolicyType("risk_based"), PolicyTypeRiskBased)
	assert.Equal(t, PolicyType("timebound"), PolicyTypeTimebound)
	assert.Equal(t, PolicyType("location"), PolicyTypeLocation)
}

// TestReviewScopeEmpty verifies empty scope marshals correctly
func TestReviewScopeEmpty(t *testing.T) {
	scope := ReviewScope{}

	data, err := json.Marshal(scope)
	assert.NoError(t, err)

	var decoded ReviewScope
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Nil(t, decoded.Users)
	assert.Nil(t, decoded.Groups)
	assert.Nil(t, decoded.Applications)
	assert.Nil(t, decoded.Roles)
}

// TestReviewScopeFull verifies scope with all fields
func TestReviewScopeFull(t *testing.T) {
	scope := ReviewScope{
		Users:        []string{"user-1", "user-2"},
		Groups:       []string{"group-1"},
		Applications: []string{"app-1", "app-2", "app-3"},
		Roles:        []string{"admin", "viewer"},
	}

	data, err := json.Marshal(scope)
	assert.NoError(t, err)

	var decoded ReviewScope
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Len(t, decoded.Users, 2)
	assert.Len(t, decoded.Groups, 1)
	assert.Len(t, decoded.Applications, 3)
	assert.Len(t, decoded.Roles, 2)
}

// TestAccessReviewCompletedAt verifies optional CompletedAt field
func TestAccessReviewCompletedAt(t *testing.T) {
	t.Run("nil CompletedAt", func(t *testing.T) {
		review := &AccessReview{ID: "rev-1", Status: ReviewStatusPending}
		data, err := json.Marshal(review)
		assert.NoError(t, err)

		var decoded AccessReview
		json.Unmarshal(data, &decoded)
		assert.Nil(t, decoded.CompletedAt)
	})

	t.Run("set CompletedAt", func(t *testing.T) {
		now := time.Now()
		review := &AccessReview{ID: "rev-2", Status: ReviewStatusCompleted, CompletedAt: &now}
		data, err := json.Marshal(review)
		assert.NoError(t, err)

		var decoded AccessReview
		json.Unmarshal(data, &decoded)
		assert.NotNil(t, decoded.CompletedAt)
	})
}

// TestPolicyRuleConditions verifies arbitrary condition maps
func TestPolicyRuleConditions(t *testing.T) {
	rule := PolicyRule{
		ID: "rule-1",
		Condition: map[string]interface{}{
			"field":    "department",
			"operator": "equals",
			"value":    "finance",
			"nested":   map[string]interface{}{"key": "val"},
		},
		Effect:   "deny",
		Priority: 1,
	}

	data, err := json.Marshal(rule)
	assert.NoError(t, err)

	var decoded PolicyRule
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "department", decoded.Condition["field"])
	assert.Equal(t, "deny", decoded.Effect)
}

// TestReviewProgressCalculation verifies review progress math
func TestReviewProgressCalculation(t *testing.T) {
	tests := []struct {
		name     string
		total    int
		reviewed int
		pct      float64
	}{
		{"empty review", 0, 0, 0},
		{"no progress", 10, 0, 0},
		{"half done", 10, 5, 50},
		{"completed", 10, 10, 100},
		{"partial", 3, 1, 33.33},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pct float64
			if tt.total > 0 {
				pct = float64(tt.reviewed) / float64(tt.total) * 100
			}
			if tt.name == "partial" {
				assert.InDelta(t, tt.pct, pct, 0.01)
			} else {
				assert.InDelta(t, tt.pct, pct, 0.001)
			}
		})
	}
}
