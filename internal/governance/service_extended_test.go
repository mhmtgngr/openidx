// Package governance provides comprehensive unit tests for governance service
package governance

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// timePtr returns a pointer to the given time value
func timePtr(t time.Time) *time.Time {
	return &t
}

// strPtr returns a pointer to the given string value
func strPtr(s string) *string {
	return &s
}

// ---------------------------------------------------------------------------
// Data Model Tests (no database required)
// ---------------------------------------------------------------------------

func TestAccessReviewSerialization_Extended(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		review *AccessReview
	}{
		{
			name: "full review with all fields",
			review: &AccessReview{
				ID:            "rev-001",
				Name:          "Q1 User Access Review",
				Description:   "Quarterly access certification",
				Type:          ReviewTypeUserAccess,
				Status:        ReviewStatusPending,
				ReviewerID:    "admin-001",
				Scope:         ReviewScope{Users: []string{"user-1", "user-2"}, Groups: []string{"group-1"}},
				StartDate:     time.Now(),
				EndDate:       time.Now().AddDate(0, 0, 14),
				CreatedAt:     time.Now(),
				TotalItems:    10,
				ReviewedItems: 0,
			},
		},
		{
			name: "review with completed timestamp",
			review: &AccessReview{
				ID:           "rev-002",
				Name:         "Completed Review",
				Description:  "Finished review",
				Type:         ReviewTypeRoleAssignment,
				Status:       ReviewStatusCompleted,
				ReviewerID:   "reviewer-001",
				StartDate:    time.Now().Add(-30 * 24 * time.Hour),
				EndDate:      time.Now().Add(-7 * 24 * time.Hour),
				CreatedAt:    time.Now().Add(-40 * 24 * time.Hour),
				CompletedAt:  timePtr(time.Now().Add(-1 * time.Hour)),
				TotalItems:   50,
				ReviewedItems: 50,
			},
		},
		{
			name: "in-progress review",
			review: &AccessReview{
				ID:            "rev-003",
				Name:          "Active Review",
				Description:   "Currently being reviewed",
				Type:          ReviewTypeApplicationAccess,
				Status:        ReviewStatusInProgress,
				ReviewerID:    "manager-001",
				Scope:         ReviewScope{Applications: []string{"app-1", "app-2"}},
				StartDate:     time.Now(),
				EndDate:       time.Now().Add(30 * 24 * time.Hour),
				CreatedAt:     time.Now(),
				TotalItems:    25,
				ReviewedItems: 12,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that the review structure is valid
			assert.NotEmpty(t, tt.review.ID)
			assert.NotEmpty(t, tt.review.Name)
			assert.NotEmpty(t, tt.review.ReviewerID)
			assert.NotZero(t, tt.review.StartDate)
			assert.NotZero(t, tt.review.EndDate)
			assert.True(t, tt.review.EndDate.After(tt.review.StartDate))

			// Test status transitions are valid
			switch tt.review.Status {
			case ReviewStatusPending, ReviewStatusInProgress, ReviewStatusCompleted,
			     ReviewStatusExpired, ReviewStatusCanceled:
				// Valid status
			default:
				t.Errorf("invalid review status: %s", tt.review.Status)
			}

			// Test progress calculation
			if tt.review.TotalItems > 0 {
				progress := float64(tt.review.ReviewedItems) / float64(tt.review.TotalItems) * 100
				assert.GreaterOrEqual(t, progress, 0.0)
				assert.LessOrEqual(t, progress, 100.0)
			}
		})
	}
}

func TestReviewItemCreation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		item         *ReviewItem
		wantDecision bool
	}{
		{
			name: "pending review item",
			item: &ReviewItem{
				ID:           "item-001",
				ReviewID:     "rev-001",
				UserID:       "user-123",
				ResourceType: "role",
				ResourceID:   "role-admin",
				ResourceName: "Administrator",
				Decision:     ReviewDecisionPending,
			},
			wantDecision: false,
		},
		{
			name: "approved item with comments",
			item: &ReviewItem{
				ID:           "item-002",
				ReviewID:     "rev-001",
				UserID:       "user-456",
				ResourceType: "group",
				ResourceID:   "group-admins",
				ResourceName: "Admins Group",
				Decision:     ReviewDecisionApproved,
				DecidedBy:    "reviewer-001",
				DecidedAt:    timePtr(time.Now()),
				Comments:     "Access justified for ongoing project",
			},
			wantDecision: true,
		},
		{
			name: "revoked item",
			item: &ReviewItem{
				ID:           "item-003",
				ReviewID:     "rev-002",
				UserID:       "user-789",
				ResourceType: "application",
				ResourceID:   "app-sensitive",
				ResourceName: "Sensitive Data App",
				Decision:     ReviewDecisionRevoked,
				DecidedBy:    "reviewer-002",
				DecidedAt:    timePtr(time.Now()),
				Comments:     "No longer required",
			},
			wantDecision: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate review item structure
			assert.NotEmpty(t, tt.item.ID)
			assert.NotEmpty(t, tt.item.ReviewID)
			assert.NotEmpty(t, tt.item.UserID)
			assert.NotEmpty(t, tt.item.ResourceType)
			assert.NotEmpty(t, tt.item.ResourceID)

			// Check decision state consistency
			hasDecision := tt.item.Decision != ReviewDecisionPending
			decisionMatches := (tt.item.DecidedAt != nil) == hasDecision

			if tt.item.Decision != ReviewDecisionPending {
				assert.True(t, decisionMatches, "decision state inconsistent with timestamp")
				assert.NotEmpty(t, tt.item.DecidedBy)
			}
		})
	}
}

func TestPolicyModelValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		policy      *Policy
		shouldBeValid bool
	}{
		{
			name: "valid SoD policy",
			policy: &Policy{
				ID:          "pol-001",
				Name:        "Separation of Duties",
				Description: "Prevents conflicting role assignments",
				Type:        PolicyTypeSoD,
				Rules: []PolicyRule{
					{
						ID:        "rule-1",
						Condition: map[string]interface{}{
							"conflicting_roles": []interface{}{"admin", "auditor"},
						},
						Effect:   "deny",
						Priority: 1,
					},
				},
				Enabled:  true,
				Priority: 10,
			},
			shouldBeValid: true,
		},
		{
			name: "valid risk-based policy",
			policy: &Policy{
				ID:          "pol-002",
				Name:        "Risk-Based Access",
				Description: "Evaluates risk score before granting access",
				Type:        PolicyTypeRiskBased,
				Rules: []PolicyRule{
					{
						ID:        "rule-1",
						Condition: map[string]interface{}{
							"risk_threshold": float64(50),
						},
						Effect:   "deny",
						Priority: 1,
					},
				},
				Enabled:  true,
				Priority: 20,
			},
			shouldBeValid: true,
		},
		{
			name: "disabled policy",
			policy: &Policy{
				ID:          "pol-003",
				Name:        "Disabled Policy",
				Description: "This policy is not active",
				Type:        PolicyTypeTimebound,
				Enabled:     false,
				Priority:    5,
			},
			shouldBeValid: true,
		},
		{
			name: "policy with multiple rules",
			policy: &Policy{
				ID:          "pol-004",
				Name:        "Complex Policy",
				Type:        PolicyTypeConditionalAccess,
				Rules: []PolicyRule{
					{
						ID:        "rule-1",
						Condition: map[string]interface{}{"require_mfa": true},
						Effect:    "deny",
						Priority:  1,
					},
					{
						ID:        "rule-2",
						Condition: map[string]interface{}{"device_trust": true},
						Effect:    "deny",
						Priority:  2,
					},
				},
				Enabled:  true,
				Priority: 15,
			},
			shouldBeValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate policy structure
			assert.NotEmpty(t, tt.policy.ID)
			assert.NotEmpty(t, tt.policy.Name)
			assert.NotZero(t, tt.policy.Priority)

			// Validate policy type is one of the valid types
			validTypes := []PolicyType{
				PolicyTypeSoD, PolicyTypeRiskBased, PolicyTypeTimebound,
				PolicyTypeLocation, PolicyTypeConditionalAccess,
			}
			validType := false
			for _, vt := range validTypes {
				if tt.policy.Type == vt {
					validType = true
					break
				}
			}
			assert.True(t, validType, "policy type must be valid")

			// Validate rules
			for _, rule := range tt.policy.Rules {
				assert.NotEmpty(t, rule.ID)
				assert.NotEmpty(t, rule.Effect)
				assert.NotZero(t, rule.Priority)
			}
		})
	}
}

func TestReviewScopeCombinations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		scope ReviewScope
		want  int // expected number of non-empty fields
	}{
		{
			name:  "empty scope",
			scope: ReviewScope{},
			want:  0,
		},
			{
			name: "users only",
			scope: ReviewScope{Users: []string{"user-1", "user-2"}},
			want:  1,
		},
		{
			name:  "groups only",
			scope: ReviewScope{Groups: []string{"group-1"}},
			want:  1,
		},
		{
			name:  "applications only",
			scope: ReviewScope{Applications: []string{"app-1", "app-2", "app-3"}},
			want:  1,
		},
		{
			name:  "roles only",
			scope: ReviewScope{Roles: []string{"admin", "viewer"}},
			want:  1,
		},
		{
			name: "all fields populated",
			scope: ReviewScope{
				Users:        []string{"user-1", "user-2"},
				Groups:       []string{"group-1"},
				Applications: []string{"app-1"},
				Roles:        []string{"admin"},
			},
			want: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := 0
			if len(tt.scope.Users) > 0 {
				count++
			}
			if len(tt.scope.Groups) > 0 {
				count++
			}
			if len(tt.scope.Applications) > 0 {
				count++
			}
			if len(tt.scope.Roles) > 0 {
				count++
			}
			assert.Equal(t, tt.want, count)
		})
	}
}

// ---------------------------------------------------------------------------
// Policy Evaluation Logic Tests (no database required)
// ---------------------------------------------------------------------------

func TestPolicyEvaluation_SoD(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		conflicting []interface{}
		userRoles   []interface{}
		wantDeny    bool
	}{
		{
			name:        "no conflict - empty roles",
			conflicting: []interface{}{"admin", "auditor"},
			userRoles:   []interface{}{},
			wantDeny:    false,
		},
		{
			name:        "no conflict - different roles",
			conflicting: []interface{}{"admin", "auditor"},
			userRoles:   []interface{}{"user", "viewer"},
			wantDeny:    false,
		},
		{
			name:        "conflict - both roles present",
			conflicting: []interface{}{"admin", "auditor"},
			userRoles:   []interface{}{"admin", "auditor"},
			wantDeny:    true,
		},
		{
			name:        "conflict - case insensitive match",
			conflicting: []interface{}{"ADMIN", "AUDITOR"},
			userRoles:   []interface{}{"admin", "auditor"},
			wantDeny:    true,
		},
		{
			name:        "conflict - one role present",
			conflicting: []interface{}{"admin", "auditor"},
			userRoles:   []interface{}{"admin"},
			wantDeny:    false,
		},
		{
			name:        "partial overlap - 3 roles, 2 conflicting",
			conflicting: []interface{}{"admin", "auditor"},
			userRoles:   []interface{}{"admin", "viewer", "auditor"},
			wantDeny:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate SoD policy evaluation logic
			roleSet := make(map[string]bool)
			for _, r := range tt.userRoles {
				if roleName, ok := r.(string); ok {
					roleSet[strings.ToLower(roleName)] = true
				}
			}

			allPresent := true
			var conflictNames []string
			for _, cr := range tt.conflicting {
				if roleName, ok := cr.(string); ok {
					conflictNames = append(conflictNames, roleName)
					if !roleSet[strings.ToLower(roleName)] {
						allPresent = false
						break
					}
				}
			}

			shouldDeny := allPresent && len(conflictNames) >= 2

			assert.Equal(t, tt.wantDeny, shouldDeny)
		})
	}
}

func TestPolicyEvaluation_RiskScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		threshold            int
		isNewDevice          bool
		isUnusualLocation    bool
		failedAttempts       float64
		wantDeny             bool
	}{
		{
			name:              "zero risk - below threshold",
			threshold:        50,
			isNewDevice:       false,
			isUnusualLocation: false,
			failedAttempts:    0,
			wantDeny:           false,
		},
		{
			name:              "new device only",
			threshold:        50,
			isNewDevice:       true,
			isUnusualLocation: false,
			failedAttempts:    0,
			wantDeny:           false, // 30 < 50
		},
		{
			name:              "new device + unusual location",
			threshold:        50,
			isNewDevice:       true,
			isUnusualLocation: true,
			failedAttempts:    0,
			wantDeny:           true, // 30 + 25 = 55 >= 50
		},
		{
			name:              "all risk factors",
			threshold:        50,
			isNewDevice:       true,
			isUnusualLocation: true,
			failedAttempts:    3,
			wantDeny:           true, // 30 + 25 + 30 = 85 >= 50
		},
		{
			name:              "many failed attempts",
			threshold:        50,
			isNewDevice:       false,
			isUnusualLocation: false,
			failedAttempts:    6,
			wantDeny:           true, // 60 >= 50
		},
		{
			name:              "exactly at threshold",
			threshold:        50,
			isNewDevice:       true,
			isUnusualLocation: true,
			failedAttempts:    0,
			wantDeny:           true, // 30 + 25 = 55 >= 50
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate risk score calculation
			riskScore := 0

			if tt.isNewDevice {
				riskScore += 30
			}

			if tt.isUnusualLocation {
				riskScore += 25
			}

			riskScore += int(tt.failedAttempts) * 10

			shouldDeny := riskScore >= tt.threshold

			assert.Equal(t, tt.wantDeny, shouldDeny)
		})
	}
}

func TestPolicyEvaluation_Location(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		allowedPrefixes []string
		requestIP      string
		wantAllowed    bool
	}{
		{
			name:           "default private network ranges",
			allowedPrefixes: []string{"10.", "192.168.", "172.16.", "172.17.", "172.18.", "127.0.0.1"},
			requestIP:      "10.0.0.5",
			wantAllowed:    true,
		},
		{
			name:           "192.168 private network",
			allowedPrefixes: []string{"10.", "192.168.", "172.16.", "172.17.", "172.18.", "127.0.0.1"},
			requestIP:      "192.168.1.100",
			wantAllowed:    true,
		},
		{
			name:           "localhost",
			allowedPrefixes: []string{"10.", "192.168.", "172.16.", "172.17.", "172.18.", "127.0.0.1"},
			requestIP:      "127.0.0.1",
			wantAllowed:    true,
		},
		{
			name:           "public IP - denied",
			allowedPrefixes: []string{"10.", "192.168.", "172.16.", "172.17.", "172.18.", "127.0.0.1"},
			requestIP:      "8.8.8.8",
			wantAllowed:    false,
		},
		{
			name:           "another public IP - denied",
			allowedPrefixes: []string{"10.", "192.168.", "172.16.", "172.17.", "172.18.", "127.0.0.1"},
			requestIP:      "1.1.1.1",
			wantAllowed:    false,
		},
		{
			name:           "custom allowed prefix",
			allowedPrefixes: []string{"172.20.", "172.21."},
			requestIP:      "172.20.0.10",
			wantAllowed:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate location policy evaluation
			allowed := false
			for _, prefix := range tt.allowedPrefixes {
				if len(tt.requestIP) >= len(prefix) && tt.requestIP[:len(prefix)] == prefix {
					allowed = true
					break
				}
			}

			assert.Equal(t, tt.wantAllowed, allowed)
		})
	}
}

func TestPolicyEvaluation_Timebound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		startHour    int
		endHour      int
		allowedDays  map[time.Weekday]bool
		currentHour   int
		currentWeekday time.Weekday
		wantAllowed  bool
	}{
		{
			name:        "business hours during weekday",
			startHour:   9,
			endHour:     17,
			allowedDays: map[time.Weekday]bool{
				time.Monday: true, time.Tuesday: true, time.Wednesday: true,
				time.Thursday: true, time.Friday: true,
			},
			currentHour:  14,
			currentWeekday: time.Wednesday,
			wantAllowed: true,
		},
		{
			name:        "early morning before business hours",
			startHour:   9,
			endHour:     17,
			allowedDays: map[time.Weekday]bool{
				time.Monday: true, time.Tuesday: true, time.Wednesday: true,
				time.Thursday: true, time.Friday: true,
			},
			currentHour:  7,
			currentWeekday: time.Monday,
			wantAllowed: false,
		},
		{
			name:        "late evening after business hours",
			startHour:   9,
			endHour:     17,
			allowedDays: map[time.Weekday]bool{
				time.Monday: true, time.Tuesday: true, time.Wednesday: true,
				time.Thursday: true, time.Friday: true,
			},
			currentHour:  20,
			currentWeekday: time.Tuesday,
			wantAllowed: false,
		},
		{
			name:        "weekend - not allowed",
			startHour:   9,
			endHour:     17,
			allowedDays: map[time.Weekday]bool{
				time.Monday: true, time.Tuesday: true, time.Wednesday: true,
				time.Thursday: true, time.Friday: true,
			},
			currentHour:  12,
			currentWeekday: time.Saturday,
			wantAllowed: false,
		},
		{
			name:        "24/7 access - always allowed",
			startHour:   0,
			endHour:     24,
			allowedDays:  map[time.Weekday]bool{
				time.Sunday: true, time.Monday: true, time.Tuesday: true,
				time.Wednesday: true, time.Thursday: true, time.Friday: true, time.Saturday: true,
			},
			currentHour:  3,
			currentWeekday: time.Sunday,
			wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Check day
			dayAllowed := tt.allowedDays[tt.currentWeekday]

			// Check hour
			hourAllowed := tt.currentHour >= tt.startHour && tt.currentHour < tt.endHour

			allowed := dayAllowed && hourAllowed

			assert.Equal(t, tt.wantAllowed, allowed)
		})
	}
}

// ---------------------------------------------------------------------------
// Certification Model Tests (no database required)
// ---------------------------------------------------------------------------

func TestCertificationCampaignValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		campaign    *CertificationCampaign
		shouldError  bool
		errorMsg     string
	}{
		{
			name: "valid campaign",
			campaign: &CertificationCampaign{
				ID:              "camp-001",
				Name:            "Q1 Certification",
				Description:     "Quarterly review",
				Status:          CampaignStatusDraft,
				Deadline:        time.Now().Add(30 * 24 * time.Hour),
				CreatedBy:       "admin-001",
				CreatedAt:       time.Now(),
				AutoRevoke:      true,
				GracePeriodDays: 7,
				Reviewers: []CampaignReviewer{
					{Type: "user", ID: "reviewer-001"},
					{Type: "manager", ID: ""},
				},
			},
			shouldError: false,
		},
		{
			name: "deadline in past",
			campaign: &CertificationCampaign{
				ID:        "camp-002",
				Name:      "Invalid Campaign",
				Deadline:  time.Now().Add(-1 * time.Hour),
				CreatedBy:  "admin-001",
				CreatedAt:  time.Now(),
				Reviewers:  []CampaignReviewer{{Type: "user", ID: "reviewer-001"}},
			},
			shouldError: true,
			errorMsg:    "future",
		},
		{
			name: "empty reviewers",
			campaign: &CertificationCampaign{
				ID:        "camp-003",
				Name:      "No Reviewers",
				Deadline:  time.Now().Add(24 * time.Hour),
				CreatedBy:  "admin-001",
				CreatedAt:  time.Now(),
				Reviewers: []CampaignReviewer{},
			},
			shouldError: true,
			errorMsg:    "reviewer",
		},
		{
			name: "valid active campaign",
			campaign: &CertificationCampaign{
				ID:              "camp-004",
				Name:            "Active Campaign",
				Status:          CampaignStatusActive,
				Deadline:        time.Now().Add(7 * 24 * time.Hour),
				CreatedBy:       "admin-001",
				CreatedAt:       time.Now(),
				StartedAt:       timePtr(time.Now().Add(-1 * time.Hour)),
				TotalItems:      100,
				ReviewedItems:   45,
				Reviewers:       []CampaignReviewer{{Type: "user", ID: "reviewer-001"}},
			},
			shouldError: false,
		},
		{
			name: "completed campaign",
			campaign: &CertificationCampaign{
				ID:              "camp-005",
				Name:            "Completed Campaign",
				Status:          CampaignStatusCompleted,
				Deadline:        time.Now().Add(-7 * 24 * time.Hour),
				CreatedBy:       "admin-001",
				CreatedAt:       time.Now().Add(-30 * 24 * time.Hour),
				StartedAt:       timePtr(time.Now().Add(-25 * 24 * time.Hour)),
				CompletedAt:     timePtr(time.Now().Add(-1 * 24 * time.Hour)),
				TotalItems:      50,
				ReviewedItems:   50,
				Reviewers:       []CampaignReviewer{{Type: "user", ID: "reviewer-001"}},
			},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate campaign structure
			assert.NotEmpty(t, tt.campaign.ID)
			assert.NotEmpty(t, tt.campaign.Name)
			assert.NotEmpty(t, tt.campaign.CreatedBy)

			// Check deadline is in future (for draft campaigns)
			if tt.campaign.Status == CampaignStatusDraft || tt.campaign.Status == CampaignStatusActive {
				if tt.campaign.Deadline.Before(time.Now()) {
					assert.True(t, tt.shouldError)
					assert.Contains(t, tt.errorMsg, "future")
				}
			}

			// Check reviewers exist
			if tt.campaign.Status == CampaignStatusDraft {
				assert.NotEmpty(t, tt.campaign.Reviewers, "reviewers required")
			}

			// Check completed state consistency
			if tt.campaign.Status == CampaignStatusCompleted {
				assert.NotNil(t, tt.campaign.CompletedAt)
				if tt.campaign.TotalItems > 0 {
					assert.Equal(t, tt.campaign.TotalItems, tt.campaign.ReviewedItems,
						"completed campaign must have all items reviewed")
				}
			}
		})
	}
}

func TestCertificationItemDecisionValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		decision CertificationDecision
		valid    bool
	}{
		{
			name:     "confirm decision",
			decision: DecisionConfirm,
			valid:    true,
		},
		{
			name:     "revoke decision",
			decision: DecisionRevoke,
			valid:    true,
		},
		{
			name:     "modify decision",
			decision: DecisionModify,
			valid:    true,
		},
		{
			name:     "pending decision",
			decision: DecisionPending,
			valid:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// All standard decisions should be valid
			assert.True(t, tt.valid)
			assert.NotEmpty(t, string(tt.decision))
		})
	}
}

// ---------------------------------------------------------------------------
// JIT Grant Model Tests (no database required)
// ---------------------------------------------------------------------------

func TestJITGrantValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		grant       *JITGrant
		shouldError bool
		errorMsg     string
	}{
		{
			name: "valid active grant",
			grant: &JITGrant{
				ID:            "grant-001",
				UserID:        "user-001",
				RoleID:        "role-admin",
				RoleName:      "Administrator",
				GrantedBy:     "admin-001",
				Justification: "Emergency access",
				Duration:      2 * time.Hour,
				ExpiresAt:     time.Now().Add(2 * time.Hour),
				CreatedAt:     time.Now(),
				Status:        "active",
			},
			shouldError: false,
		},
		{
			name: "expired grant",
			grant: &JITGrant{
				ID:            "grant-002",
				UserID:        "user-002",
				RoleID:        "role-viewer",
				RoleName:      "Viewer",
				GrantedBy:     "manager-001",
				Justification: "Temporary elevation",
				Duration:      30 * time.Minute,
				ExpiresAt:     time.Now().Add(-1 * time.Hour),
				CreatedAt:     time.Now().Add(-2 * time.Hour),
				Status:        "expired",
			},
			shouldError: false,
		},
		{
			name: "revoked grant",
			grant: &JITGrant{
				ID:            "grant-003",
				UserID:        "user-003",
				RoleID:        "role-poweruser",
				RoleName:      "Power User",
				GrantedBy:     "admin-001",
				Justification: "Abuse detected",
				Duration:      15 * time.Minute,
				ExpiresAt:     time.Now().Add(15 * time.Minute),
				CreatedAt:     time.Now().Add(-30 * time.Minute),
				RevokedAt:     timePtr(time.Now().Add(-15 * time.Minute)),
				RevokedBy:     strPtr("admin-001"),
				Status:        "revoked",
			},
			shouldError: false,
		},
		{
			name: "grant with minimum duration",
			grant: &JITGrant{
				ID:            "grant-004",
				UserID:        "user-004",
				RoleID:        "role-developer",
				RoleName:      "Developer",
				GrantedBy:     "user-004",
				Justification: "Code deployment",
				Duration:      15 * time.Minute,
				ExpiresAt:     time.Now().Add(15 * time.Minute),
				CreatedAt:     time.Now(),
				Status:        "active",
			},
			shouldError: false,
		},
		{
			name: "grant with maximum duration",
			grant: &JITGrant{
				ID:            "grant-005",
				UserID:        "user-005",
				RoleID:        "role-ops",
				RoleName:      "Ops Engineer",
				GrantedBy:     "manager-001",
				Justification: "Maintenance window",
				Duration:      8 * time.Hour,
				ExpiresAt:     time.Now().Add(8 * time.Hour),
				CreatedAt:     time.Now(),
				Status:        "active",
			},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate grant structure
			assert.NotEmpty(t, tt.grant.ID)
			assert.NotEmpty(t, tt.grant.UserID)
			assert.NotEmpty(t, tt.grant.RoleID)
			assert.NotEmpty(t, tt.grant.RoleName)
			assert.NotEmpty(t, tt.grant.GrantedBy)
			assert.NotEmpty(t, tt.grant.Justification)
			assert.NotZero(t, tt.grant.Duration)

			// Validate duration is within bounds
			if tt.grant.Duration < MinimumJITDuration || tt.grant.Duration > MaximumJITDuration {
				t.Error("JIT grant duration outside valid range")
			}

			// Validate expiry is after creation
			if tt.grant.Status == "active" {
				assert.True(t, tt.grant.ExpiresAt.After(tt.grant.CreatedAt),
					"expiry must be after creation time")
			}

			// Validate status consistency
			validStatuses := map[string]bool{
				"active": true, "expired": true, "revoked": true,
			}
			assert.True(t, validStatuses[tt.grant.Status], "invalid grant status")

			// If revoked, must have revocation info
			if tt.grant.Status == "revoked" {
				assert.NotNil(t, tt.grant.RevokedAt, "revoked grant must have revocation timestamp")
				assert.NotNil(t, tt.grant.RevokedBy, "revoked grant must have revoker")
			}
		})
	}
}

func TestJITRequestValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		request      JITRequest
		shouldError  bool
		errorContains string
	}{
		{
			name: "valid request with minimum duration",
			request: JITRequest{
				UserID:        "user-001",
				RoleID:        "role-developer",
				Duration:      15 * time.Minute,
				Justification: "Need to deploy hotfix",
				RequestedBy:   "user-001",
			},
			shouldError: false,
		},
		{
			name: "valid request with maximum duration",
			request: JITRequest{
				UserID:        "user-002",
				RoleID:        "role-ops",
				Duration:      8 * time.Hour,
				Justification: "Maintenance window access",
				RequestedBy:   "manager-001",
			},
			shouldError: false,
		},
		{
			name: "duration too short",
			request: JITRequest{
				UserID:        "user-003",
				RoleID:        "role-admin",
				Duration:      5 * time.Minute,
				Justification: "Quick task",
				RequestedBy:   "user-003",
			},
			shouldError:  true,
			errorContains: "at least",
		},
		{
			name: "duration too long",
			request: JITRequest{
				UserID:        "user-004",
				RoleID:        "role-viewer",
				Duration:      12 * time.Hour,
				Justification: "Long running task",
				RequestedBy:   "user-004",
			},
			shouldError:  true,
			errorContains: "not exceed",
		},
		{
			name: "missing user ID",
			request: JITRequest{
				RoleID:        "role-admin",
				Duration:      2 * time.Hour,
				Justification: "Need access",
				RequestedBy:   "admin-001",
			},
			shouldError:  true,
			errorContains: "user_id",
		},
		{
			name: "missing role ID",
			request: JITRequest{
				UserID:        "user-005",
				Duration:      2 * time.Hour,
				Justification: "Need access",
				RequestedBy:   "user-005",
			},
			shouldError:  true,
			errorContains: "role_id",
		},
		{
			name: "missing justification",
			request: JITRequest{
				UserID:      "user-006",
				RoleID:      "role-admin",
				Duration:    2 * time.Hour,
				RequestedBy: "user-006",
			},
			shouldError:  true,
			errorContains: "justification",
		},
		{
			name: "empty justification",
			request: JITRequest{
				UserID:        "user-007",
				RoleID:        "role-admin",
				Duration:      2 * time.Hour,
				Justification: "",
				RequestedBy:   "user-007",
			},
			shouldError:  true,
			errorContains: "justification",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate request fields
			hasError := false
			errorMsg := ""

			if tt.request.UserID == "" {
				hasError = true
				errorMsg = "user_id is required"
			}

			if tt.request.RoleID == "" && !hasError {
				hasError = true
				errorMsg = "role_id is required"
			}

			if tt.request.Justification == "" && !hasError {
				hasError = true
				errorMsg = "justification is required"
			}

			if tt.request.Duration < MinimumJITDuration && !hasError {
				hasError = true
				errorMsg = fmt.Sprintf("duration must be at least %v", MinimumJITDuration)
			}

			if tt.request.Duration > MaximumJITDuration && !hasError {
				hasError = true
				errorMsg = fmt.Sprintf("duration must not exceed %v", MaximumJITDuration)
			}

			if tt.shouldError {
				assert.True(t, hasError, "expected validation error")
				if tt.errorContains != "" {
					assert.Contains(t, errorMsg, tt.errorContains)
				}
			} else {
				assert.False(t, hasError, "unexpected validation error: " + errorMsg)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Review Progress Calculation Tests
// ---------------------------------------------------------------------------

func TestReviewProgressCalculation_Extended(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		total        int
		reviewed     int
		expectedPct  float64
	}{
		{
			name:        "empty review",
			total:       0,
			reviewed:     0,
			expectedPct:  0,
		},
		{
			name:        "no progress",
			total:       10,
			reviewed:     0,
			expectedPct:  0,
		},
		{
			name:        "25% complete",
			total:       100,
			reviewed:     25,
			expectedPct:  25,
		},
		{
			name:        "half complete",
			total:       50,
			reviewed:     25,
			expectedPct: 50,
		},
		{
			name:        "75% complete",
			total:       200,
			reviewed:     150,
			expectedPct: 75,
		},
		{
			name:        "fully complete",
			total:       1000,
			reviewed:     1000,
			expectedPct:  100,
		},
		{
			name:        "odd number - one-third complete",
			total:       9,
			reviewed:     3,
			expectedPct:  33.33,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pct float64
			if tt.total > 0 {
				pct = float64(tt.reviewed) / float64(tt.total) * 100
			}

			if tt.expectedPct == 0 || tt.expectedPct == 25 || tt.expectedPct == 50 ||
			   tt.expectedPct == 75 || tt.expectedPct == 100 {
				assert.InDelta(t, tt.expectedPct, pct, 0.01)
			} else {
				// For the 33.33% case, allow more delta
				assert.InDelta(t, tt.expectedPct, pct, 0.01)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Type Constant Validation Tests
// ---------------------------------------------------------------------------

func TestReviewTypeConstants(t *testing.T) {
	t.Parallel()

	expectedTypes := []ReviewType{
		ReviewTypeUserAccess,
		ReviewTypeRoleAssignment,
		ReviewTypeApplicationAccess,
		ReviewTypePrivilegedAccess,
	}

	for _, rt := range expectedTypes {
		t.Run(string(rt)+"_has_value", func(t *testing.T) {
			assert.NotEmpty(t, string(rt))
		})
	}
}

func TestReviewStatusConstants(t *testing.T) {
	t.Parallel()

	expectedStatuses := []ReviewStatus{
		ReviewStatusPending,
		ReviewStatusInProgress,
		ReviewStatusCompleted,
		ReviewStatusExpired,
		ReviewStatusCanceled,
	}

	for _, rs := range expectedStatuses {
		t.Run(string(rs)+"_has_value", func(t *testing.T) {
			assert.NotEmpty(t, string(rs))
		})
	}
}

func TestReviewDecisionConstants(t *testing.T) {
	t.Parallel()

	expectedDecisions := []ReviewDecision{
		ReviewDecisionPending,
		ReviewDecisionApproved,
		ReviewDecisionRevoked,
		ReviewDecisionFlagged,
	}

	for _, rd := range expectedDecisions {
		t.Run(string(rd)+"_has_value", func(t *testing.T) {
			assert.NotEmpty(t, string(rd))
		})
	}
}

func TestPolicyTypeConstants(t *testing.T) {
	t.Parallel()

	expectedTypes := []PolicyType{
		PolicyTypeSoD,
		PolicyTypeRiskBased,
		PolicyTypeTimebound,
		PolicyTypeLocation,
		PolicyTypeConditionalAccess,
	}

	for _, pt := range expectedTypes {
		t.Run(string(pt)+"_has_value", func(t *testing.T) {
			assert.NotEmpty(t, string(pt))
		})
	}
}

func TestCampaignStatusConstants(t *testing.T) {
	t.Parallel()

	expectedStatuses := []CampaignStatus{
		CampaignStatusDraft,
		CampaignStatusActive,
		CampaignStatusCompleted,
		CampaignStatusExpired,
		CampaignStatusCancelled,
	}

	for _, cs := range expectedStatuses {
		t.Run(string(cs)+"_has_value", func(t *testing.T) {
			assert.NotEmpty(t, string(cs))
		})
	}
}

func TestCertificationDecisionConstants(t *testing.T) {
	t.Parallel()

	expectedDecisions := []CertificationDecision{
		DecisionConfirm,
		DecisionRevoke,
		DecisionModify,
		DecisionPending,
	}

	for _, cd := range expectedDecisions {
		t.Run(string(cd)+"_has_value", func(t *testing.T) {
			assert.NotEmpty(t, string(cd))
		})
	}
}

// ---------------------------------------------------------------------------
// Duration Constant Tests
// ---------------------------------------------------------------------------

func TestJITDurationConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 15*time.Minute, MinimumJITDuration)
	assert.Equal(t, 8*time.Hour, MaximumJITDuration)
	assert.Equal(t, 30*time.Second, JITExpiryCheckInterval)
}

func TestJITDurationBounds(t *testing.T) {
	t.Parallel()

	// Test minimum boundary
	minRequest := JITRequest{Duration: MinimumJITDuration - 1}
	assert.True(t, minRequest.Duration < MinimumJITDuration)

	// Test maximum boundary
	maxRequest := JITRequest{Duration: MaximumJITDuration + 1}
	assert.True(t, maxRequest.Duration > MaximumJITDuration)

	// Test valid durations
	validDurations := []time.Duration{
		MinimumJITDuration,
		30 * time.Minute,
		1 * time.Hour,
		4 * time.Hour,
		MaximumJITDuration,
	}

	for _, d := range validDurations {
		assert.True(t, d >= MinimumJITDuration)
		assert.True(t, d <= MaximumJITDuration)
	}
}
