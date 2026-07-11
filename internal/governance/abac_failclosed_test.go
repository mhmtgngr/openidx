package governance

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// TestEvaluateABACPolicies_FailsClosedOnQueryError proves the ABAC policy
// decision point denies when it cannot read its policies. The abac_policies
// table is deliberately never created, so the evaluation query errors on a
// missing relation — the decision must be "not allowed", never a fail-open
// allow.
func TestEvaluateABACPolicies_FailsClosedOnQueryError(t *testing.T) {
	db, cleanup := setupTestDB(t) // skips if testcontainers unavailable
	defer cleanup()

	svc := &Service{db: db, logger: zap.NewNop()}

	result := svc.EvaluateABACPolicies(context.Background(), ABACEvaluationRequest{
		ResourceType: "document",
		ResourceID:   "doc-1",
		UserAttributes: map[string]interface{}{
			"department": "finance",
		},
	})

	if result.Allowed {
		t.Fatalf("ABAC evaluation with an unreadable policy table returned Allowed=true (fail-open); want denied. Reason=%q", result.Reason)
	}
}
