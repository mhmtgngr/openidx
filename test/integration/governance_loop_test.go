//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// J6 — the governance loop, at the step that has to reach outside governance.
//
// "Access request → approval → certification campaign → revoke propagates" is
// the journey the readiness guide marks ✅ with no automated proof behind it.
// The only browser spec aimed at it, e2e/access-reviews-flow.spec.ts, is 738
// lines driven entirely by mocked responses, so moving it to the run side of
// e2e/suite.txt would prove that the console renders fixtures — not that a
// reviewer's decision does anything.
//
// What is worth proving is the last word: PROPAGATES. A certification decision
// is three separate effects in two services, and each has failed independently
// in this codebase's history:
//
//  1. the item is recorded revoked,
//  2. the underlying access is actually removed,
//  3. the user's LIVE session stops working.
//
// (3) is the one with a history. internal/revocation exists because governance
// wrote its revocation marker to `auth:user_revoked:<uid>`, a key format
// inherited from a TokenService no binary reaches, while oauth reads
// `oauth:user_tokens_revoked_at:<uid>`. Both halves were internally consistent
// and the revocation reached nothing: a reviewer could revoke somebody's
// access, see it recorded, see it audited, and the person kept working until
// their token expired. A unit test in internal/oauth now pins the key. This
// pins the whole path, through the running services, which is the only place
// the two are actually separate processes.
//
// (1) and (2) are asserted too, and together: SubmitReviewDecision wraps them
// in one transaction precisely so an item cannot be marked revoked while the
// access survives, and a test that checked only the item would pass on exactly
// that hollow state.

const governanceURL = "http://localhost:8002"

// seedReviewWithItem creates a certification campaign holding one item that
// points at (user, role) — the shape populateRoleAssignmentItems produces — and
// returns (reviewID, itemID).
//
// Seeded rather than driven through the campaign-generation API because the
// step under test is the DECISION. Generating items is its own surface; if it
// were in the path here, a change there would fail this test and name the wrong
// thing.
func seedReviewWithItem(t *testing.T, db *pgxpool.Pool, orgID, reviewerID, userID, roleID, roleName string) (string, string) {
	t.Helper()

	var reviewID string
	bypassQueryRow(t, db, &reviewID, `
		INSERT INTO access_reviews (name, description, type, status, reviewer_id, start_date, end_date, org_id)
		VALUES ($1, 'J6 integration fixture', 'user_access', 'in_progress', $2::uuid,
		        NOW() - INTERVAL '1 day', NOW() + INTERVAL '30 days', $3::uuid)
		RETURNING id::text`, "J6 campaign "+roleName, reviewerID, orgID)
	require.NotEmpty(t, reviewID, "seeded review has no id")

	var itemID string
	bypassQueryRow(t, db, &itemID, `
		INSERT INTO review_items (review_id, user_id, resource_type, resource_id, resource_name, decision, org_id)
		VALUES ($1::uuid, $2::uuid, 'role', $3, $4, 'pending', $5::uuid)
		RETURNING id::text`, reviewID, userID, roleID, roleName, orgID)
	require.NotEmpty(t, itemID, "seeded review item has no id")

	return reviewID, itemID
}

func TestAccessReviewRevocationReachesTheUser(t *testing.T) {
	db := integrationDB(t)
	defer db.Close()

	ctx := context.Background()
	const defaultOrgID = "00000000-0000-0000-0000-000000000010"
	nonce := fmt.Sprintf("%d", time.Now().UnixNano())

	username := "reviewed-" + nonce
	const password = "GovernanceIntegration!2026"
	userID := createTestUser(t, username, username+"@example.com", password)
	t.Cleanup(func() { deleteTestUser(t, userID) })

	// The access under review: a role this user holds. The revoke has to remove
	// this row, not merely stamp the item.
	var roleID string
	bypassQueryRow(t, db, &roleID, `
		INSERT INTO roles (name, description, org_id)
		VALUES ($1, 'J6 integration fixture', $2::uuid)
		RETURNING id::text`, "j6-role-"+nonce, defaultOrgID)
	require.NotEmpty(t, roleID, "seeded role has no id")

	bypassExec(t, db, `
		INSERT INTO user_roles (user_id, role_id, org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, userID, roleID, defaultOrgID)

	var held int
	require.NoError(t, db.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_roles WHERE user_id = $1::uuid AND role_id = $2::uuid`,
		userID, roleID).Scan(&held))
	require.Equal(t, 1, held, "the fixture did not give the user the role it is about to revoke")

	// The live session the revocation has to reach.
	accessToken := loginAndGetToken(t, username, password)
	status, body := apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", accessToken)
	require.Equal(t, 200, status, "the reviewed user's own token was refused before any revocation: %v", body)

	// The campaign's assigned reviewer. authorizeReviewDecision admits an
	// administrator OR the assigned reviewer, and assigning one exercises the
	// branch a real campaign uses rather than an admin bypass — the same branch
	// that must refuse everybody else.
	adminToken := getAdminToken(t)
	reviewerID, _ := decodeJWTPayload(t, adminToken)["sub"].(string)
	require.NotEmpty(t, reviewerID, "could not read the reviewer id from the admin token")

	reviewID, itemID := seedReviewWithItem(t, db, defaultOrgID, reviewerID, userID, roleID, "j6-role-"+nonce)

	// The reviewer's decision, through the API the console calls.
	status, body = apiRequest(t, "POST",
		fmt.Sprintf("%s/api/v1/governance/reviews/%s/items/%s/decision", governanceURL, reviewID, itemID),
		`{"decision": "revoked", "comments": "J6 integration: revoked by the campaign"}`, adminToken)
	require.Equal(t, 200, status, "submitting the revoke decision failed: %v", body)

	t.Run("the decision is recorded", func(t *testing.T) {
		var decision string
		require.NoError(t, db.QueryRow(ctx,
			`SELECT decision FROM review_items WHERE id = $1::uuid`, itemID).Scan(&decision))
		assert.Equal(t, "revoked", decision, "the reviewer's decision was not recorded")
	})

	// Recorded and enforced are one transaction on purpose: an item marked
	// revoked while the role survives is the silent hole access reviews exist
	// to close, and it is what a test asserting only the item above would miss.
	t.Run("the access is actually removed", func(t *testing.T) {
		var stillHeld int
		require.NoError(t, db.QueryRow(ctx,
			`SELECT COUNT(*) FROM user_roles WHERE user_id = $1::uuid AND role_id = $2::uuid`,
			userID, roleID).Scan(&stillHeld))
		assert.Equal(t, 0, stillHeld,
			"the review item says revoked and the user still holds the role")
	})

	t.Run("the revocation is audited against the reviewer and the user", func(t *testing.T) {
		var audited int
		require.NoError(t, db.QueryRow(ctx, `
			SELECT COUNT(*) FROM audit_events
			WHERE action = 'access_review.revoked' AND target_id = $1`,
			userID).Scan(&audited))
		assert.GreaterOrEqual(t, audited, 1,
			"no access_review.revoked audit row: the revocation happened and nobody can show who did it")
	})

	// THE ONE THAT CROSSES A PROCESS BOUNDARY, and the one this loop got wrong
	// before. governance writes the marker; oauth-service, a different process,
	// reads it on every /oauth/userinfo. If the two ever spell it differently
	// again, everything above still passes and the reviewed user keeps working.
	t.Run("the reviewed user's live session stops working", func(t *testing.T) {
		status, body := apiRequest(t, "GET", oauthURL+"/oauth/userinfo", "", accessToken)
		assert.Equal(t, http.StatusUnauthorized, status,
			"the access review revoked this user and their live access token still answers. "+
				"governance's killUserSessions and oauth's IsAccessTokenRevoked must use "+
				"revocation.UserTokensRevokedAtKey — a second spelling is how this failed before: %v", body)
	})
}
