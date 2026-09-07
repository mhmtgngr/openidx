//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// J5 — privileged access, at the step that hands a human a secret.
//
// "Request → approve → checkout/brokered session → recording → review" is the
// third of the Definition of Done's journeys with no automated proof. Its
// brokered-session half needs guacd and a target host, and stays an operator
// drill. Its CREDENTIAL half does not, and it is the half that matters most:
// POST /pam/entries/:id/reveal is the only path in the product that ever hands
// PAM secret material to a person.
//
// WHY THROUGH THE RUNNING SERVICE. test/integration/jit_checkout_test.go covers
// the checkout mechanics, and says in its own header why it stops where it
// does: "governance HTTP handlers are not driven (gin+JWT wiring is heavy).
// This validates the checkout mechanics that the HTTP layer delegates to."
//
// That is the shape of every gap this branch has found. The mechanics are not
// the control. The control is the handler: the org predicate on the entry
// lookup, the allow_reveal flag, the ACL for non-admins, and the audit row —
// and all four live in code a test of vault.Service never reaches. The
// integration job now boots access-service so this can be driven where it runs.
//
// Four assertions, because they fail independently:
//
//   - a user with no grant is refused,
//   - the same user, granted, gets the secret,
//   - allow_reveal=false refuses EVEN AN ADMIN (the handler's own claim: an
//     entry provisioned for injection-only access stays password-less for
//     everyone until an audited edit flips the flag),
//   - the reveal is in the audit trail, naming who and which entry.

const accessURL = "http://localhost:8007"

// createPamEntry provisions a PAM entry holding a secret and returns its id.
// Created through the admin API rather than seeded, because the secret has to
// reach the vault sealed with the running service's keyring — a hand-written
// row would point at a secret that does not exist, and every assertion below
// would be about the error path.
func createPamEntry(t *testing.T, adminToken, name, secret string, allowReveal bool) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"name": %q,
		"entry_type": "credential",
		"username": "svc-account",
		"secret": %q,
		"allow_reveal": %t
	}`, name, secret, allowReveal)

	status, resp := apiRequest(t, "POST", accessURL+"/api/v1/access/pam/entries", body, adminToken)
	require.Equal(t, http.StatusCreated, status, "creating the PAM entry failed: %v", resp)

	id, _ := resp["id"].(string)
	if id == "" {
		// Some create handlers nest the record; accept either shape rather than
		// failing on a detail that is not what this test is about.
		if entry, ok := resp["entry"].(map[string]interface{}); ok {
			id, _ = entry["id"].(string)
		}
	}
	require.NotEmpty(t, id, "the created entry has no id: %v", resp)
	return id
}

func TestPrivilegedCredentialRevealIsGranted(t *testing.T) {
	db := integrationDB(t)
	defer db.Close()

	ctx := context.Background()
	nonce := fmt.Sprintf("%d", time.Now().UnixNano())
	adminToken := getAdminToken(t)

	const secret = "correct-horse-battery-staple-J5"
	entryID := createPamEntry(t, adminToken, "j5-revealable-"+nonce, secret, true)
	t.Cleanup(func() {
		apiRequest(t, "DELETE", accessURL+"/api/v1/access/pam/entries/"+entryID, "", adminToken)
	})

	// The engineer who will ask for the credential. An ordinary user: no admin
	// role, no grant yet.
	username := "j5-engineer-" + nonce
	const password = "PrivilegedIntegration!2026"
	userID := createTestUser(t, username, username+"@example.com", password)
	t.Cleanup(func() { deleteTestUser(t, userID) })
	userToken := loginAndGetToken(t, username, password)

	t.Run("an ungranted user is refused", func(t *testing.T) {
		status, body := apiRequest(t, "POST",
			accessURL+"/api/v1/access/pam/entries/"+entryID+"/reveal",
			`{"reason": "J5 integration: before any grant"}`, userToken)
		assert.Equal(t, http.StatusForbidden, status,
			"a user with no reveal grant read a privileged credential: %v", body)
		assert.NotContains(t, fmt.Sprintf("%v", body), secret,
			"the refusal response carried the secret it was refusing")
	})

	// The approval step, through the admin API the console calls.
	status, body := apiRequest(t, "POST",
		accessURL+"/api/v1/access/pam/entries/"+entryID+"/grants",
		fmt.Sprintf(`{"principal_type":"user","principal_id":%q,"actions":["reveal"]}`, userID),
		adminToken)
	require.Contains(t, []int{http.StatusOK, http.StatusCreated}, status,
		"granting reveal failed: %v", body)

	t.Run("the granted user gets the credential", func(t *testing.T) {
		status, body := apiRequest(t, "POST",
			accessURL+"/api/v1/access/pam/entries/"+entryID+"/reveal",
			`{"reason": "J5 integration: after the grant"}`, userToken)
		require.Equal(t, http.StatusOK, status,
			"the granted engineer was refused their own credential: %v", body)
		assert.Equal(t, secret, body["value"],
			"the reveal returned something other than the stored secret")
	})

	// Polled, not read once. access-service posts its audit events to
	// audit-service in a goroutine, deliberately: a slow audit sidecar must not
	// hold up the request that is already authorized. So the row arrives shortly
	// after the 200, and a single immediate SELECT would be a race that passes
	// on a fast machine — the shape that put an off-by-a-microsecond assertion
	// into CI earlier on this branch.
	t.Run("the reveal is in the audit trail, naming who and what", func(t *testing.T) {
		var audited int
		for i := 0; i < 50; i++ {
			require.NoError(t, db.QueryRow(ctx, `
				SELECT COUNT(*) FROM audit_events
				WHERE action = 'pam.entry_revealed' AND target_id = $1`, entryID).Scan(&audited))
			if audited > 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		require.GreaterOrEqual(t, audited, 1,
			"a privileged credential was handed to a person and the audit trail does not say so. "+
				"access-service posts to audit-service over HTTP; if that service is not running the "+
				"event is warned about and dropped, so this assertion is also the check that the "+
				"integration stack has an audit trail at all")

		// WHO, in the actor column — not buried in the details blob. An auditor
		// asking "who revealed this credential" filters on actor_id; a trail
		// that records the reveal and leaves the actor blank answers the wrong
		// half of the question.
		var actor string
		require.NoError(t, db.QueryRow(ctx, `
			SELECT COALESCE(actor_id, '') FROM audit_events
			WHERE action = 'pam.entry_revealed' AND target_id = $1
			ORDER BY timestamp DESC LIMIT 1`, entryID).Scan(&actor))
		assert.Equal(t, userID, actor,
			"the audit row records the reveal and not who did it")
	})

	// A reason is not optional: the audit row is worth nothing without one, and
	// the handler binds it as required.
	t.Run("a reveal with no reason is refused", func(t *testing.T) {
		status, body := apiRequest(t, "POST",
			accessURL+"/api/v1/access/pam/entries/"+entryID+"/reveal", `{}`, userToken)
		assert.Equal(t, http.StatusBadRequest, status,
			"a credential was revealed with no reason recorded: %v", body)
	})
}

// The flag the handler says is enforced for administrators too. An entry
// provisioned for injection-only access — the credential is used to open a
// session and never shown — must stay password-less for everyone, or the
// distinction the product sells between "brokered" and "revealed" access is a
// checkbox on a page.
func TestAnInjectionOnlyEntryRefusesEvenAnAdministrator(t *testing.T) {
	nonce := fmt.Sprintf("%d", time.Now().UnixNano())
	adminToken := getAdminToken(t)

	const secret = "never-to-be-shown-J5"
	entryID := createPamEntry(t, adminToken, "j5-injection-only-"+nonce, secret, false)
	t.Cleanup(func() {
		apiRequest(t, "DELETE", accessURL+"/api/v1/access/pam/entries/"+entryID, "", adminToken)
	})

	status, body := apiRequest(t, "POST",
		accessURL+"/api/v1/access/pam/entries/"+entryID+"/reveal",
		`{"reason": "J5 integration: an admin asking for an injection-only secret"}`, adminToken)

	assert.Equal(t, http.StatusForbidden, status,
		"allow_reveal=false and an administrator was still handed the secret: %v", body)
	assert.NotContains(t, fmt.Sprintf("%v", body), secret,
		"the refusal response carried the secret it was refusing")
}
