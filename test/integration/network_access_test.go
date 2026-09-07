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

// J4 — network access, at the step that decides whether a device gets any.
//
// "Enroll agent/BrowZer → posture check → reach a dark service" is the last of
// the Definition of Done's journeys with no automated proof. Its third step
// needs a Ziti controller, a router and a dark service to dial, and stays an
// operator drill (tools/darkprobe, the going-dark runbook). Its first two steps
// are HTTP against access-service, and they are the steps that decide the third:
// applyPostureDeviceTrust (agent_api.go:1039) grants or removes the
// `device-trusted` Ziti role attribute from the posture verdict, and that
// attribute is the Tier-2 gate the reconciler's dial policies require.
//
// So the question this asks is not "is posture recorded". It is: WHO IS ALLOWED
// TO SAY WHAT A DEVICE'S POSTURE IS. Writing it answered that with "anybody":
// /agent/report and /agent/config are registered outside the JWT middleware,
// and neither read the credential enrollment issues. A report was accepted for
// any agent id a caller cared to type, and one HTTP request with no
// authentication of any kind could hand a device Tier-2 network access — or
// take it away from someone else's laptop.
//
//	POST /api/v1/access/agent/report   (no headers, invented agent id)
//	→ 202 {"compliance_score":1,"status":"accepted"}   and the row was stored
//
// Both shipped agents send the credential (the Android one as X-Auth-Token, the
// Go one as Authorization: Bearer) and access-service.yaml has always documented
// a 401 on both paths. Only the server never looked. internal/access/agent_auth.go
// is the fix; this drives it where it runs.
func TestNetworkAccessPostureIsOnlyReportableByTheDevice(t *testing.T) {
	db := integrationDB(t)
	t.Cleanup(func() { db.Close() })

	ctx := context.Background()
	adminToken := getAdminToken(t)
	nonce := fmt.Sprintf("%d", time.Now().UnixNano())

	// --- Step 1: enroll, through the two admin/agent endpoints a real device uses.
	status, minted := apiRequest(t, "POST", accessURL+"/api/v1/access/agent/tokens",
		fmt.Sprintf(`{"description":"J4 integration %s","reusable":false}`, nonce), adminToken)
	require.Equal(t, http.StatusOK, status, "minting an enrollment token failed: %v", minted)
	enrollToken, _ := minted["token"].(string)
	require.NotEmpty(t, enrollToken, "the mint response carries no token: %v", minted)

	status, enrolled := apiRequestWithHeaders(t, "POST", accessURL+"/api/v1/access/agent/enroll",
		fmt.Sprintf(`{"hostname":"j4-%s","os":"linux","platform":"linux","form_factor":"laptop"}`, nonce),
		enrollToken, nil)
	require.Equal(t, http.StatusOK, status, "enrollment failed: %v", enrolled)

	agentID, _ := enrolled["agent_id"].(string)
	authToken, _ := enrolled["auth_token"].(string)
	require.NotEmpty(t, agentID, "enrollment returned no agent_id: %v", enrolled)
	require.NotEmpty(t, authToken, "enrollment returned no auth_token — the device has no credential "+
		"to authenticate its later reports with: %v", enrolled)
	t.Cleanup(func() {
		apiRequest(t, "DELETE", accessURL+"/api/v1/access/agents/"+agentID, "", adminToken)
	})

	// A compliant report and a failing one, in the shape the agent sends.
	compliant := `{"results":[{"check_type":"disk_encryption","severity":"critical",` +
		`"result":{"status":"pass","score":1,"message":"encrypted"}}]}`
	failing := `{"results":[{"check_type":"disk_encryption","severity":"critical",` +
		`"result":{"status":"fail","score":0,"message":"not encrypted"}}]}`

	postureRows := func() int {
		var n int
		require.NoError(t, db.QueryRow(ctx,
			`SELECT count(*) FROM agent_posture_results WHERE agent_id = $1`, agentID).Scan(&n))
		return n
	}
	verdict := func() (string, float64) {
		var s string
		var score float64
		require.NoError(t, db.QueryRow(ctx,
			`SELECT compliance_status, COALESCE(compliance_score,0) FROM enrolled_agents
			 WHERE agent_id = $1`, agentID).Scan(&s, &score))
		return s, score
	}

	// --- Step 2: the posture check, and who may perform it.

	t.Run("an anonymous caller cannot report posture for this device", func(t *testing.T) {
		before := postureRows()
		status, body := apiRequestWithHeaders(t, "POST", accessURL+"/api/v1/access/agent/report",
			compliant, "", map[string]string{"X-Agent-ID": agentID})
		assert.Equal(t, http.StatusUnauthorized, status,
			"a request with no credentials reported posture for an enrolled device: %v", body)
		assert.Equal(t, before, postureRows(),
			"the refused report was still written to the trail")
	})

	t.Run("a guessed token is refused", func(t *testing.T) {
		status, body := apiRequestWithHeaders(t, "POST", accessURL+"/api/v1/access/agent/report",
			compliant, "", map[string]string{"X-Agent-ID": agentID, "X-Auth-Token": "not-the-token"})
		assert.Equal(t, http.StatusUnauthorized, status, "a guessed token was accepted: %v", body)
	})

	t.Run("an agent id nobody enrolled is refused", func(t *testing.T) {
		status, body := apiRequestWithHeaders(t, "POST", accessURL+"/api/v1/access/agent/report",
			compliant, "", map[string]string{
				"X-Agent-ID": "j4-never-enrolled-" + nonce, "X-Auth-Token": "anything"})
		assert.Equal(t, http.StatusUnauthorized, status, "%v", body)

		var n int
		require.NoError(t, db.QueryRow(ctx,
			`SELECT count(*) FROM agent_posture_results WHERE agent_id = $1`,
			"j4-never-enrolled-"+nonce).Scan(&n))
		assert.Zero(t, n, "posture was recorded for a device that does not exist")
	})

	t.Run("the device reports its own posture and the verdict is recorded", func(t *testing.T) {
		status, body := apiRequestWithHeaders(t, "POST", accessURL+"/api/v1/access/agent/report",
			compliant, "", map[string]string{"X-Agent-ID": agentID, "X-Auth-Token": authToken})
		require.Equal(t, http.StatusAccepted, status,
			"the enrolled device could not report its own posture: %v", body)
		assert.Equal(t, float64(1), body["compliance_score"])

		assert.Positive(t, postureRows(), "the accepted report reached no posture row")
		state, score := verdict()
		assert.Equal(t, "compliant", state, "a passing critical check left the device %q", state)
		assert.Equal(t, float64(1), score)
	})

	t.Run("an anonymous caller cannot take a compliant device's trust away", func(t *testing.T) {
		// The half that is easy to miss. A forged FAILURE is not noise: with
		// POSTURE_DEVICE_TRUST_GATE=enforce it removes `device-trusted` from the
		// device's Ziti identity, which drops it to the Tier-1 minimum. One
		// unauthenticated HTTP request per laptop.
		status, body := apiRequestWithHeaders(t, "POST", accessURL+"/api/v1/access/agent/report",
			failing, "", map[string]string{"X-Agent-ID": agentID})
		require.Equal(t, http.StatusUnauthorized, status, "%v", body)

		state, score := verdict()
		assert.Equal(t, "compliant", state,
			"an unauthenticated request moved an enrolled device's compliance verdict")
		assert.Equal(t, float64(1), score)
	})

	t.Run("a report may not be filed under another device's id", func(t *testing.T) {
		// Valid credentials, someone else's id in the body. Before the id came
		// from the credential rather than the payload, this is how one enrolled
		// device wrote posture for every other device in the fleet.
		status, body := apiRequestWithHeaders(t, "POST", accessURL+"/api/v1/access/agent/report",
			`{"agent_id":"some-other-device","results":[]}`, "",
			map[string]string{"X-Agent-ID": agentID, "X-Auth-Token": authToken})
		assert.Equal(t, http.StatusBadRequest, status, "%v", body)
	})

	t.Run("configuration is served to the device and to nobody else", func(t *testing.T) {
		status, body := apiRequest(t, "GET",
			accessURL+"/api/v1/access/agent/config?agent_id="+agentID, "", "")
		assert.Equal(t, http.StatusUnauthorized, status,
			"an agent_id in the query string was enough to read a device's check list, "+
				"report cadence and kiosk policy: %v", body)

		status, cfg := apiRequestWithHeaders(t, "GET", accessURL+"/api/v1/access/agent/config",
			"", "", map[string]string{"X-Agent-ID": agentID, "X-Auth-Token": authToken})
		require.Equal(t, http.StatusOK, status, "the device could not read its own config: %v", cfg)
		assert.NotNil(t, cfg["checks"], "the config carries no check list: %v", cfg)
	})

	// --- The administrator's view of the same journey.
	t.Run("the posture an administrator sees is the one the device reported", func(t *testing.T) {
		status, body := apiRequest(t, "GET",
			accessURL+"/api/v1/access/agents/"+agentID+"/posture", "", adminToken)
		require.Equal(t, http.StatusOK, status, "reading the device's posture failed: %v", body)
		assert.Equal(t, true, body["compliant"],
			"the console shows a different verdict than the trail holds: %v", body)

		// And the check itself, not just the summary: `compliant` starts true
		// and is only falsified by a failing row, so a device that has never
		// reported reads compliant too. The results array is what separates
		// "passed its checks" from "has no checks".
		results, _ := body["results"].([]interface{})
		require.Len(t, results, 1, "the admin view shows %d checks for a device that reported one: %v",
			len(results), body)
		row, _ := results[0].(map[string]interface{})
		assert.Equal(t, "disk_encryption", row["check_type"])
		assert.Equal(t, "pass", row["status"],
			"the device reported a pass and the console shows %v", row["status"])
	})

	fmt.Printf("J4: agent %s enrolled, posture reportable only with its own credential\n", agentID)
}
