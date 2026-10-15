package access

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Re-enrolment by fingerprint takes an existing agent's row only on proof.
//
// The fingerprint is the client's own claim (sha256 of the machine id and
// host name, which any local account can compute), and the enrolment that
// names it used to take the row whoever sent it: the real agent's token was
// rotated out from under it, a suspension was lifted, and the device key was
// replaced or dropped. The wizard code that admits such an enrolment is one
// any user of the organization can make for themselves. These tests pin the
// rule (reenrolmentRefusal), the function-level behaviour against the minimal
// schema, and the handler-level behaviour with a real device-key signature
// against the migrated schema.

func TestReenrolmentRefusalRules(t *testing.T) {
	const (
		agent = "agent-11111111"
		alice = "00000000-0000-0000-0000-00000000a11c"
		bob   = "00000000-0000-0000-0000-000000000b0b"
	)
	cases := []struct {
		name                 string
		owner                string
		hasKey               bool
		method, user, signed string
		want                 string
	}{
		{"no existing row", "", false, "session", bob, "", ""},
		{"the device signed as the agent", alice, true, "session", bob, agent, ""},
		{"a signature naming another agent is not proof", alice, true, "session", bob, "agent-other", "device_key_required"},
		{"a keyed row is not taken by an operator token", alice, true, "token", "", "", "device_key_required"},
		{"a keyed row is not taken by its own user unsigned", alice, true, "session", alice, "", "device_key_required"},
		{"an operator token takes a keyless row", alice, false, "token", "", "", ""},
		{"the same user takes a keyless row", alice, false, "session", alice, "", ""},
		{"the same user over OAuth takes a keyless row", alice, false, "oauth", alice, "", ""},
		{"another user does not", alice, false, "session", bob, "", "fingerprint_not_owned"},
		{"a user does not take a row an operator enrolled", "", false, "session", bob, "", "fingerprint_not_owned"},
		{"an anonymous session does not take a row", alice, false, "session", "", "", "fingerprint_not_owned"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			existing := agent
			if c.name == "no existing row" {
				existing = ""
			}
			if got := reenrolmentRefusal(existing, c.owner, c.hasKey, c.method, c.user, c.signed); got != c.want {
				t.Errorf("reenrolmentRefusal = %q, want %q", got, c.want)
			}
		})
	}
}

const (
	ownerAlice = "00000000-0000-0000-0000-00000000a11c"
	ownerBob   = "00000000-0000-0000-0000-000000000b0b"
)

type ownershipRow struct {
	status, hash, owner string
	// fingerprint is "" for a row written without one.
	fingerprint string
	conflict    string
}

func readOwnershipRow(t *testing.T, ctx context.Context, h *AgentAPIHandler, agentID string) ownershipRow {
	t.Helper()
	var r ownershipRow
	if err := h.db.Pool.QueryRow(ctx, `
		SELECT status, COALESCE(auth_token_hash,''), COALESCE(enrolled_by_user_id::text,''),
		       COALESCE(device_fingerprint,''), COALESCE(metadata->>'fingerprint_conflict','')
		  FROM enrolled_agents WHERE agent_id = $1`, agentID).
		Scan(&r.status, &r.hash, &r.owner, &r.fingerprint, &r.conflict); err != nil {
		t.Fatalf("read %s: %v", agentID, err)
	}
	return r
}

func TestAnotherUsersEnrolmentDoesNotTakeOverTheRow(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	for _, stmt := range enrolledAgentsSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	h := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	req := enrollRequest{Hostname: "SHARED-PC", Platform: "windows", DeviceFingerprint: "win:shared-pc"}
	issue := func(method, user string) issuedAgentCredentials {
		t.Helper()
		creds, err := h.issueAgentCredentials(ctx, req, method, user, idemOrgA)
		if err != nil {
			t.Fatalf("enrolment (%s, %q) refused: %v", method, user, err)
		}
		return creds
	}

	alice := issue("session", ownerAlice)
	before := readOwnershipRow(t, ctx, h, alice.AgentID)
	if before.owner != ownerAlice || before.fingerprint == "" {
		t.Fatalf("the first enrolment did not record its user and fingerprint: %+v", before)
	}

	// Bob names Alice's machine with a wizard code of his own.
	bob := issue("session", ownerBob)
	if bob.AgentID == alice.AgentID {
		t.Fatalf("another user's enrolment took the row: both are %s", alice.AgentID)
	}
	if after := readOwnershipRow(t, ctx, h, alice.AgentID); after != before {
		t.Errorf("another user's enrolment changed the row: %+v -> %+v", before, after)
	}
	bobRow := readOwnershipRow(t, ctx, h, bob.AgentID)
	if bobRow.fingerprint != "" {
		t.Errorf("the conflicting enrolment kept the fingerprint %q; it is the other agent's", bobRow.fingerprint)
	}
	if bobRow.conflict != "fingerprint_not_owned" {
		t.Errorf("the conflicting enrolment's row does not say why: %+v", bobRow)
	}
	if bobRow.owner != ownerBob {
		t.Errorf("the new row is owned by %q, want %q", bobRow.owner, ownerBob)
	}

	// Alice herself, and an operator token, still take the keyless row.
	again := issue("session", ownerAlice)
	if again.AgentID != alice.AgentID {
		t.Errorf("the owner's re-enrolment minted %s, want her own %s", again.AgentID, alice.AgentID)
	}
	if now := readOwnershipRow(t, ctx, h, alice.AgentID); now.hash == before.hash {
		t.Error("the owner's re-enrolment did not rotate the token")
	}
	operator := issue("token", "")
	if operator.AgentID != alice.AgentID {
		t.Errorf("an operator token's re-enrolment minted %s, want %s", operator.AgentID, alice.AgentID)
	}

	// A suspended row is lifted by its owner, not by a stranger.
	if _, err := db.Pool.Exec(ctx, `UPDATE enrolled_agents SET status = 'suspended' WHERE agent_id = $1`, alice.AgentID); err != nil {
		t.Fatal(err)
	}
	stranger := issue("session", ownerBob)
	if stranger.AgentID == alice.AgentID {
		t.Fatal("a stranger's enrolment took the suspended row")
	}
	if row := readOwnershipRow(t, ctx, h, alice.AgentID); row.status != "suspended" {
		t.Errorf("a stranger's enrolment lifted the suspension: status %q", row.status)
	}
	if lifted := issue("session", ownerAlice); lifted.AgentID != alice.AgentID || lifted.Status != "active" {
		t.Errorf("the owner's re-enrolment did not lift the suspension: %+v", lifted)
	}
}

func TestAKeyedDeviceReenrolsOnlyWithItsSignature(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	for _, stmt := range enrolledAgentsSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	h := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	req := enrollRequest{Hostname: "KEYED-PC", Platform: "windows", DeviceFingerprint: "win:keyed-pc"}
	issue := func(r enrollRequest, method, user string) issuedAgentCredentials {
		t.Helper()
		creds, err := h.issueAgentCredentials(ctx, r, method, user, idemOrgA)
		if err != nil {
			t.Fatalf("enrolment (%s, %q) refused: %v", method, user, err)
		}
		return creds
	}

	keyed := issue(req, "session", ownerAlice)
	if _, err := db.Pool.Exec(ctx, `UPDATE enrolled_agents SET device_public_key = 'k', device_key_kind = 'tpm',
		device_key_bound_at = NOW() WHERE agent_id = $1`, keyed.AgentID); err != nil {
		t.Fatal(err)
	}
	before := readOwnershipRow(t, ctx, h, keyed.AgentID)

	for _, c := range []struct{ method, user string }{{"token", ""}, {"session", ownerAlice}, {"oauth", ownerAlice}} {
		got := issue(req, c.method, c.user)
		if got.AgentID == keyed.AgentID {
			t.Errorf("an unsigned %s enrolment by %q took the keyed row", c.method, c.user)
		}
		if row := readOwnershipRow(t, ctx, h, got.AgentID); row.conflict != "device_key_required" {
			t.Errorf("the new row after an unsigned %s enrolment says %q, want device_key_required", c.method, row.conflict)
		}
	}
	if after := readOwnershipRow(t, ctx, h, keyed.AgentID); after != before {
		t.Errorf("unsigned enrolments changed the keyed row: %+v -> %+v", before, after)
	}

	// The signature is the proof, whoever admitted the enrolment.
	signed := req
	signed.signedAgentID = keyed.AgentID
	for _, c := range []struct{ method, user string }{{"token", ""}, {"session", ownerBob}} {
		got := issue(signed, c.method, c.user)
		if got.AgentID != keyed.AgentID {
			t.Errorf("a signed %s enrolment minted %s, want the device's own %s", c.method, got.AgentID, keyed.AgentID)
		}
	}
	// A signature that names some other agent proves nothing for this row.
	other := req
	other.signedAgentID = "agent-someone-else"
	if got := issue(other, "token", ""); got.AgentID == keyed.AgentID {
		t.Error("a signature naming another agent took the keyed row")
	}
}

// A signed re-enrolment through the real route: the agent holds a key the
// server bound at its first enrolment, enrols again signing the exact bytes
// it sends as that agent, and gets its own agent id back. The same enrolment
// unsigned becomes a new agent and leaves the keyed row untouched, with an
// agent.enroll_denied record in the agent's tenant; a wrong signature is
// refused outright.
func TestASignedReenrolmentTakesTheDeviceRow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	var orgID string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('keyed-org', 'keyed-org') RETURNING id::text`).
		Scan(&orgID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO agent_enrollment_tokens (token_hash, description, expires_at, reusable, revoked, org_id)
		VALUES ($1, 'test', NOW() + interval '1 hour', true, false, $2)`, sha256Hex("fleet-token"), orgID); err != nil {
		t.Fatalf("seed enrollment token: %v", err)
	}

	agentH := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	router := gin.New()
	agentH.RegisterAgentPublicRoutes(router.Group("/api/v1/access"))

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(der)

	const fp = "win:keyed-route"
	body := func() []byte {
		b, _ := json.Marshal(map[string]any{
			"hostname": "KEYED-ROUTE", "platform": "windows", "device_fingerprint": fp,
			"device_key": map[string]string{"public_key": pubB64, "kind": "tpm"},
		})
		return b
	}
	type enrolment struct {
		AgentID   string `json:"agent_id"`
		AuthToken string `json:"auth_token"`
	}
	send := func(headers map[string]string, b []byte) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/access/agent/enroll", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer fleet-token")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	enrolled := func(t *testing.T, w *httptest.ResponseRecorder) enrolment {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("enrolment answered %d, want 200: %s", w.Code, w.Body.String())
		}
		var e enrolment
		if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || e.AgentID == "" {
			t.Fatalf("enrolment answer has no credential (%v): %s", err, w.Body.String())
		}
		return e
	}
	signedHeaders := func(agentID string, b []byte, key *ecdsa.PrivateKey) map[string]string {
		t.Helper()
		ts := time.Now().Unix()
		input, err := agentRequestSigningInput(http.MethodPost, "/api/v1/access/agent/enroll", agentID, ts, b)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(input)
		sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return map[string]string{
			"X-Agent-ID":            agentID,
			headerAgentKeyTimestamp: strconv.FormatInt(ts, 10),
			headerAgentKeySignature: base64.StdEncoding.EncodeToString(sig),
		}
	}
	row := func(t *testing.T, agentID string) ownershipRow {
		t.Helper()
		return readOwnershipRow(t, orgctx.With(ctx, orgctx.Org{ID: orgID}), agentH, agentID)
	}
	refusals := func(t *testing.T, agentID string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, `
			SELECT count(*) FROM unified_audit_events
			 WHERE event_type = 'agent.enroll_denied' AND org_id::text = $1
			   AND details->>'agent_id' = $2 AND details->>'outcome' = 'denied'`,
			orgID, agentID).Scan(&n); err != nil {
			t.Fatalf("read the audit trail: %v", err)
		}
		return n
	}

	first := enrolled(t, send(nil, body()))
	var bound bool
	if err := db.Pool.QueryRow(ctx, `SELECT device_public_key IS NOT NULL FROM enrolled_agents WHERE agent_id = $1`,
		first.AgentID).Scan(&bound); err != nil || !bound {
		t.Fatalf("the first enrolment did not bind the key (err %v, bound %v)", err, bound)
	}
	before := row(t, first.AgentID)

	t.Run("signed as itself, the device keeps its agent id", func(t *testing.T) {
		b := body()
		again := enrolled(t, send(signedHeaders(first.AgentID, b, priv), b))
		if again.AgentID != first.AgentID {
			t.Fatalf("a signed re-enrolment minted %s, want %s", again.AgentID, first.AgentID)
		}
		if again.AuthToken == first.AuthToken {
			t.Error("the signed re-enrolment did not rotate the token")
		}
		if n := refusals(t, first.AgentID); n != 0 {
			t.Errorf("a signed re-enrolment was audited as denied %d times", n)
		}
	})

	t.Run("unsigned, even by a fleet token, it is a new agent", func(t *testing.T) {
		before := row(t, first.AgentID)
		other := enrolled(t, send(nil, body()))
		if other.AgentID == first.AgentID {
			t.Fatal("an unsigned enrolment took the keyed row")
		}
		if after := row(t, first.AgentID); after != before {
			t.Errorf("the unsigned enrolment changed the keyed row: %+v -> %+v", before, after)
		}
		if r := row(t, other.AgentID); r.fingerprint != "" || r.conflict != "device_key_required" {
			t.Errorf("the new agent's row = %+v, want no fingerprint and conflict device_key_required", r)
		}
		if n := refusals(t, first.AgentID); n != 1 {
			t.Errorf("found %d agent.enroll_denied records for the keyed agent, want 1", n)
		}
	})

	t.Run("a wrong signature is refused", func(t *testing.T) {
		wrong, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		b := body()
		w := send(signedHeaders(first.AgentID, b, wrong), b)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("a wrong signature answered %d, want 401: %s", w.Code, w.Body.String())
		}
		var resp map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["code"] != "device_signature_invalid" {
			t.Errorf("refusal code = %q, want device_signature_invalid", resp["code"])
		}
		if _, leaked := resp["auth_token"]; leaked {
			t.Error("the refusal carries a credential")
		}
		if after := row(t, first.AgentID); after.hash != before.hash && after.status != "active" {
			t.Errorf("the refused enrolment changed the row: %+v", after)
		}
	})
}
