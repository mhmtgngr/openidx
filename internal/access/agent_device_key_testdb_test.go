package access

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// A device that holds a key speaks only with it.
//
// The test drives the real enrolment, report and registration handlers on the
// migrated schema: an enrolment that names a key binds it; from then on an
// unsigned report, or one signed by another key, is refused and writes
// nothing, while a signed one is accepted. A device enrolled without a key
// reports on its token as before, registers its key once with a request
// signed by that key, and is then held to it; a second, different key is
// refused. Enrolling again without a key clears the binding.
func TestADeviceWithAKeySpeaksOnlyWithIt(t *testing.T) {
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
		`INSERT INTO organizations (name, slug) VALUES ('device-key-org', 'device-key-org') RETURNING id::text`).
		Scan(&orgID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	newToken := func(plain string) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO agent_enrollment_tokens (token_hash, description, expires_at, reusable, revoked, org_id)
			VALUES ($1, 'test', NOW() + interval '1 hour', true, false, $2)`, sha256Hex(plain), orgID); err != nil {
			t.Fatalf("seed enrollment token: %v", err)
		}
	}
	newToken("enroll-with-key")

	agentH := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	router := gin.New()
	agentH.RegisterAgentPublicRoutes(router.Group("/api/v1/access"))
	call := func(path, agentID, token string, body []byte, sign *ecdsa.PrivateKey, signAs string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if agentID != "" {
			req.Header.Set("X-Agent-ID", agentID)
			req.Header.Set("X-Auth-Token", token)
		} else {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if sign != nil {
			ts, sig := signAgentRequest(t, sign, http.MethodPost, path, signAs, time.Now(), body)
			req.Header.Set(headerAgentKeyTimestamp, ts)
			req.Header.Set(headerAgentKeySignature, sig)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	const reportPath = "/api/v1/access/agent/report"
	report := []byte(`{"results":[{"check_type":"firewall","severity":"low","result":{"status":"pass","score":1}}]}`)
	postureRows := func(agentID string) int {
		var n int
		_ = db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM agent_posture_results WHERE agent_id = $1`, agentID).Scan(&n)
		return n
	}

	// --- enrolled with a key
	priv, pub := newTestDeviceKey(t)
	enrolBody, _ := json.Marshal(map[string]any{
		"hostname": "pc-1", "platform": "windows/amd64", "device_fingerprint": "win:aaaa",
		"device_key": map[string]string{"public_key": pub, "kind": "tpm"},
	})
	w := call("/api/v1/access/agent/enroll", "", "enroll-with-key", enrolBody, nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("enrol: %d %s", w.Code, w.Body.String())
	}
	type enrolment struct {
		AgentID        string `json:"agent_id"`
		AuthToken      string `json:"auth_token"`
		DeviceKeyBound bool   `json:"device_key_bound"`
	}
	read := func(w *httptest.ResponseRecorder) enrolment {
		t.Helper()
		var e enrolment
		if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
			t.Fatalf("enrolment answer: %v %s", err, w.Body.String())
		}
		return e
	}
	enrolled := read(w)
	if !enrolled.DeviceKeyBound {
		t.Fatalf("the enrolment named a key, and the answer must say it is bound: %s", w.Body.String())
	}
	id, tok := enrolled.AgentID, enrolled.AuthToken

	if w := call(reportPath, id, tok, report, nil, ""); w.Code != http.StatusUnauthorized ||
		!bytes.Contains(w.Body.Bytes(), []byte("device_signature_required")) {
		t.Fatalf("an unsigned report from a keyed device: %d %s", w.Code, w.Body.String())
	}
	other, _ := newTestDeviceKey(t)
	if w := call(reportPath, id, tok, report, other, id); w.Code != http.StatusUnauthorized ||
		!bytes.Contains(w.Body.Bytes(), []byte("device_signature_invalid")) {
		t.Fatalf("a report signed by another key: %d %s", w.Code, w.Body.String())
	}
	if n := postureRows(id); n != 0 {
		t.Fatalf("refused reports wrote %d posture rows", n)
	}
	if w := call(reportPath, id, tok, report, priv, id); w.Code != http.StatusAccepted {
		t.Fatalf("a report signed by the device key: %d %s", w.Code, w.Body.String())
	}
	if n := postureRows(id); n != 1 {
		t.Fatalf("the signed report wrote %d posture rows, want 1", n)
	}

	// --- enrolled without a key, registers one later
	newToken("enroll-without-key")
	enrolBody, _ = json.Marshal(map[string]any{"hostname": "pc-2", "platform": "windows/amd64", "device_fingerprint": "win:bbbb"})
	w = call("/api/v1/access/agent/enroll", "", "enroll-without-key", enrolBody, nil, "")
	enrolled = read(w)
	if enrolled.DeviceKeyBound {
		t.Fatal("no key was named, so none is bound")
	}
	id2, tok2 := enrolled.AgentID, enrolled.AuthToken
	if w := call(reportPath, id2, tok2, report, nil, ""); w.Code != http.StatusAccepted {
		t.Fatalf("a device with no key reports on its token as before: %d %s", w.Code, w.Body.String())
	}
	priv2, pub2 := newTestDeviceKey(t)
	reg, _ := json.Marshal(deviceKeyRequest{PublicKey: pub2, Kind: "software"})
	const regPath = "/api/v1/access/agent/device-key"
	if w := call(regPath, id2, tok2, reg, other, id2); w.Code != http.StatusUnauthorized {
		t.Fatalf("a registration not signed by the key it registers: %d %s", w.Code, w.Body.String())
	}
	if w := call(regPath, id2, tok2, reg, priv2, id2); w.Code != http.StatusCreated {
		t.Fatalf("registration: %d %s", w.Code, w.Body.String())
	}
	if w := call(regPath, id2, tok2, reg, priv2, id2); w.Code != http.StatusOK {
		t.Fatalf("the same key again: %d %s", w.Code, w.Body.String())
	}
	_, pub3 := newTestDeviceKey(t)
	reg3, _ := json.Marshal(deviceKeyRequest{PublicKey: pub3, Kind: "file"})
	if w := call(regPath, id2, tok2, reg3, nil, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("an unsigned registration: %d", w.Code)
	}
	if w := call(reportPath, id2, tok2, report, nil, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("once registered, the device is held to its key: %d %s", w.Code, w.Body.String())
	}
	if w := call(reportPath, id2, tok2, report, priv2, id2); w.Code != http.StatusAccepted {
		t.Fatalf("signed with the registered key: %d %s", w.Code, w.Body.String())
	}
	var kind string
	_ = db.Pool.QueryRow(ctx, `SELECT COALESCE(device_key_kind,'') FROM enrolled_agents WHERE agent_id = $1`, id2).Scan(&kind)
	if kind != "software" {
		t.Fatalf("the key's kind is recorded for administrators: %q", kind)
	}

	// --- a different key for a keyed device is refused; re-enrolling clears it
	priv4, pub4 := newTestDeviceKey(t)
	reg4, _ := json.Marshal(deviceKeyRequest{PublicKey: pub4, Kind: "file"})
	if w := call(regPath, id2, tok2, reg4, priv4, id2); w.Code != http.StatusConflict {
		t.Fatalf("a second, different key: %d %s", w.Code, w.Body.String())
	}
	enrolBody, _ = json.Marshal(map[string]any{"hostname": "pc-2", "platform": "windows/amd64", "device_fingerprint": "win:bbbb"})
	w = call("/api/v1/access/agent/enroll", "", "enroll-without-key", enrolBody, nil, "")
	enrolled = read(w)
	if enrolled.AgentID != id2 {
		t.Fatalf("re-enrolment by fingerprint keeps the agent id: %s vs %s", enrolled.AgentID, id2)
	}
	if w := call(reportPath, id2, enrolled.AuthToken, report, nil, ""); w.Code != http.StatusAccepted {
		t.Fatalf("an enrolment without a key clears the binding: %d %s", w.Code, w.Body.String())
	}
}
