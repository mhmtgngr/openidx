package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/config"
)

// The acr claim and the mint-time gate read the session the server recorded,
// with the same step-up window the freshness gate uses.
func TestSessionACRReadsTheRecordedSession(t *testing.T) {
	svc, ctx, cleanup := stampFixture(t)
	defer cleanup()
	svc.config = &config.Config{StepUpMaxAge: 15 * time.Minute}

	pwd, fresh, stale, key := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, id := range []string{pwd, fresh, stale, key} {
		seedStampSession(t, svc, ctx, id)
	}
	svc.recordSessionAuthMethods(ctx, pwd, []string{"pwd"})
	svc.recordSessionAuthMethods(ctx, fresh, mfaAuthMethods("pwd", "totp"))
	svc.recordSessionAuthMethods(ctx, stale, mfaAuthMethods("pwd", "totp"))
	if _, err := svc.db.Pool.Exec(ctx, `UPDATE sessions SET mfa_verified_at = NOW() - INTERVAL '1 hour' WHERE id = $1`, stale); err != nil {
		t.Fatal(err)
	}
	svc.recordSessionAuthMethods(ctx, key, mfaAuthMethods("pwd", "webauthn"))

	for id, want := range map[string]string{
		pwd: ACRPassword, fresh: ACRMFAFresh, stale: ACRMFA, key: ACRPhishingResistant, uuid.NewString(): "",
	} {
		if got := svc.sessionACR(ctx, id); got != want {
			t.Errorf("session %s: acr = %q, want %q", id, got, want)
		}
	}
}

// A request that asks for more than the session proved is not minted; with no
// factor that could satisfy it, the answer says so.
func TestACRGateRefusesWhatTheSessionCannotProve(t *testing.T) {
	svc, ctx, cleanup := stampFixture(t)
	defer cleanup()
	svc.config = &config.Config{StepUpMaxAge: 15 * time.Minute}
	id := uuid.NewString()
	seedStampSession(t, svc, ctx, id)
	svc.recordSessionAuthMethods(ctx, id, []string{"pwd"})

	gin.SetMode(gin.TestMode)
	run := func(acr string) (*httptest.ResponseRecorder, bool) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/oauth/login", nil).WithContext(ctx)
		ok := svc.acrGateAllows(c, map[string]string{"client_id": "c", "session_id": id, paramACRValues: acr}, uuid.NewString(), false)
		return w, ok
	}
	if _, ok := run(""); !ok {
		t.Fatal("no acr_values must mint")
	}
	if _, ok := run(ACRPassword); !ok {
		t.Fatal("a password session satisfies urn:openidx:pwd")
	}
	w, ok := run(ACRMFA)
	if ok || w.Code != http.StatusForbidden {
		t.Fatalf("urn:openidx:mfa on a password session: ok=%v code=%d", ok, w.Code)
	}
	var body map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != errUnmetAuthnRequired {
		t.Fatalf("error = %v", body["error"])
	}
}
