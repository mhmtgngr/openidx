package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

const pushTestOrg = "00000000-0000-0000-0000-000000000010"

type pushFixture struct {
	t      *testing.T
	db     *database.PostgresDB
	ctx    context.Context
	suffix string
}

func (f *pushFixture) user(name string, org string) string {
	f.t.Helper()
	var id string
	if err := f.db.Pool.QueryRow(f.ctx,
		`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, name+"-"+f.suffix).Scan(&id); err != nil {
		f.t.Fatalf("seed user: %v", err)
	}
	return id
}

// device seeds a push device. lastSeen is SQL for last_seen_at ("NULL" for a
// row the migration could not backfill).
func (f *pushFixture) device(user, org, token string, enabled bool, created, lastSeen string) string {
	f.t.Helper()
	var id string
	if err := f.db.Pool.QueryRow(f.ctx, fmt.Sprintf(`
		INSERT INTO mfa_push_devices (user_id, device_token, platform, device_name, enabled, org_id, created_at, last_seen_at)
		VALUES ($1, $2::text, 'android', $2::text, $3, $4, %s, %s) RETURNING id::text`, created, lastSeen),
		user, token+"-"+f.suffix, enabled, org).Scan(&id); err != nil {
		f.t.Fatalf("seed device %s: %v", token, err)
	}
	return id
}

func (f *pushFixture) row(id string) (enabled bool, reason string, disabledAt *time.Time, lastSeen *time.Time) {
	f.t.Helper()
	if err := f.db.Pool.QueryRow(f.ctx, `
		SELECT COALESCE(enabled, false), COALESCE(disabled_reason, ''), disabled_at, last_seen_at
		  FROM mfa_push_devices WHERE id = $1::uuid`, id).Scan(&enabled, &reason, &disabledAt, &lastSeen); err != nil {
		f.t.Fatalf("read device %s: %v", id, err)
	}
	return
}

func (f *pushFixture) waitAudit(action string, targets ...string) {
	f.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var n int
		if err := f.db.Pool.QueryRow(f.ctx,
			`SELECT count(*) FROM audit_events WHERE action = $1 AND target_id = ANY($2::text[])`,
			action, targets).Scan(&n); err != nil {
			f.t.Fatalf("count audit: %v", err)
		}
		if n == len(targets) {
			return
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("audit %s: %d events for %d targets", action, n, len(targets))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The sweep disables (never deletes) every enabled device unseen for the
// window, in every org, writes one audit event per device, and does nothing
// the second time. The device then registering again brings it back.
func TestPushDeviceSweepDisablesOnlyTheDead(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	f := &pushFixture{t: t, db: db, ctx: orgctx.WithBypassRLS(context.Background()), suffix: fmt.Sprintf("%d", time.Now().UnixNano())}

	var orgB string
	if err := db.Pool.QueryRow(f.ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, "push-b-"+f.suffix).Scan(&orgB); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	alice := f.user("push-alice", pushTestOrg)
	bob := f.user("push-bob", orgB)

	dead := f.device(alice, pushTestOrg, "dead", true, "NOW() - interval '300 days'", "NOW() - interval '100 days'")
	alive := f.device(alice, pushTestOrg, "alive", true, "NOW() - interval '300 days'", "NOW() - interval '10 days'")
	nearly := f.device(alice, pushTestOrg, "nearly", true, "NOW() - interval '300 days'", "NOW() - interval '89 days'")
	unbackfilled := f.device(alice, pushTestOrg, "unbackfilled", true, "NOW() - interval '120 days'", "NULL")
	switchedOff := f.device(alice, pushTestOrg, "switched-off", false, "NOW() - interval '300 days'", "NOW() - interval '200 days'")
	otherOrg := f.device(bob, orgB, "other-org", true, "NOW() - interval '300 days'", "NOW() - interval '95 days'")

	cfg := &config.Config{}
	cfg.PushMFA.Enabled = true
	svc := NewService(db, nil, cfg, zap.NewNop())
	now := time.Now()
	swept, err := svc.sweepStalePushDevices(f.ctx, now, 90*24*time.Hour)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	var got []string
	for _, d := range swept {
		got = append(got, d.ID)
	}
	want := []string{dead, unbackfilled, otherOrg}
	sort.Strings(got)
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("swept %v, want %v", got, want)
	}
	for _, id := range want {
		enabled, reason, disabledAt, _ := f.row(id)
		if enabled || reason != PushDisabledStale || disabledAt == nil {
			t.Errorf("device %s: enabled=%v reason=%q disabled_at=%v, want disabled as stale", id, enabled, reason, disabledAt)
		}
	}
	for _, id := range []string{alive, nearly} {
		if enabled, reason, _, _ := f.row(id); !enabled || reason != "" {
			t.Errorf("device %s seen within the window was touched: enabled=%v reason=%q", id, enabled, reason)
		}
	}
	if enabled, reason, disabledAt, _ := f.row(switchedOff); enabled || reason != "" || disabledAt != nil {
		t.Errorf("a device the user switched off must keep no system mark: reason=%q disabled_at=%v", reason, disabledAt)
	}
	var orgOfOther string
	for _, d := range swept {
		if d.ID == otherOrg {
			orgOfOther = d.OrgID
		}
	}
	if orgOfOther != orgB {
		t.Errorf("the other org's device was reported in org %q, want %q", orgOfOther, orgB)
	}
	f.waitAudit("push_device.disabled_stale", want...)

	again, err := svc.sweepStalePushDevices(f.ctx, now, 90*24*time.Hour)
	if err != nil || len(again) != 0 {
		t.Fatalf("second sweep: %d devices (%v), want none", len(again), err)
	}
	if off, err := svc.sweepStalePushDevices(f.ctx, now, 0); err != nil || len(off) != 0 {
		t.Fatalf("a zero window must sweep nothing: %d (%v)", len(off), err)
	}

	// The phone comes back: registering again is proof of life.
	var token string
	if err := db.Pool.QueryRow(f.ctx, `SELECT device_token FROM mfa_push_devices WHERE id = $1::uuid`, dead).Scan(&token); err != nil {
		t.Fatal(err)
	}
	orgCtx := orgctx.With(context.Background(), orgctx.Org{ID: pushTestOrg})
	if _, err := svc.RegisterPushMFADevice(orgCtx, alice, &PushMFAEnrollment{DeviceToken: token, Platform: "android", DeviceName: "Back again"}, "198.51.100.4"); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	enabled, reason, disabledAt, lastSeen := f.row(dead)
	if !enabled || reason != "" || disabledAt != nil {
		t.Fatalf("re-registered device: enabled=%v reason=%q disabled_at=%v, want enabled with no mark", enabled, reason, disabledAt)
	}
	if lastSeen == nil || time.Since(*lastSeen) > time.Minute {
		t.Fatalf("re-registered device last_seen_at = %v, want now", lastSeen)
	}

	// Answering a challenge (approve or deny) is seen too.
	if err := svc.updatePushDeviceLastUsed(orgCtx, nearly); err != nil {
		t.Fatal(err)
	}
	if _, _, _, lastSeen := f.row(nearly); lastSeen == nil || time.Since(*lastSeen) > time.Minute {
		t.Fatalf("answered device last_seen_at = %v, want now", lastSeen)
	}

	// A new registration starts seen.
	dev, err := svc.RegisterPushMFADevice(orgCtx, alice, &PushMFAEnrollment{DeviceToken: "brand-new-" + f.suffix, Platform: "ios", DeviceName: "New"}, "198.51.100.4")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, _, _, lastSeen := f.row(dev.ID); lastSeen == nil || time.Since(*lastSeen) > time.Minute {
		t.Fatalf("new device last_seen_at = %v, want now", lastSeen)
	}
}

// The console's Sign-in methods card: admin only, the caller's org only,
// every change audited.
func TestAdminSignInMethods(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)
	f := &pushFixture{t: t, db: db, ctx: orgctx.WithBypassRLS(context.Background()), suffix: fmt.Sprintf("%d", time.Now().UnixNano())}

	var orgB string
	if err := db.Pool.QueryRow(f.ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, "signin-b-"+f.suffix).Scan(&orgB); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	admin := f.user("signin-admin", pushTestOrg)
	target := f.user("signin-target", pushTestOrg)
	stranger := f.user("signin-stranger", orgB)
	stale := f.device(target, pushTestOrg, "stale-phone", true, "NOW() - interval '200 days'", "NOW() - interval '60 days'")
	fresh := f.device(target, pushTestOrg, "fresh-phone", true, "NOW() - interval '200 days'", "NOW() - interval '1 day'")
	if _, err := db.Pool.Exec(f.ctx, `INSERT INTO mfa_backup_codes (user_id, code_hash, org_id) VALUES ($1, 'h1', $2), ($1, 'h2', $2)`, target, pushTestOrg); err != nil {
		t.Fatalf("seed backup codes: %v", err)
	}

	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	call := func(roles []string, method, path string, params gin.Params, handler gin.HandlerFunc) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Params = params
		c.Set("user_id", admin)
		c.Set("roles", roles)
		c.Request = httptest.NewRequest(method, path, nil).
			WithContext(orgctx.With(context.Background(), orgctx.Org{ID: pushTestOrg}))
		handler(c)
		return w
	}
	admins := []string{"admin"}

	w := call(admins, http.MethodGet, "/", gin.Params{{Key: "id", Value: target}}, svc.handleAdminGetSignInMethods)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var m SignInMethods
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	statuses := map[string]string{}
	for _, d := range m.PushDevices {
		statuses[d.ID] = d.Status
		if d.LastSeenAt == nil {
			t.Errorf("device %s has no last_seen_at", d.ID)
		}
	}
	if statuses[stale] != PushStatusStale || statuses[fresh] != PushStatusActive {
		t.Fatalf("statuses = %v", statuses)
	}
	if m.BackupCodesRemaining != 2 || m.StaleAfterDays != 30 || m.Summary.UsableFactors != 1 || m.Summary.OnlyStalePush {
		t.Fatalf("listing = %+v", m)
	}

	if w := call([]string{"user"}, http.MethodGet, "/", gin.Params{{Key: "id", Value: target}}, svc.handleAdminGetSignInMethods); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin list: %d, want 403", w.Code)
	}
	if w := call(admins, http.MethodGet, "/", gin.Params{{Key: "id", Value: stranger}}, svc.handleAdminGetSignInMethods); w.Code != http.StatusNotFound {
		t.Fatalf("another org's user: %d, want 404", w.Code)
	}

	// Disable the fresh phone: it keeps its row, marked by an administrator.
	w = call(admins, http.MethodPost, "/", gin.Params{{Key: "id", Value: target}, {Key: "method", Value: "push"}, {Key: "credential_id", Value: fresh}}, svc.handleAdminDisableSignInCredential)
	if w.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}
	if enabled, reason, _, _ := f.row(fresh); enabled || reason != PushDisabledAdmin {
		t.Fatalf("disabled device: enabled=%v reason=%q", enabled, reason)
	}
	f.waitAudit("push_device.disabled_admin", target)
	if w := call(admins, http.MethodPost, "/", gin.Params{{Key: "id", Value: target}, {Key: "method", Value: "webauthn"}, {Key: "credential_id", Value: fresh}}, svc.handleAdminDisableSignInCredential); w.Code != http.StatusBadRequest {
		t.Fatalf("disable a non-push method: %d, want 400", w.Code)
	}
	// Another org's device id under this org's user: not found.
	strangerPhone := f.device(stranger, orgB, "stranger-phone", true, "NOW()", "NOW()")
	if w := call(admins, http.MethodPost, "/", gin.Params{{Key: "id", Value: target}, {Key: "method", Value: "push"}, {Key: "credential_id", Value: strangerPhone}}, svc.handleAdminDisableSignInCredential); w.Code != http.StatusNotFound {
		t.Fatalf("disable another user's device: %d, want 404", w.Code)
	}

	// Remove the stale phone and the backup codes.
	w = call(admins, http.MethodDelete, "/", gin.Params{{Key: "id", Value: target}, {Key: "method", Value: "push"}, {Key: "credential_id", Value: stale}}, svc.handleAdminRemoveSignInCredential)
	if w.Code != http.StatusOK {
		t.Fatalf("remove push: %d %s", w.Code, w.Body.String())
	}
	var left int
	if err := db.Pool.QueryRow(f.ctx, `SELECT count(*) FROM mfa_push_devices WHERE id = $1::uuid`, stale).Scan(&left); err != nil || left != 0 {
		t.Fatalf("removed device still there: %d (%v)", left, err)
	}
	w = call(admins, http.MethodDelete, "/", gin.Params{{Key: "id", Value: target}, {Key: "method", Value: "backup_codes"}}, svc.handleAdminRemoveSignInMethod)
	if w.Code != http.StatusOK {
		t.Fatalf("remove backup codes: %d %s", w.Code, w.Body.String())
	}
	if w := call(admins, http.MethodDelete, "/", gin.Params{{Key: "id", Value: target}, {Key: "method", Value: "totp"}}, svc.handleAdminRemoveSignInMethod); w.Code != http.StatusNotFound {
		t.Fatalf("remove TOTP the user does not have: %d, want 404", w.Code)
	}
	if w := call(admins, http.MethodDelete, "/", gin.Params{{Key: "id", Value: target}, {Key: "method", Value: "password"}}, svc.handleAdminRemoveSignInMethod); w.Code != http.StatusBadRequest {
		t.Fatalf("remove an unknown method: %d, want 400", w.Code)
	}
	f.waitAudit("mfa.admin_removed", target, target)
}
