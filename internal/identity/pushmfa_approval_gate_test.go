package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// The push prompt is the last thing between a stolen password and a session.
// These cases pin the three questions it now asks that it did not ask before:
// who is answering, how many times they may guess, and whether the device that
// received the prompt is still allowed to answer for its user.
//
// They run against a real Postgres and a miniredis because all three read
// state: two tables and a counter.

var pushGateSchema = []string{
	`CREATE TABLE IF NOT EXISTS mfa_push_devices (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL,
		device_token TEXT UNIQUE NOT NULL, platform VARCHAR(20) NOT NULL,
		device_name VARCHAR(255), device_model VARCHAR(100), os_version VARCHAR(50),
		app_version VARCHAR(50), enabled BOOLEAN DEFAULT true, trusted BOOLEAN DEFAULT false,
		last_ip VARCHAR(45), created_at TIMESTAMPTZ DEFAULT NOW(),
		last_used_at TIMESTAMPTZ, expires_at TIMESTAMPTZ,
		agent_id VARCHAR(64), device_id VARCHAR(64), enrollment_session_id UUID)`,
	`CREATE TABLE IF NOT EXISTS mfa_push_challenges (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL,
		device_id UUID NOT NULL, challenge_code VARCHAR(10) NOT NULL,
		status VARCHAR(20) DEFAULT 'pending', session_info JSONB,
		created_at TIMESTAMPTZ DEFAULT NOW(), expires_at TIMESTAMPTZ NOT NULL,
		responded_at TIMESTAMPTZ, ip_address VARCHAR(45), user_agent TEXT,
		location VARCHAR(255))`,
	`CREATE TABLE IF NOT EXISTS enrolled_agents (
		agent_id VARCHAR(64) PRIMARY KEY, status VARCHAR(20) NOT NULL DEFAULT 'active',
		enrolled_by_user_id UUID)`,
}

const (
	pushOrg      = "00000000-0000-0000-0000-0000000000f0"
	pushOwner    = "11111111-0000-0000-0000-0000000000f1"
	pushOther    = "11111111-0000-0000-0000-0000000000f2"
	pushDevSelf  = "22222222-0000-0000-0000-0000000000f1"
	pushDevAgent = "22222222-0000-0000-0000-0000000000f2"
	pushDevOff   = "22222222-0000-0000-0000-0000000000f3"
)

type pushGateFixture struct {
	svc   *Service
	db    *database.PostgresDB
	redis *miniredis.Miniredis
	ctx   context.Context
}

func newPushGateFixture(t *testing.T) *pushGateFixture {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: pushOrg})
	for _, stmt := range pushGateSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	for _, seed := range []string{
		// A plain self-enrolled authenticator: no agent behind it.
		`INSERT INTO mfa_push_devices (id, user_id, device_token, platform, enabled) VALUES ('` + pushDevSelf + `','` + pushOwner + `','ntfy:self','android',true)`,
		// One registered by a device enrolment, tied to an agent (v135 linkage).
		`INSERT INTO mfa_push_devices (id, user_id, device_token, platform, enabled, agent_id) VALUES ('` + pushDevAgent + `','` + pushOwner + `','ntfy:agent','android',true,'agent-phone')`,
		// One the user switched off.
		`INSERT INTO mfa_push_devices (id, user_id, device_token, platform, enabled) VALUES ('` + pushDevOff + `','` + pushOwner + `','ntfy:off','android',false)`,
		`INSERT INTO enrolled_agents (agent_id, status, enrolled_by_user_id) VALUES ('agent-phone','active','` + pushOwner + `')`,
	} {
		if _, err := db.Pool.Exec(ctx, seed); err != nil {
			t.Fatalf("seed: %v\n%s", err, seed)
		}
	}

	mini := miniredis.RunT(t)
	svc := &Service{
		db:     db,
		redis:  &database.RedisClient{Client: redis.NewClient(&redis.Options{Addr: mini.Addr()})},
		cfg:    &config.Config{},
		logger: zap.NewNop(),
	}
	return &pushGateFixture{svc: svc, db: db, redis: mini, ctx: ctx}
}

// challenge writes a pending challenge and returns its id and code.
func (f *pushGateFixture) challenge(t *testing.T, id, userID, deviceID, code string) *PushMFAChallenge {
	t.Helper()
	ch := &PushMFAChallenge{
		ID: id, UserID: userID, DeviceID: deviceID, ChallengeCode: code,
		Status: "pending", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := f.svc.storePushChallenge(f.ctx, ch); err != nil {
		t.Fatalf("store challenge: %v", err)
	}
	return ch
}

func (f *pushGateFixture) status(t *testing.T, id string) string {
	t.Helper()
	var st string
	if err := f.db.Pool.QueryRow(f.ctx, `SELECT status FROM mfa_push_challenges WHERE id=$1`, id).Scan(&st); err != nil {
		t.Fatalf("read status: %v", err)
	}
	return st
}

// TestPushApprovalIsAnsweredOnlyByItsOwnUser is the authorization case. The
// route is on the authenticated identity group and isIdentitySelfService admits
// every authenticated user to anything under /mfa/, so the only thing that can
// make "the caller's own MFA verification" true is this comparison.
func TestPushApprovalIsAnsweredOnlyByItsOwnUser(t *testing.T) {
	f := newPushGateFixture(t)
	const id = "33333333-0000-0000-0000-0000000000f1"
	f.challenge(t, id, pushOwner, pushDevSelf, "42")

	ok, err := f.svc.VerifyPushMFAChallenge(f.ctx, pushOther, &PushMFAChallengeResponse{
		ChallengeID: id, ChallengeCode: "42", Approved: true,
	})
	if ok {
		t.Fatal("another user approved this challenge")
	}
	if !errors.Is(err, ErrPushChallengeNotYours) {
		t.Errorf("err = %v, want ErrPushChallengeNotYours", err)
	}
	if st := f.status(t, id); st != "pending" {
		t.Errorf("the challenge was moved to %q by a stranger's attempt", st)
	}

	// An unauthenticated (empty) subject is refused for the same reason.
	if ok, err := f.svc.VerifyPushMFAChallenge(f.ctx, "", &PushMFAChallengeResponse{
		ChallengeID: id, ChallengeCode: "42", Approved: true,
	}); ok || !errors.Is(err, ErrPushChallengeNotYours) {
		t.Errorf("empty caller: ok=%v err=%v", ok, err)
	}

	// The owner still gets through.
	if ok, err := f.svc.VerifyPushMFAChallenge(f.ctx, pushOwner, &PushMFAChallengeResponse{
		ChallengeID: id, ChallengeCode: "42", Approved: true,
	}); !ok || err != nil {
		t.Fatalf("the owner could not approve their own challenge: ok=%v err=%v", ok, err)
	}
	if st := f.status(t, id); st != "approved" {
		t.Errorf("status = %q, want approved", st)
	}
}

// TestPushNumberMatchIsNotGuessable: the code is two digits, ninety values. A
// wrong guess used to leave the challenge pending, so all ninety could be
// walked. Three wrong answers now burn it.
func TestPushNumberMatchIsNotGuessable(t *testing.T) {
	f := newPushGateFixture(t)
	const id = "33333333-0000-0000-0000-0000000000f2"
	f.challenge(t, id, pushOwner, pushDevSelf, "77")

	for i := 1; i <= pushApprovalAttemptLimit; i++ {
		ok, err := f.svc.VerifyPushMFAChallenge(f.ctx, pushOwner, &PushMFAChallengeResponse{
			ChallengeID: id, ChallengeCode: "11", Approved: true,
		})
		if ok || err == nil {
			t.Fatalf("attempt %d: a wrong code was accepted (ok=%v err=%v)", i, ok, err)
		}
	}

	if st := f.status(t, id); st != "denied" {
		t.Fatalf("after %d wrong codes the challenge is %q, want denied", pushApprovalAttemptLimit, st)
	}
	// And the right code no longer helps: the challenge is spent.
	if ok, _ := f.svc.VerifyPushMFAChallenge(f.ctx, pushOwner, &PushMFAChallengeResponse{
		ChallengeID: id, ChallengeCode: "77", Approved: true,
	}); ok {
		t.Error("the correct code was accepted after the challenge was denied")
	}
}

// TestPushAttemptCounterWithoutRedisIsStrict: no counter must never read as
// unlimited guesses. With no Redis the first wrong code is the last.
func TestPushAttemptCounterWithoutRedisIsStrict(t *testing.T) {
	f := newPushGateFixture(t)
	f.svc.redis = nil
	const id = "33333333-0000-0000-0000-0000000000f3"
	f.challenge(t, id, pushOwner, pushDevSelf, "55")

	if ok, err := f.svc.VerifyPushMFAChallenge(f.ctx, pushOwner, &PushMFAChallengeResponse{
		ChallengeID: id, ChallengeCode: "10", Approved: true,
	}); ok || err == nil {
		t.Fatalf("wrong code accepted: ok=%v err=%v", ok, err)
	}
	if st := f.status(t, id); st != "denied" {
		t.Errorf("status = %q, want denied — with no counter a wrong code must be final", st)
	}
}

// TestPushApprovalChecksTheApprovingDevice is the design's own sentence: a
// device that is pending approval or revoked must not be able to approve.
func TestPushApprovalChecksTheApprovingDevice(t *testing.T) {
	f := newPushGateFixture(t)

	t.Run("a revoked enrolled device cannot approve", func(t *testing.T) {
		const id = "33333333-0000-0000-0000-0000000000f4"
		f.challenge(t, id, pushOwner, pushDevAgent, "31")
		if _, err := f.db.Pool.Exec(f.ctx,
			`UPDATE enrolled_agents SET status='revoked' WHERE agent_id='agent-phone'`); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		defer f.db.Pool.Exec(f.ctx, `UPDATE enrolled_agents SET status='active' WHERE agent_id='agent-phone'`) //nolint:errcheck // test cleanup

		ok, err := f.svc.VerifyPushMFAChallenge(f.ctx, pushOwner, &PushMFAChallengeResponse{
			ChallengeID: id, ChallengeCode: "31", Approved: true,
		})
		if ok {
			t.Fatal("a revoked phone approved a sign-in")
		}
		if !errors.Is(err, ErrPushDeviceNotApprovable) {
			t.Errorf("err = %v, want ErrPushDeviceNotApprovable", err)
		}
	})

	t.Run("a pending enrolled device cannot approve", func(t *testing.T) {
		const id = "33333333-0000-0000-0000-0000000000f5"
		f.challenge(t, id, pushOwner, pushDevAgent, "32")
		if _, err := f.db.Pool.Exec(f.ctx,
			`UPDATE enrolled_agents SET status='pending' WHERE agent_id='agent-phone'`); err != nil {
			t.Fatalf("pend: %v", err)
		}
		defer f.db.Pool.Exec(f.ctx, `UPDATE enrolled_agents SET status='active' WHERE agent_id='agent-phone'`) //nolint:errcheck // test cleanup

		if ok, err := f.svc.VerifyPushMFAChallenge(f.ctx, pushOwner, &PushMFAChallengeResponse{
			ChallengeID: id, ChallengeCode: "32", Approved: true,
		}); ok || !errors.Is(err, ErrPushDeviceNotApprovable) {
			t.Errorf("pending device: ok=%v err=%v", ok, err)
		}
	})

	t.Run("a disabled registration cannot approve", func(t *testing.T) {
		const id = "33333333-0000-0000-0000-0000000000f6"
		f.challenge(t, id, pushOwner, pushDevOff, "33")
		if ok, err := f.svc.VerifyPushMFAChallenge(f.ctx, pushOwner, &PushMFAChallengeResponse{
			ChallengeID: id, ChallengeCode: "33", Approved: true,
		}); ok || !errors.Is(err, ErrPushDeviceNotApprovable) {
			t.Errorf("disabled device: ok=%v err=%v", ok, err)
		}
	})

	t.Run("an active enrolled device still approves", func(t *testing.T) {
		const id = "33333333-0000-0000-0000-0000000000f7"
		f.challenge(t, id, pushOwner, pushDevAgent, "34")
		if ok, err := f.svc.VerifyPushMFAChallenge(f.ctx, pushOwner, &PushMFAChallengeResponse{
			ChallengeID: id, ChallengeCode: "34", Approved: true,
		}); !ok || err != nil {
			t.Errorf("an active enrolled phone was refused: ok=%v err=%v", ok, err)
		}
	})

	t.Run("a self-enrolled authenticator still approves", func(t *testing.T) {
		const id = "33333333-0000-0000-0000-0000000000f8"
		f.challenge(t, id, pushOwner, pushDevSelf, "35")
		if ok, err := f.svc.VerifyPushMFAChallenge(f.ctx, pushOwner, &PushMFAChallengeResponse{
			ChallengeID: id, ChallengeCode: "35", Approved: true,
		}); !ok || err != nil {
			t.Errorf("a device with no agent behind it was refused: ok=%v err=%v", ok, err)
		}
	})

	// A DENY is never refused on device grounds. A revoked phone saying "this
	// wasn't me" is a signal worth keeping.
	t.Run("a revoked device may still deny", func(t *testing.T) {
		const id = "33333333-0000-0000-0000-0000000000f9"
		f.challenge(t, id, pushOwner, pushDevAgent, "36")
		if _, err := f.db.Pool.Exec(f.ctx,
			`UPDATE enrolled_agents SET status='revoked' WHERE agent_id='agent-phone'`); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		defer f.db.Pool.Exec(f.ctx, `UPDATE enrolled_agents SET status='active' WHERE agent_id='agent-phone'`) //nolint:errcheck // test cleanup

		ok, err := f.svc.VerifyPushMFAChallenge(f.ctx, pushOwner, &PushMFAChallengeResponse{
			ChallengeID: id, Approved: false, Reported: true,
		})
		if ok || err != nil {
			t.Fatalf("a deny from a revoked device was refused: ok=%v err=%v", ok, err)
		}
		if st := f.status(t, id); st != "reported" {
			t.Errorf("status = %q, want reported", st)
		}
	})
}

// TestApprovingDeviceUsableReasons pins the reasons, because they are what an
// operator reads in the log when an approval is refused.
func TestApprovingDeviceUsableReasons(t *testing.T) {
	f := newPushGateFixture(t)

	for _, tc := range []struct {
		name     string
		deviceID string
		setup    string
		wantOK   bool
	}{
		{"self-enrolled and enabled", pushDevSelf, "", true},
		{"enrolled and active", pushDevAgent, "", true},
		{"disabled registration", pushDevOff, "", false},
		{"registration gone", "22222222-0000-0000-0000-0000000000ff", "", false},
		{"agent missing from the fleet", pushDevAgent, `DELETE FROM enrolled_agents WHERE agent_id='agent-phone'`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != "" {
				if _, err := f.db.Pool.Exec(f.ctx, tc.setup); err != nil {
					t.Fatalf("setup: %v", err)
				}
				defer f.db.Pool.Exec(f.ctx, //nolint:errcheck // test cleanup
					`INSERT INTO enrolled_agents (agent_id, status, enrolled_by_user_id) VALUES ('agent-phone','active','`+pushOwner+`') ON CONFLICT (agent_id) DO NOTHING`)
			}
			ok, why, err := f.svc.approvingDeviceUsable(f.ctx, tc.deviceID)
			if err != nil {
				t.Fatalf("approvingDeviceUsable: %v", err)
			}
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v (reason %q)", ok, tc.wantOK, why)
			}
			if !ok && why == "" {
				t.Error("refused with no reason; the operator's log would say nothing")
			}
		})
	}
}

// TestPushChallengeIsRaisedOnlyForTheCaller closes the other half of the same
// hole: POST /mfa/push/challenge took user_id out of the body on a route every
// authenticated user reaches, so one account could make another account's phone
// buzz on demand — MFA fatigue, from the product's own endpoint — and learn the
// challenge id it got back. The login flow does not come through here; it calls
// CreatePushMFAChallenge in-process.
//
// The service is built with no database on purpose: the refusal must happen
// before anything is created, so a handler that let the request through would
// panic or error rather than quietly pass.
func TestPushChallengeIsRaisedOnlyForTheCaller(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{logger: zap.NewNop(), cfg: &config.Config{}}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/identity/mfa/push/challenge",
		strings.NewReader(`{"user_id":"`+pushOther+`"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("user_id", pushOwner)

	s.handleCreatePushChallenge(c)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 — one user raised a push prompt on another's phone (body %s)", w.Code, w.Body.String())
	}

	// And with no authenticated subject at all.
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest(http.MethodPost, "/api/v1/identity/mfa/push/challenge",
		strings.NewReader(`{"user_id":"`+pushOwner+`"}`))
	c2.Request.Header.Set("Content-Type", "application/json")

	s.handleCreatePushChallenge(c2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401 for an unauthenticated caller", w2.Code)
	}
}
