package identity

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The four second-factor tables v146 belted, and the one thing about them that
// is easy to get backwards.
//
// internal/oauth/mfa_policy.go decides whether to demand a second factor by
// asking each enrolment table in turn, DISCARDING THE ERROR, and treating a nil
// result as "not enrolled":
//
//	if smsEnr, _ := s.identityService.GetSMSEnrollment(ctx, user.ID); smsEnr != nil && ...
//
// It runs on the sign-in path, where an organization has not always been
// resolved. Under FORCE RLS an unset app.org_id returns no rows, which is
// indistinguishable from a user who never enrolled — so for a user whose ONLY
// factor is SMS, adding the belt naively would sign them in with no second
// factor at all. That is the opposite direction from v145's
// HasActiveBypassCode, where the same mechanism happened to fail safe, and it
// is why the direction has to be checked rather than assumed.
//
// TestMFAFactorSurvivesAnOrglessRead is that check. The rest prove the org
// predicate the bypass leans on is load-bearing and not decorative.
//
// WHAT THESE CANNOT PROVE. The tables below are hand-rolled without policies,
// and the pool connects as a superuser, which bypasses row-level security
// whatever the table says — so nothing here exercises the belt itself. These
// pin the CODE's half of the contract: the bypass is present, the org term is
// real, and the row is filed under its user. The belt's half is proved under a
// NOSUPERUSER NOBYPASSRLS role by test/integration/cross_org_test.go, which is
// the only place in this repository where FORCE ROW LEVEL SECURITY is actually
// in force.
const mfaFactorIsolationSchema = `
CREATE TABLE IF NOT EXISTS mfa_sms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    phone_number VARCHAR(20) NOT NULL,
    country_code VARCHAR(5) NOT NULL DEFAULT '+1',
    verified BOOLEAN DEFAULT false,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    verified_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    UNIQUE(user_id));
CREATE TABLE IF NOT EXISTS mfa_email_otp (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email_address VARCHAR(255) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    UNIQUE(user_id));
CREATE TABLE IF NOT EXISTS mfa_phone_call (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    phone_number VARCHAR(20) NOT NULL,
    country_code VARCHAR(5) NOT NULL,
    verified BOOLEAN DEFAULT false,
    enabled BOOLEAN DEFAULT true,
    voice_language VARCHAR(10) DEFAULT 'en-US',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    UNIQUE(user_id));
CREATE TABLE IF NOT EXISTS mfa_otp_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method VARCHAR(20) NOT NULL,
    recipient VARCHAR(255) NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    status VARCHAR(20) DEFAULT 'pending',
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ);
`

// newMFAFactorService reuses the two-org fixture v145's suite already builds
// and adds the four factor tables to it.
func newMFAFactorService(t *testing.T) (*Service, context.Context, context.Context) {
	t.Helper()
	s, aCtx, bCtx, db := newCredentialIsolationService(t)
	if _, err := db.Pool.Exec(context.Background(), mfaFactorIsolationSchema); err != nil {
		t.Fatalf("mfa factor schema: %v", err)
	}
	return s, aCtx, bCtx
}

// THE ONE THAT MATTERS. A factor enrolled inside an organization must still be
// visible to a read that carries none, because the caller that matters most —
// the MFA policy on the sign-in path — reads an invisible factor as an absent
// one and waves the sign-in through.
func TestMFAFactorSurvivesAnOrglessRead(t *testing.T) {
	s, _, bCtx := newMFAFactorService(t)
	orgless := context.Background()

	if err := s.storeSMSEnrollment(bCtx, &SMSEnrollment{
		ID: uuid.New().String(), UserID: credUserB, PhoneNumber: "5551234567",
		CountryCode: "+1", Verified: true, Enabled: true, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("enrol sms: %v", err)
	}
	if err := s.storeEmailOTPEnrollment(bCtx, &EmailOTPEnrollment{
		ID: uuid.New().String(), UserID: credUserB, EmailAddress: "bob@example.test",
		Enabled: true, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("enrol email otp: %v", err)
	}
	if _, err := s.EnrollPhoneCall(bCtx, credUserB, "5559876543", "+1"); err != nil {
		// The challenge send may fail with no voice provider configured; the
		// enrolment row is what this test is about, so only a write failure
		// matters and that surfaces on the read below.
		t.Logf("EnrollPhoneCall returned %v (expected without a voice provider)", err)
	}

	t.Run("sms enrolment is visible with no org on the context", func(t *testing.T) {
		got, err := s.GetSMSEnrollment(orgless, credUserB)
		if err != nil || got == nil {
			t.Fatalf("an enrolled SMS factor read as ABSENT with no org on the context (err=%v). "+
				"mfa_policy.go discards this error and treats nil as 'not enrolled', so a user "+
				"whose only factor is SMS would sign in with no second factor at all", err)
		}
		if !got.Verified || !got.Enabled {
			t.Errorf("enrolment came back verified=%v enabled=%v; the policy requires both",
				got.Verified, got.Enabled)
		}
	})

	t.Run("email otp enrolment is visible with no org on the context", func(t *testing.T) {
		got, err := s.GetEmailOTPEnrollment(orgless, credUserB)
		if err != nil || got == nil {
			t.Fatalf("an enrolled e-mail OTP factor read as ABSENT with no org on the context (err=%v)", err)
		}
	})

	t.Run("phone call enrolment is visible with no org on the context", func(t *testing.T) {
		if _, err := s.GetPhoneCallEnrollment(orgless, credUserB); err != nil {
			t.Fatalf("an enrolled voice factor read as ABSENT with no org on the context: %v", err)
		}
	})
}

// The enrolment must carry the user's organization, not the caller's, and not
// nothing: the row is written on a bypassed connection, so the column is the
// only thing that files it.
func TestMFAFactorIsStampedWithTheUsersOrg(t *testing.T) {
	s, _, bCtx := newMFAFactorService(t)

	if err := s.storeSMSEnrollment(bCtx, &SMSEnrollment{
		ID: uuid.New().String(), UserID: credUserB, PhoneNumber: "5551234567",
		CountryCode: "+1", Verified: true, Enabled: true, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("enrol: %v", err)
	}

	var org string
	if err := s.db.Pool.QueryRow(context.Background(),
		"SELECT org_id::text FROM mfa_sms WHERE user_id = $1", credUserB).Scan(&org); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if org != credOrgB {
		t.Errorf("SMS enrolment filed under org %s, want %s (the user's own)", org, credOrgB)
	}
}

// The bypass is only safe because the org term in each predicate is real. Move
// a row to another organization behind the query's back and it must vanish —
// if it does not, the predicate is decoration and the bypass is a hole.
func TestMFAFactorOrgPredicateIsLoadBearing(t *testing.T) {
	s, _, bCtx := newMFAFactorService(t)

	if err := s.storeSMSEnrollment(bCtx, &SMSEnrollment{
		ID: uuid.New().String(), UserID: credUserB, PhoneNumber: "5551234567",
		CountryCode: "+1", Verified: true, Enabled: true, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if _, err := s.db.Pool.Exec(context.Background(),
		"UPDATE mfa_sms SET org_id = $1 WHERE user_id = $2", credOrgA, credUserB); err != nil {
		t.Fatalf("doctor the row: %v", err)
	}

	if got, err := s.GetSMSEnrollment(context.Background(), credUserB); err == nil && got != nil {
		t.Error("a row whose org_id no longer matches its user was still returned; " +
			"the org term in the predicate does nothing, and the RLS bypass around it is unguarded")
	}
}

// OTP challenges carry the code hash, the recipient and the requester's IP.
// They are written on the bypassed verification path, so the same two
// properties have to hold: filed under the user's org, and found again by the
// rate limiter that decides how many codes a user may ask for.
func TestOTPChallengeIsScopedAndCountable(t *testing.T) {
	s, _, bCtx := newMFAFactorService(t)

	ch := &OTPChallenge{
		ID: uuid.New().String(), UserID: credUserB, Method: "sms",
		Recipient: "+15551234567", CodeHash: "hash", MaxAttempts: 3,
		Status: "pending", IPAddress: "10.0.0.9", UserAgent: "test",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := s.storeOTPChallenge(bCtx, ch); err != nil {
		t.Fatalf("store challenge: %v", err)
	}

	var org string
	if err := s.db.Pool.QueryRow(context.Background(),
		"SELECT org_id::text FROM mfa_otp_challenges WHERE id = $1", ch.ID).Scan(&org); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if org != credOrgB {
		t.Errorf("challenge filed under org %s, want %s", org, credOrgB)
	}

	// The rate limiter, on a context with no organization — the shape the
	// oauth service's step-up reaches it on. A count of zero here does not
	// lock anyone out; it lets them request codes without limit.
	n, err := s.countRecentOTPChallenges(context.Background(), credUserB, "sms", time.Hour)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("the OTP rate limiter counted %d challenges, want 1; at zero it stops limiting", n)
	}

	// And the verification path finds the challenge it just wrote.
	got, err := s.getLatestOTPChallenge(context.Background(), credUserB, "sms")
	if err != nil || got == nil {
		t.Fatalf("the pending challenge was invisible to verification (err=%v)", err)
	}
	if got.ID != ch.ID {
		t.Errorf("got challenge %s, want %s", got.ID, ch.ID)
	}
}

// A user in another organization has no factors of their own; the reads are
// keyed by user, so this is about the fixture staying honest rather than about
// a caller crossing a boundary — handlers_otp.go takes user_id from the
// session and never from a path parameter.
func TestMFAFactorReadsAreKeyedByUser(t *testing.T) {
	s, aCtx, bCtx := newMFAFactorService(t)
	_ = aCtx

	if err := s.storeSMSEnrollment(bCtx, &SMSEnrollment{
		ID: uuid.New().String(), UserID: credUserB, PhoneNumber: "5551234567",
		CountryCode: "+1", Verified: true, Enabled: true, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if got, err := s.GetSMSEnrollment(orgctx.With(context.Background(),
		orgctx.Org{ID: credOrgA}), credUserA); err == nil && got != nil {
		t.Error("org A's user has an SMS enrolment it never made")
	}
}
