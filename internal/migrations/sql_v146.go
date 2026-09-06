package migrations

// Migration v146 — the second factors that were left half-scoped.
//
// OpenIDX offers six second factors. Three of them — mfa_totp, mfa_push_devices
// and mfa_webauthn — carry org_id and sit behind the FORCE RLS belt. The other
// three — mfa_sms, mfa_email_otp, mfa_phone_call — do not, and neither does
// mfa_otp_challenges, the live challenge rows behind the first two. The
// asymmetry is not hidden: internal/admin/mfa_management.go says it out loud,
// in a comment above a SELECT that lists all six side by side, three of them
// with `AND x.org_id = $1` and three without. It reads as a fact of the
// schema. It is a gap in the belt.
//
// Every query against these four is keyed on user_id, and a user belongs to
// exactly one organization, so this is DEPTH rather than a live hole — the
// v143 trusted_browsers case, not the v145 hardware_tokens one. Two things
// make it worth doing anyway. mfa_otp_challenges holds the code hash, the
// recipient (a real phone number or e-mail address) and the requester's IP for
// every OTP in flight, with no tenant column at all; and the challenge's
// status and attempt counter are updated by BARE id, which is safe only for as
// long as no handler ever accepts a challenge id from a caller.
//
// It also finishes a pair v143 left half-done: that migration belted
// phone_call_challenges without belting mfa_phone_call, the enrolment those
// challenges are issued against.
//
// THE DANGEROUS PART OF THIS BATCH IS THE BELT ITSELF, and it points the
// opposite way from v145. internal/oauth/mfa_policy.go's evaluateMFA decides
// whether to demand a second factor by asking each enrolment table in turn,
// discarding the error, and treating a nil result as "not enrolled":
//
//	if smsEnr, _ := s.identityService.GetSMSEnrollment(ctx, user.ID); smsEnr != nil && ...
//
// Under FORCE RLS on a connection with no app.org_id, that read returns
// nothing — indistinguishable from a user who never enrolled. For a user whose
// ONLY factor is SMS, ev.Enabled would stay false and the sign-in would be
// waved through with no second factor at all. Adding the belt naively here
// does not lock anybody out; it lets everybody in. v145's HasActiveBypassCode
// had the same mechanism pointing the safe way round, which is exactly why the
// direction has to be checked each time rather than assumed. So the policy
// reads run bypassed with the tenant in the predicate, and a test pins it.
//
// UNIQUE(user_id) STAYS AS IT IS, and it is the third case in the taxonomy the
// last two migrations built. v143 re-scoped social_providers.provider_key
// because an install-wide key let the first tenant take a name from everybody.
// v144 kept saml_service_providers.entity_id because that key is what resolves
// the tenant. Here the key is neither: user_id already DETERMINES org_id, so
// UNIQUE(user_id) and UNIQUE(org_id, user_id) accept exactly the same rows —
// except that the second would also permit one user to hold two enrolments in
// two organizations, which is not a tenancy feature but a corrupt row. The
// narrower constraint is the stronger one. Re-scoping a unique key is not a
// step in this programme's recipe; it is a judgement, and here it says no.
//
// Plain statements only — the runner's splitSQL cannot handle DO $$ blocks.
var mfaFactorTenantScopeUp = `-- Migration 146: org_id + FORCE RLS on the remaining second factors.

-- mfa_sms -------------------------------------------------------------------
ALTER TABLE mfa_sms ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE mfa_sms m SET org_id = u.org_id FROM users u WHERE m.user_id = u.id AND m.org_id IS NULL;
UPDATE mfa_sms SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE mfa_sms ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mfa_sms_org ON mfa_sms(org_id);

-- UNIQUE(user_id) is left alone: user_id already determines org_id, so a
-- per-org key would accept strictly more rows, and the extra rows it would
-- accept are corrupt ones. See the file comment.

DROP POLICY IF EXISTS pol_mfa_sms_org_scope ON mfa_sms;
CREATE POLICY pol_mfa_sms_org_scope ON mfa_sms
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE mfa_sms ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_sms FORCE  ROW LEVEL SECURITY;

-- mfa_email_otp -------------------------------------------------------------
ALTER TABLE mfa_email_otp ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE mfa_email_otp m SET org_id = u.org_id FROM users u WHERE m.user_id = u.id AND m.org_id IS NULL;
UPDATE mfa_email_otp SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE mfa_email_otp ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mfa_email_otp_org ON mfa_email_otp(org_id);

DROP POLICY IF EXISTS pol_mfa_email_otp_org_scope ON mfa_email_otp;
CREATE POLICY pol_mfa_email_otp_org_scope ON mfa_email_otp
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE mfa_email_otp ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_email_otp FORCE  ROW LEVEL SECURITY;

-- mfa_phone_call ------------------------------------------------------------
-- v143 belted phone_call_challenges without belting the enrolment those
-- challenges are issued against; this closes the pair. user_id is nullable
-- here (it is NOT NULL on the other three), so the fallback is load-bearing.
ALTER TABLE mfa_phone_call ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE mfa_phone_call m SET org_id = u.org_id FROM users u WHERE m.user_id = u.id AND m.org_id IS NULL;
UPDATE mfa_phone_call SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE mfa_phone_call ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mfa_phone_call_org ON mfa_phone_call(org_id);

DROP POLICY IF EXISTS pol_mfa_phone_call_org_scope ON mfa_phone_call;
CREATE POLICY pol_mfa_phone_call_org_scope ON mfa_phone_call
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE mfa_phone_call ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_phone_call FORCE  ROW LEVEL SECURITY;

-- mfa_otp_challenges --------------------------------------------------------
-- The live rows: code hash, recipient (a real phone number or e-mail) and the
-- requester's IP, for every OTP in flight.
ALTER TABLE mfa_otp_challenges ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE mfa_otp_challenges c SET org_id = u.org_id FROM users u WHERE c.user_id = u.id AND c.org_id IS NULL;
UPDATE mfa_otp_challenges SET org_id = (SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1) WHERE org_id IS NULL;

ALTER TABLE mfa_otp_challenges ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mfa_otp_challenges_org ON mfa_otp_challenges(org_id, user_id, created_at DESC);

DROP POLICY IF EXISTS pol_mfa_otp_challenges_org_scope ON mfa_otp_challenges;
CREATE POLICY pol_mfa_otp_challenges_org_scope ON mfa_otp_challenges
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE mfa_otp_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_otp_challenges FORCE  ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_sms, mfa_email_otp, mfa_phone_call, mfa_otp_challenges TO openidx_app;
`

// Down drops the belt and the columns. The backfill is not reversed: the rows
// it attributed had no org before, and a re-apply cannot reconstruct an
// attribution once the user it was derived from is gone. UNIQUE(user_id) is
// untouched in both directions because the up migration never moved it.
var mfaFactorTenantScopeDown = `-- Rollback 146.

ALTER TABLE mfa_otp_challenges NO FORCE ROW LEVEL SECURITY;
ALTER TABLE mfa_otp_challenges DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_mfa_otp_challenges_org_scope ON mfa_otp_challenges;
DROP INDEX IF EXISTS idx_mfa_otp_challenges_org;
ALTER TABLE mfa_otp_challenges DROP COLUMN IF EXISTS org_id;

ALTER TABLE mfa_phone_call NO FORCE ROW LEVEL SECURITY;
ALTER TABLE mfa_phone_call DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_mfa_phone_call_org_scope ON mfa_phone_call;
DROP INDEX IF EXISTS idx_mfa_phone_call_org;
ALTER TABLE mfa_phone_call DROP COLUMN IF EXISTS org_id;

ALTER TABLE mfa_email_otp NO FORCE ROW LEVEL SECURITY;
ALTER TABLE mfa_email_otp DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_mfa_email_otp_org_scope ON mfa_email_otp;
DROP INDEX IF EXISTS idx_mfa_email_otp_org;
ALTER TABLE mfa_email_otp DROP COLUMN IF EXISTS org_id;

ALTER TABLE mfa_sms NO FORCE ROW LEVEL SECURITY;
ALTER TABLE mfa_sms DISABLE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pol_mfa_sms_org_scope ON mfa_sms;
DROP INDEX IF EXISTS idx_mfa_sms_org;
ALTER TABLE mfa_sms DROP COLUMN IF EXISTS org_id;
`
