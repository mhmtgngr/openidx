package migrations

// Migration v186 — record WHEN a login session last proved a second factor.
//
// The product has step-up endpoints (/oauth/stepup-challenge, -verify,
// -status) that mint a short-lived `step_up` JWT, and nothing in the product
// has ever asked for one: no handler, no middleware, no gate reads it. It is
// the same shape as every other control on this branch that displayed without
// enforcing. Making it enforce needs one fact the schema did not hold.
//
// sessions.auth_methods (v133) records WHICH methods established a session --
// ["pwd"] or ["pwd","mfa"] -- and drives the amr claim. It cannot answer the
// question a step-up gate asks, which is not "did this session ever use MFA"
// but "how long ago". A session that passed MFA at 09:00 still reports
// ["pwd","mfa"] at 19:00, so a control built on auth_methods alone would treat
// a ten-hour-old factor as fresh and would never require anything of anybody.
//
// mfa_verified_at is that timestamp. It is stamped in exactly two places:
//
//   - login, when a second factor was verified in the flow (the same call that
//     records auth_methods, derived from the methods it is given -- so a
//     future caller that records "mfa" cannot forget the timestamp); and
//   - /oauth/stepup-verify, on success. That is what gives step-up an effect:
//     answering a challenge makes the session fresh again, which is the whole
//     mechanism by which a user gets past the gate.
//
// Backfilled, not left NULL, for the sessions that can prove the value:
// `started_at` where auth_methods contains 'mfa' is not an invention -- it is
// the moment that session's second factor was verified, the same fact the amr
// claim already asserts about it. Leaving those NULL would declare every live
// MFA session stale at upgrade and, on an install that turns the gate straight
// to enforce, prompt every signed-in admin at once for a factor they supplied
// seconds earlier. Sessions with no 'mfa' in auth_methods stay NULL: they
// never proved a second factor and nothing here may pretend otherwise.
//
// The gate that reads this column is off by default (STEPUP_GATE=off) and has
// an observe mode, so an operator sees who WOULD be asked before anyone is.

var sessionMFAVerifiedAtUp = `-- Migration 186: sessions.mfa_verified_at for the step-up freshness gate.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS mfa_verified_at TIMESTAMPTZ;

-- Truthful backfill only: a session whose recorded auth methods include a
-- second factor verified it when the session started. Sessions without 'mfa'
-- keep NULL -- "never proved a second factor" -- which the gate reads as stale.
UPDATE sessions
   SET mfa_verified_at = started_at
 WHERE mfa_verified_at IS NULL
   AND auth_methods IS NOT NULL
   AND 'mfa' = ANY(auth_methods);

CREATE INDEX IF NOT EXISTS idx_sessions_mfa_verified_at
    ON sessions (id, mfa_verified_at) WHERE mfa_verified_at IS NOT NULL;`

var sessionMFAVerifiedAtDown = `-- Rollback 186.
DROP INDEX IF EXISTS idx_sessions_mfa_verified_at;
ALTER TABLE sessions DROP COLUMN IF EXISTS mfa_verified_at;`
