package migrations

// Migration v126 — throttle state for the device-code verification endpoint.
//
// RFC 8628 §5.2 names two defences against guessing a user_code, and requires
// both: enough entropy, and rate limiting at the verification endpoint. v125
// shipped the first — 8 characters over a 20-symbol alphabet is ~34.6 bits,
// well past the RFC's 20-bit floor — and its own comment names throttling as
// part of the defence, but nothing implemented it. Entropy alone is the weaker
// half: it makes any single guess unlikely, and does nothing to stop a caller
// making guesses in a loop for the ten minutes a code stays live.
//
// What a successful guess buys is worth stating, because it is not "read
// someone's code". Both verification routes sit behind end-user auth, so the
// guesser is signed in as themselves; approving a stranger's pending code binds
// *their* subject to that device, and the television in someone else's house
// silently signs in as the attacker. The cheaper attack is denial: sweep the
// space and deny every code found, and the device grant stops working for the
// whole tenant. Neither needs the attacker to learn anything secret.
//
// Only failures are recorded. A caller who types the code they were shown is
// never counted, so the limit is invisible to the flow it protects and only
// binds on someone probing codes they were not given.
//
// State lives here rather than in Redis for the same reason the TOTP throttle
// (v123) does: Redis is optional in this deployment, and a brute-force counter
// that stops counting during an outage is not a control.
//
// Deliberately NOT given the FORCE-RLS belt, and neither is oauth_device_codes
// (v125) — the belt requires the app.org_id GUC to be set on every connection
// that touches the table, and the device tests drive the pool directly with no
// org context, so adding it here would make those tables read empty instead of
// failing loudly. Both tables are registered in tools/orgscope instead, so the
// existing hard CI gate catches a query that drops its org predicate. Extending
// the belt to them is worth doing once the test harness sets the GUC.
var deviceVerifyThrottleUp = `-- Migration 126: rate-limit state for device-code verification.
CREATE TABLE IF NOT EXISTS oauth_device_verification_attempts (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID        NOT NULL,
    -- The signed-in subject that made the failed attempt. Both verification
    -- routes are behind end-user auth, so this is always populated.
    subject      TEXT        NOT NULL,
    -- Second dimension, so one attacker holding several accounts is still
    -- capped. Empty when the address could not be determined.
    client_ip    TEXT        NOT NULL DEFAULT '',
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Both indexes carry attempted_at so the window predicate is served by the
-- index rather than by re-reading every attempt the tenant ever made.
CREATE INDEX IF NOT EXISTS idx_device_verify_attempts_subject
    ON oauth_device_verification_attempts(org_id, subject, attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_device_verify_attempts_ip
    ON oauth_device_verification_attempts(org_id, client_ip, attempted_at DESC);
`

var deviceVerifyThrottleDown = `-- Migration 126 rollback.
DROP INDEX IF EXISTS idx_device_verify_attempts_ip;
DROP INDEX IF EXISTS idx_device_verify_attempts_subject;
DROP TABLE IF EXISTS oauth_device_verification_attempts;
`
