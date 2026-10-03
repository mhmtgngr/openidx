package migrations

// Migration v220 -- an access request records when its requester was warned
// that the access it gave ends within the hour.
//
// Section 6.10 of the third-party access framework: the requester of a
// time-bound access request is told before the access ends, not only after.
// The governance JIT expiry sweep warns each fulfilled request whose window
// closes within the hour, once: it claims the request by stamping
// expiry_warned_at, publishes access_request.expiring to the tenant's webhook
// subscribers, and notifies the requester unless they switched those
// notifications off. A request whose window was set or moved after the warning
// is not warned again; the stamp says the warning went out, and when.

var accessRequestExpiryWarnedUp = `-- Migration 220: access_requests.expiry_warned_at.
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS expiry_warned_at TIMESTAMPTZ;
`

var accessRequestExpiryWarnedDown = `-- Migration 220 down.
ALTER TABLE access_requests DROP COLUMN IF EXISTS expiry_warned_at;
`
