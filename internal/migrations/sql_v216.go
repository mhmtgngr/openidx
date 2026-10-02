package migrations

// Migration v216 -- a PAM entry connection can be requested and approved like
// any other access, and the grant that approval writes is its own row.
//
// Section 6.9 of the third-party access framework (decision D3): a PAM entry
// is a governance request type, resource_type 'pam_entry'. Fulfilling an
// approved request writes a 'connect' grant on the entry for the requester,
// ending when the request's window does. Until now an administrator wrote every
// grant by hand, outside the approval policies, the audit of decisions and the
// expiry sweep.
//
// pam_entry_grants.request_id names the access request a grant fulfils. The
// table held one grant per (entry, principal), which a request-made grant
// cannot share with a standing one: an administrator's permanent 'view' grant
// and a four-hour 'connect' grant from a request are two grants with two
// lifetimes, and folding them into one row would either cut the standing grant
// when the request ends or leave the request's grant standing. So the key is
// split:
//
//   - pam_entry_grants_standing_key: one grant per (entry, principal) among
//     the grants no request made, which is the old rule, kept for the
//     administrator's upsert (ON CONFLICT ... WHERE request_id IS NULL);
//   - pam_entry_grants_request_key: one grant per request, so fulfilling a
//     request twice writes nothing twice.
//
// The grant check reads every live row (EXISTS), so a user holding both a
// standing grant and a request's grant holds the union, and ending the
// request's grant (by request_id) leaves the standing one alone.
//
// ON DELETE CASCADE on request_id: the grant exists only because of its
// request.
//
// Down removes the request-made grants (they cannot fit the old key beside a
// standing grant), drops both indexes and the column, and restores the old
// constraint.

var pamEntryRequestGrantsUp = `-- Migration 216: PAM entry grants written by an access request.
ALTER TABLE pam_entry_grants ADD COLUMN IF NOT EXISTS request_id UUID REFERENCES access_requests(id) ON DELETE CASCADE;
ALTER TABLE pam_entry_grants DROP CONSTRAINT IF EXISTS pam_entry_grants_entry_id_principal_type_principal_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS pam_entry_grants_standing_key
    ON pam_entry_grants (entry_id, principal_type, principal_id) WHERE request_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS pam_entry_grants_request_key
    ON pam_entry_grants (request_id) WHERE request_id IS NOT NULL;
`

var pamEntryRequestGrantsDown = `-- Migration 216 down: one grant per (entry, principal) again.
DELETE FROM pam_entry_grants WHERE request_id IS NOT NULL;
DROP INDEX IF EXISTS pam_entry_grants_request_key;
DROP INDEX IF EXISTS pam_entry_grants_standing_key;
ALTER TABLE pam_entry_grants DROP COLUMN IF EXISTS request_id;
ALTER TABLE pam_entry_grants DROP CONSTRAINT IF EXISTS pam_entry_grants_entry_id_principal_type_principal_id_key;
ALTER TABLE pam_entry_grants ADD CONSTRAINT pam_entry_grants_entry_id_principal_type_principal_id_key
    UNIQUE (entry_id, principal_type, principal_id);
`
