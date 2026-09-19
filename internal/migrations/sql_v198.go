package migrations

// Migration v198 -- backchannel_logout_pending: the seam between the paths
// that end a session in another binary and the process that can tell the
// relying parties.
//
// THE GAP IS THE SAME SHAPE AS v196. Back-channel logout (Back-Channel Logout
// 1.0, internal/oauth/backchannel_logout.go) mints a logout token with the
// issuer's signing key and POSTs it to every relying party a session reached.
// oauth-service does that from its one revocation funnel. Sixteen other paths
// end sessions -- the identity service's session pages, password change,
// offboarding, lifecycle actions and deprovisioning; the admin console's
// revoke-session and revoke-all; the breach responder; the DSAR delete and
// restrict; the risk engine's remediation; the device-revoke and kill-switch
// paths in access; the SCIM deprovisioner -- in five binaries, with a raw
// UPDATE or DELETE on the sessions table, and none of them holds the key. Six
// of them DELETE the row, so no later sweep in oauth-service could even
// discover that the session existed.
//
// WHY A PENDING ROW AND NOT A SWEEP. The row the drainer needs -- tenant, user,
// the client the session was created for and every client holding a refresh
// token bound to it -- is exactly what a DELETE removes and what a DSAR erasure
// removes on purpose. So the severing path captures the candidate clients into
// this table on the handle it already holds, BEFORE its own statement runs, and
// oauth-service resolves those candidates against the tenant's registered
// back_channel_logout_uri values when it drains. A path that captures nothing
// (a session no relying party ever reached) writes no row: the CHECK on
// client_ids refuses an empty capture rather than letting the drainer mark a
// row about nobody as delivered.
//
// WHY NOT THE OUTBOX: v196's two measured reasons hold unchanged -- one
// consumer by construction, and a sink whose chart default is off.
//
// THE SHAPE IS v196's: org-scoped row, SKIP LOCKED claim, claimed_at so a
// drainer that dies mid-batch hands its rows back, published_at as the done
// marker, attempts as the poison guard, a partial backlog index, forced
// org-scoped RLS. delivered and failed record what the fan-out achieved so an
// operator can tell "no relying party registered a URI" from "every relying
// party refused".
//
// Down drops the table. A pending logout is a work item, not a record: an
// install rolling back to v197 is one where sessions ended elsewhere were never
// announced, which is where it already was.

var backchannelLogoutPendingUp = `-- Migration 198: pending back-channel logouts from the paths that end sessions elsewhere.
CREATE TABLE IF NOT EXISTS backchannel_logout_pending (
    id           BIGSERIAL PRIMARY KEY,
    org_id       UUID NOT NULL,
    session_id   UUID NOT NULL,
    user_id      UUID NOT NULL,
    client_ids   TEXT[] NOT NULL CHECK (cardinality(client_ids) > 0),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at   TIMESTAMPTZ,
    published_at TIMESTAMPTZ,
    attempts     INT NOT NULL DEFAULT 0,
    delivered    INT,
    failed       INT
);

-- The backlog is what the drainer reads on every tick; the rest is history.
CREATE INDEX IF NOT EXISTS idx_backchannel_logout_pending_backlog
    ON backchannel_logout_pending (id)
    WHERE published_at IS NULL;

DROP POLICY IF EXISTS pol_backchannel_logout_pending_org_scope ON backchannel_logout_pending;
CREATE POLICY pol_backchannel_logout_pending_org_scope ON backchannel_logout_pending
  USING (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
         OR org_id = NULLIF(current_setting('app.org_id', true), '')::uuid);
ALTER TABLE backchannel_logout_pending ENABLE ROW LEVEL SECURITY;
ALTER TABLE backchannel_logout_pending FORCE  ROW LEVEL SECURITY;
`

var backchannelLogoutPendingDown = `-- Migration 198 down: drop the pending back-channel logout table.
DROP TABLE IF EXISTS backchannel_logout_pending;
`
