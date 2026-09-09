package migrations

// Migration v187 — cap how long a refresh-token FAMILY may live, not just how
// long one token in it may live.
//
// THE LIMIT THAT NEVER BOUND. oauth_clients.refresh_token_lifetime reads as
// "how long this client may go without signing in again", and it is enforced:
// GetRefreshToken refuses a token past its expires_at. But rotation
// (handleRefreshTokenGrant, RFC 6749 §6) issues each successor with
//
//	ExpiresAt = time.Now().Add(client.RefreshTokenLifetime)
//
// so the window restarts on every use, and every native client refreshes far
// more often than the window: the desktop agent hourly, the phone whenever the
// app opens. The 30 days the three native clients were seeded with therefore
// bound only on a device that went DARK for thirty days. A phone taken while
// unlocked, or an agent on a machine that changed hands, kept a valid chain for
// as long as it kept refreshing -- which is to say indefinitely, until someone
// noticed and revoked the device by hand.
//
// This is the shape this branch keeps finding: a number that looks like a limit
// and cannot bind on the case it exists for. v185 gave the family a device to
// be revoked with; this gives it an end.
//
// WHAT IS ADDED.
//
//	oauth_refresh_tokens.family_started_at   when the family's FIRST token was
//	                                         issued; carried through rotation
//	oauth_clients.refresh_token_max_lifetime the cap, in seconds; NULL = uncapped
//
// The cap is checked at the refresh grant, before an access token is minted:
// past it the family is revoked and the client is told to sign in again. The
// per-token lifetime keeps its meaning -- how long a device may be offline --
// and the cap answers the different question of how long one authorization may
// be stretched by continuous use.
//
// WHY A STORED COLUMN RATHER THAN MIN(created_at). The oldest row of a family
// is not a reliable origin: rows age out with their own expires_at, so a family
// whose first tokens have been pruned would look younger every time it is
// asked, and the cap would recede ahead of the client forever -- the same
// never-binding failure one level down. The stored value is copied forward by
// rotation and cannot move.
//
// NULL after the backfill means a row written by a binary that predates this
// column, which can only happen during a rolling upgrade. The grant reads such
// a row's own created_at instead, so that family's clock starts at the upgrade
// rather than retroactively signing everybody out; the next rotation stamps it
// properly.
//
// THE VALUES, and they are a decision rather than a measurement.
// docs/CLIENT-ACCESS-DESIGN.md §2 recommended 14 days sliding for a phone, 30
// for the Windows agent because it re-attests posture continuously, and a hard
// cap of 90 for both. Taken as written. An operator who has already tuned
// refresh_token_lifetime keeps their value: the UPDATE matches on the seeded
// 2592000 and changes nothing else.
//
// Browser clients (admin-console, access-proxy, oauth-playground) are NOT
// capped here. Their refresh token lives in a browser rather than at rest on a
// device someone can pick up, and capping the console would sign administrators
// out on a schedule nobody asked for. Uncapped is the honest default for a
// column whose absence means "no cap".

var refreshFamilyLifetimeUp = `-- Migration 187: cap the refresh-token family lifetime.
ALTER TABLE oauth_refresh_tokens ADD COLUMN IF NOT EXISTS family_started_at TIMESTAMPTZ;

-- Truthful backfill: a family started when its oldest surviving token was
-- issued. That is the best evidence the table holds, and it is exact for every
-- family whose first token has not yet aged out.
UPDATE oauth_refresh_tokens t
   SET family_started_at = f.started
  FROM (SELECT family_id, MIN(created_at) AS started
          FROM oauth_refresh_tokens
         WHERE family_id IS NOT NULL
         GROUP BY family_id) f
 WHERE t.family_id = f.family_id
   AND t.family_started_at IS NULL;

-- A token with no family is its own origin (pre-v122 rows).
UPDATE oauth_refresh_tokens
   SET family_started_at = created_at
 WHERE family_started_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_family_started
    ON oauth_refresh_tokens (family_id, family_started_at)
 WHERE family_started_at IS NOT NULL;

ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS refresh_token_max_lifetime INTEGER;

-- The two mobile clients: 14 days per token, 90-day family cap.
UPDATE oauth_clients
   SET refresh_token_lifetime = 1209600, refresh_token_max_lifetime = 7776000
 WHERE client_id IN ('openidx-mobile', 'openidx-agent-android')
   AND refresh_token_lifetime = 2592000;

-- The Windows agent keeps 30 days per token -- it re-attests posture
-- continuously, so a long offline window costs less there -- and takes the
-- same 90-day cap.
UPDATE oauth_clients
   SET refresh_token_max_lifetime = 7776000
 WHERE client_id = 'openidx-desktop'
   AND refresh_token_max_lifetime IS NULL;`

var refreshFamilyLifetimeDown = `-- Rollback 187.
UPDATE oauth_clients
   SET refresh_token_lifetime = 2592000
 WHERE client_id IN ('openidx-mobile', 'openidx-agent-android')
   AND refresh_token_lifetime = 1209600;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS refresh_token_max_lifetime;
DROP INDEX IF EXISTS idx_oauth_refresh_tokens_family_started;
ALTER TABLE oauth_refresh_tokens DROP COLUMN IF EXISTS family_started_at;`
