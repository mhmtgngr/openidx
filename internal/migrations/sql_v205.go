package migrations

// Migration v205 -- oauth_clients.api_access: which applications' access tokens
// OpenIDX's own APIs accept.
//
// Every application a user signs in to through OpenIDX is issued an access
// token carrying that user's roles, because the token endpoint mints the same
// token for every client. The roles are a fact about the user. Whether a token
// may exercise them on OpenIDX itself -- the admin API, the identity and
// governance APIs, the MCP gateway -- is a decision about the application, and
// nothing recorded it, so those APIs accepted the access token of any
// application a user had signed in to. This column is that decision. The
// issuer stamps tokens for a client that has it (the openidx_api claim), and
// the API validators refuse a token without the claim; the endpoints a relying
// party calls (UserInfo, introspection, revocation, logout) keep accepting any
// access token.
//
// EXISTING CLIENTS KEEP WORKING. The column is added with DEFAULT true, which
// fills every row that exists when this runs -- the console, the desktop and
// mobile apps, every integration an operator has registered -- and the default
// is then switched to false, so a client registered afterwards may not call the
// APIs until it is allowed to. On a fresh install the seeded clients exist by
// the time this runs and get true for the same reason. Doing it as two ALTERs
// rather than an ADD and an UPDATE touches no row under the row-level-security
// belt and rewrites nothing: a constant default is stored once in the catalog.
//
// Down drops the column. An install rolling back to v204 runs code that neither
// reads nor mints the claim.

var oauthClientsAPIAccessUp = `-- Migration 205: whether an application's access tokens may call OpenIDX's own APIs.
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS api_access BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE oauth_clients ALTER COLUMN api_access SET DEFAULT false;
`

var oauthClientsAPIAccessDown = `-- Migration 205 down: drop the per-application API access switch.
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS api_access;
`
