package migrations

// Migration v199 -- post_logout_redirect_uris: the list RP-Initiated Logout
// actually means by "registered".
//
// WHAT WAS THERE. handleLogout validates post_logout_redirect_uri (PR #82 made
// it stop being an open redirect), but the client model had no list to validate
// AGAINST, so the allowlist was derived from redirect_uris by comparing ORIGIN
// -- scheme, host and port -- and ignoring the path. postLogoutRedirectAllowed
// says so in its own comment, and ends it with "a first-class
// post_logout_redirect_uris column can tighten this to exact-match later".
// This is later.
//
// WHY ORIGIN IS NOT ENOUGH. OpenID Connect RP-Initiated Logout 1.0 §2 requires
// the OP to verify the value against URIs REGISTERED for the client, and the
// registration it means is post_logout_redirect_uris -- a list whose whole
// purpose is that the logout landing page is usually NOT the OAuth callback
// path. Matching on origin says yes to every path on that host, so any
// open-redirector, any user-content page and any half-finished route on the
// relying party's own domain is a legal destination for a browser the IdP is
// handing back. The RP registered two paths and got its entire site.
//
// WHY THE OLD BEHAVIOUR SURVIVES ANYWAY, and this is the decision the column
// encodes rather than hides: a client with an EMPTY list keeps the origin
// derivation. Making exact-match unconditional would refuse the logout
// redirect of every client in every existing install on the upgrade that adds
// this column, because none of them has registered anything yet. The default
// has to be installable; registration is what tightens it. So: a list that is
// there is authoritative and exact; a list that is not there falls back to the
// origin rule with a log line naming the client, so an operator can see which
// clients are still on the loose rule.
//
// JSONB, like redirect_uris (v1) and for the same reason -- the store already
// marshals string slices that way and the console already renders them.
//
// Down drops the column. An install rolling back to v198 is one where the
// origin rule decides every logout redirect, which is where it already was.

var postLogoutRedirectURIsUp = `-- Migration 199: the registered post-logout landing pages, per client.
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS post_logout_redirect_uris JSONB;
`

var postLogoutRedirectURIsDown = `-- Migration 199 down: drop the registered post-logout landing pages.
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS post_logout_redirect_uris;
`
