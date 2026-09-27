package migrations

// Migration v208 -- magic_links.token_lookup: an indexed way to find the one
// link a token was minted for.
//
// A magic link's token was stored only as a bcrypt hash, which cannot be looked
// up, so VerifyMagicLink read every pending link of every organization and
// bcrypt-compared the presented token with each until one matched. That is one
// bcrypt (cost 12, about a quarter of a second of CPU) per pending link in the
// install, spent on every unauthenticated GET /oauth/magic-link-verify, and an
// anonymous visitor can mint pending links by asking for them. And the link
// that matched was taken from whichever organization it belonged to.
//
// token_lookup is the SHA-256 of the token, hex-encoded. The token is 32 random
// bytes, so the digest discloses nothing a bcrypt hash would protect, and it can
// be indexed: the verifier finds the one candidate by it, in the request's
// organization, and bcrypt-compares that one. The index is unique; a token is
// minted once.
//
// Links minted before this migration have no lookup and are not found: they
// stop working, and the person asks for another. They live for the configured
// link expiry (fifteen minutes by default), and a fallback that scanned for
// them would keep the scan reachable by anyone for that long. Nothing is
// rewritten; the column is NULL for them, and the unique index admits any
// number of NULLs.
//
// Down drops the index and the column. Links minted after the upgrade then keep
// their bcrypt hash, which the rolled-back scan still verifies.

var magicLinkLookupUp = `-- Migration 208: an indexed lookup for magic-link tokens.
ALTER TABLE magic_links ADD COLUMN IF NOT EXISTS token_lookup VARCHAR(64);
CREATE UNIQUE INDEX IF NOT EXISTS idx_magic_links_token_lookup ON magic_links (token_lookup);
`

var magicLinkLookupDown = `-- Migration 208 down: drop the magic-link lookup.
DROP INDEX IF EXISTS idx_magic_links_token_lookup;
ALTER TABLE magic_links DROP COLUMN IF EXISTS token_lookup;
`
