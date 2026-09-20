package migrations

// Migration v202 -- drop oauth_clients.front_channel_logout_uri, a column
// nothing has ever read or written.
//
// v63 added it alongside the back-channel logout URI. The back-channel column
// went on to become a feature: stored by the client store, accepted by dynamic
// registration and the admin API, edited in the console, advertised in
// discovery and DELIVERED (logout tokens minted and posted, the drain seam for
// sessions ended in other binaries). The front-channel column did none of
// that. A search of the whole tree -- Go, TypeScript, OpenAPI, Helm -- finds
// it in exactly one place: the ALTER TABLE that created it. No store reads or
// writes it, no API or console field maps to it, and discovery does not claim
// frontchannel_logout_supported, so it is a dead column and not an advertised
// lie: the honest disposition is the one v151 gave guacamole_connection_pool,
// which was likewise never read. Dropping it loses no data, because every row
// has always held NULL.
//
// OpenID Connect Front-Channel Logout 1.0 remains a feature this product could
// add. If it is added, it arrives with a reader, a writer, a discovery claim
// and a delivery -- in the migration that adds the column back -- not by
// keeping a column around in case.
var frontChannelLogoutColumnDropUp = `-- Migration 202: drop the never-read front_channel_logout_uri column.

ALTER TABLE oauth_clients DROP COLUMN IF EXISTS front_channel_logout_uri;
`

// Down restores the column as v63 declared it: nullable VARCHAR(500). Nothing
// is lost in either direction, since nothing ever wrote to it.
var frontChannelLogoutColumnDropDown = `-- Rollback 202.

ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS front_channel_logout_uri VARCHAR(500);
`
