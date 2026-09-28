package migrations

// Migration v209 -- oauth_clients.token_exchange_audiences: the audiences a
// client may obtain tokens for through token exchange (RFC 8693).
//
// Token exchange took the audience of the token it issued from the request,
// verbatim: any client registered for the grant could turn a user's access
// token into one for any other application of the organization, carrying the
// user's roles. What a client may obtain tokens for is a decision about the
// client, made by an administrator, and nothing recorded it. This column is
// that decision: the audiences the exchange may issue for besides the client
// itself.
//
// NULL, what every existing row gets, means none. A client that exchanges
// tokens for itself keeps working; one that asked for another audience is
// refused (invalid_target) until an administrator lists it. There is no
// default that would keep the old behaviour, because the old behaviour was
// "any audience at all".
//
// Down drops the column. An install rolled back below v209 runs code that
// neither reads nor writes it.

var oauthClientsTokenExchangeAudiencesUp = `-- Migration 209: the audiences a client may obtain through token exchange.
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS token_exchange_audiences JSONB;
`

var oauthClientsTokenExchangeAudiencesDown = `-- Migration 209 down: drop the token exchange audience list.
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS token_exchange_audiences;
`
