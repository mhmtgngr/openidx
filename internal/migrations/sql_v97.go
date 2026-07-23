package migrations

// Migration v97 — dynamic client registration + token exchange support.
//
// Adds the store for RFC 7592 registration access tokens so a client created
// via RFC 7591 Dynamic Client Registration can later be read/updated/deleted by
// its registrant (agent identity: an autonomous client manages its own
// credential lifecycle without an admin).
//
// The token is stored hashed (SHA-256), one per client, replaced on rotation.
// oauth_clients already exists; this only adds the management-token side table.
//
// Token Exchange (RFC 8693) itself needs no schema: it validates an existing
// signed token and issues a new one, both stateless. This migration is the DCR
// half of the PR.
//
// Additive + idempotent.
var dcrTokenExchangeUp = `-- Migration 097: DCR registration access tokens.
CREATE TABLE IF NOT EXISTS oauth_registration_tokens (
    client_id   VARCHAR(255) PRIMARY KEY,
    token_hash  VARCHAR(64) NOT NULL,
    org_id      UUID,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
`

var dcrTokenExchangeDown = `-- Rollback 097.
DROP TABLE IF EXISTS oauth_registration_tokens;
`
