package migrations

// Migration 246: an identity provider's federation profile.
//
// identity_providers so far held what a Keycloak-shaped sign-in needed:
// issuer, client id and secret, scopes. Signing in through Entra ID, ADFS or
// a partner organization's issuer needs the rest of what OpenID Connect lets
// a relying party configure, and what OpenIDX decides about the people who
// arrive that way:
//
//   - discovery_url: where the provider's document is when it is not at
//     <issuer>/.well-known/openid-configuration (ADFS: /adfs/...).
//   - use_pkce: send a code challenge (on by default; every provider this
//     exists for accepts S256).
//   - trust_upstream_mfa: whether a second factor the provider asserts in
//     amr/acr counts as OpenIDX's second factor for an INTERNAL user. Off by
//     default: a provider's MFA claim is its word, and an external user is
//     held to OpenIDX's own factor whatever this says.
//   - claims_mapping: which claim fills which user field (shape shared with
//     social_providers.attribute_mapping).
//   - group_mapping: [{claim_value, group_id}] from the provider's groups
//     claim to OpenIDX groups.
//   - jit_policy: whether an unknown person is provisioned, as which
//     population (internal, external), with which rules.
//   - pass_through_params: which of login_hint, prompt, max_age, domain_hint
//     the authorization request forwards.
//   - external_id_claim: which claim is the person's stable id at the
//     provider (sub; oid for Entra, which keeps sub pairwise per client).
//
// Every column has a default, so every provider configured before this
// behaves exactly as before: standard discovery location, PKCE on, upstream
// MFA not trusted, standard claims, no group mapping, no provisioning rule
// beyond what the sign-in path did (which it keeps doing until jit_policy
// says otherwise), sub as the external id. The table is already scoped and
// belted; no policy changes.
var federatedIdPProfileUp = `-- Migration 246: identity provider federation profile.
ALTER TABLE identity_providers ADD COLUMN IF NOT EXISTS discovery_url TEXT;
ALTER TABLE identity_providers ADD COLUMN IF NOT EXISTS use_pkce BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE identity_providers ADD COLUMN IF NOT EXISTS trust_upstream_mfa BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE identity_providers ADD COLUMN IF NOT EXISTS claims_mapping JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE identity_providers ADD COLUMN IF NOT EXISTS group_mapping JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE identity_providers ADD COLUMN IF NOT EXISTS jit_policy JSONB NOT NULL DEFAULT '{"provision": false, "population": "internal"}'::jsonb;
ALTER TABLE identity_providers ADD COLUMN IF NOT EXISTS pass_through_params TEXT[] NOT NULL DEFAULT ARRAY['login_hint','prompt','max_age']::text[];
ALTER TABLE identity_providers ADD COLUMN IF NOT EXISTS external_id_claim VARCHAR(32) NOT NULL DEFAULT 'sub';
`

var federatedIdPProfileDown = `-- Rollback migration 246.
ALTER TABLE identity_providers DROP COLUMN IF EXISTS external_id_claim;
ALTER TABLE identity_providers DROP COLUMN IF EXISTS pass_through_params;
ALTER TABLE identity_providers DROP COLUMN IF EXISTS jit_policy;
ALTER TABLE identity_providers DROP COLUMN IF EXISTS group_mapping;
ALTER TABLE identity_providers DROP COLUMN IF EXISTS claims_mapping;
ALTER TABLE identity_providers DROP COLUMN IF EXISTS trust_upstream_mfa;
ALTER TABLE identity_providers DROP COLUMN IF EXISTS use_pkce;
ALTER TABLE identity_providers DROP COLUMN IF EXISTS discovery_url;
`
