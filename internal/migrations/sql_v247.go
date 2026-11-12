package migrations

// Migration 247: partner organizations that sign in through their own
// identity provider.
//
// A vendor organization so far onboarded people one way: an administrator's
// invitation. A partner whose people already have accounts at their own
// identity provider (a ministry's Entra tenant, a supplier's ADFS) should
// not need one invitation per person. vendor_organizations gains:
//
//   - onboarding_mode: invitation (as before), federated (people arrive
//     through SSO and are provisioned as external users of this vendor) or
//     both.
//   - idp_id: the identity provider the vendor's people sign in through.
//   - sliding_expiry: every successful federated sign-in moves the
//     account's expiry forward (never past the contract end or 365 days).
//   - default_group_ids: the groups a provisioned person joins (only those
//     open to external users).
//
// A federated vendor must name a default sponsor: every external account
// needs one (I1), and a person provisioned at sign-in has nobody else.
var vendorFederationUp = `-- Migration 247: vendor federation.
ALTER TABLE vendor_organizations ADD COLUMN IF NOT EXISTS onboarding_mode VARCHAR(16) NOT NULL DEFAULT 'invitation' CHECK (onboarding_mode IN ('invitation','federated','both'));
ALTER TABLE vendor_organizations ADD COLUMN IF NOT EXISTS idp_id UUID REFERENCES identity_providers(id) ON DELETE SET NULL;
ALTER TABLE vendor_organizations ADD COLUMN IF NOT EXISTS sliding_expiry BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE vendor_organizations ADD COLUMN IF NOT EXISTS default_group_ids UUID[] NOT NULL DEFAULT '{}';
ALTER TABLE vendor_organizations DROP CONSTRAINT IF EXISTS vendor_federated_needs_sponsor;
ALTER TABLE vendor_organizations ADD CONSTRAINT vendor_federated_needs_sponsor CHECK (onboarding_mode = 'invitation' OR default_sponsor_user_id IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_vendor_organizations_idp_id ON vendor_organizations (idp_id);
`

var vendorFederationDown = `-- Rollback migration 247.
DROP INDEX IF EXISTS idx_vendor_organizations_idp_id;
ALTER TABLE vendor_organizations DROP CONSTRAINT IF EXISTS vendor_federated_needs_sponsor;
ALTER TABLE vendor_organizations DROP COLUMN IF EXISTS default_group_ids;
ALTER TABLE vendor_organizations DROP COLUMN IF EXISTS sliding_expiry;
ALTER TABLE vendor_organizations DROP COLUMN IF EXISTS idp_id;
ALTER TABLE vendor_organizations DROP COLUMN IF EXISTS onboarding_mode;
`
