### Added
- **Partner organizations can sign in through their own identity provider.**
  A vendor organization gains an onboarding mode (`invitation`, `federated`,
  `both`), a bound identity provider, sliding expiry and default groups
  (migration 247). A federated mode requires a default sponsor. A person the
  provider vouches for is matched to a vendor by provider, then by email
  domain, then by the provider's `jit_policy.vendor_org_id`, and is
  provisioned as an external user with the vendor's sponsor, an expiry capped
  by the contract end and 365 days, only the default groups open to external
  users, and `pending_mfa` status. Population rules (e.g. Entra `acct`, with
  `#EXT#` as fallback) separate staff from guests on the same provider. With
  sliding expiry each federated sign-in moves the expiry forward
  (`external.expiry_slid`). Suspended vendors and unknown partners are refused
  (`sso_partner_not_registered`).
