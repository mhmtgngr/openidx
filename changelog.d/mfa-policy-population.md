### Added
- **MFA policies can target a population.** Besides groups, a policy can now apply
  only to a user type (internal, external, service), a partner organization, an
  identity provider or an application. Every condition picked must match; a sign-in
  without an IdP or application never matches those conditions. The MFA policy
  dialog has an "Applies to" selector for each.
