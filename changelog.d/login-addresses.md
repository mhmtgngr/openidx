### Added
- **Give an account extra sign-in addresses by hand.** Users → *Edit user* →
  *Sign-in addresses*: an administrator adds an address
  (`name@company.example`) and the person can sign in with it and their
  password, in any letter case. It is for the people whose real address is not
  in the directory's `mail` attribute (a lab or test domain, a mailbox on
  another domain, a new address not synced yet) and for local accounts, which
  have no directory at all. A directory sync never touches these addresses
  (it rewrites `users.mail` on every run). They live in `user_login_addresses`
  (migration 266), unique within the organization, up to 5 per account.
  An address that is another account's username, email, mail or address is
  refused (`address_in_use`, naming nobody); if one ends up shared anyway the
  sign-in refuses it for both accounts, as for any contested address, and a
  username always wins over an address. Only an administrator can add or remove
  them, never the account holder; both are audited
  (`user.login_address_added`, `user.login_address_removed`). Password reset and
  notifications keep using the account's email.
  `GET|POST /api/v1/identity/users/{id}/login-addresses`,
  `DELETE /api/v1/identity/users/{id}/login-addresses/{addrId}`.
