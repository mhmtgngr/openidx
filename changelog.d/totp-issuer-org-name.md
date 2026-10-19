### Changed
- **Authenticator apps show your organization's name.** A new TOTP enrollment
  labels the entry with the organization's name instead of "OpenIDX", so people
  with accounts in two organizations can tell the codes apart. A colon in the
  name becomes a hyphen; an organization with no name still shows "OpenIDX".
  Existing authenticator entries keep their old label.
