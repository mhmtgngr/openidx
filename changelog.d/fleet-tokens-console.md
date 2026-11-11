### Added
- **Fleet enrollment tokens in the console.** Agent Fleet lists, mints and revokes reusable tokens with a name,
  an optional device limit, a lifetime of up to a year (90 days by default) and tags stamped on every device
  they enrol. Each use is counted atomically and a token at its limit is refused.
- **Deploy panel.** Right after a fleet token is minted the console shows it once with copyable Intune, GPO,
  manual PowerShell and Linux install commands.

### Changed
- **Fleet tokens are exempt from the hourly enrolment quota** and minting one asks for a fresh MFA when the
  step-up gate is on. One-time tokens keep the quota.

### Upgrade notes
- Migration 250 (`fleet_tokens_and_tags`). New tokens may live at most 366 days; existing ten-year fleet tokens
  keep working until revoked (the check is NOT VALID). `RegisterAgentAdminRoutes` takes the step-up gate.
