### Fixed
- **The "Require MFA for all users" switch did nothing.** Settings > Security
  wrote `security.require_mfa`, which sign-in never read. The switch is gone;
  in its place the tab says MFA is enforced with MFA policies and links to MFA
  Management. The ISO 27001 report's A.5 evidence now states the MFA
  requirement from the enabled MFA policies that name at least one method,
  and mentions the old setting only as a legacy value sign-in ignores.
