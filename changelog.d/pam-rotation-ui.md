### Added
- **Credential rotation, visible from PAM.** PAM connection entries with a
  vaulted secret show a rotation chip (rotated every N h with the last OK
  time, failed, or not rotated) and an **Enable rotation** action that
  prefills the connector from the entry (ssh, Postgres on 5432, MySQL on
  3306, otherwise generate-only). Vault secrets without a policy offer the
  same action on their Rotations tab. The policy form is now a shared
  component.
- `GET /api/v1/vault/rotation-policies?secret_id=` filters policies to one
  secret, org-scoped. PAM entries now return `vault_secret_id`.

### Fixed
- The vault Rotations tab colours a successful run green again: the engine
  records `succeeded`, the console looked for `success`.

### Documentation
- New PAM maturity assessment (`docs/docs/guide/pam-maturity.md`) with
  runbooks to enable and roll back rotation on an SSH entry.
