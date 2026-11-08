### Security
- **PAM entry session recordings are sealed and retained.** A recording of a
  session opened from a PAM entry (Connect on an entry, a Windows app launch)
  used to stay plaintext on disk for ever. The sealer and the retention
  sweep only covered route sessions. These recordings are now:
  - encrypted at rest once the session ends, when a recording key is
    configured, and announced as `pam.recording.sealed`;
  - removed after the organization's recording retention, audited as
    `pam.recording_purged`.

### Added
- **Download an entry session's recording.**
  `GET /pam/sessions/{id}/recording` (administrators only) streams it,
  decrypting a sealed one, and is audited as `pam.recording_downloaded`. A
  purged recording answers `410 recording_purged`.

### Upgrade notes
- **Migration 241** adds `recording_sealed_at`, `recording_sha256`,
  `recording_key_id` and `recording_purged_at` to `pam_entry_sessions`.
- **Legal holds do not cover entry sessions yet.** The legal-hold table is
  tied to route sessions only.
