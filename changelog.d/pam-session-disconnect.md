### Fixed
- **PAM sessions end when the user leaves.** A brokered session whose user
  closed the tab used to stay "active" in the session ledger for ever. The
  lifecycle sweep now ends a session the broker has not served for 10 minutes,
  with reason `disconnected`, audited as `pam.session_ended` and published to
  webhooks like any other end. A broker that cannot be reached ends nothing.

### Upgrade notes
- **Migration 240** adds `pam_entry_sessions.broker_last_seen_at`. On the first
  sweep after the upgrade, old sessions the broker no longer serves are ended.
