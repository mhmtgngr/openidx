### Added
- **Watermark over privileged sessions.** A session window can show the
  user's name, the session and the time across the screen, so a screenshot or
  a photo of a privileged session carries a name.
  - External (vendor) users' sessions always have it.
  - For internal users, turn on **Watermark internal users' sessions** in the
    privileged session policy (`watermark_internal`).
  - The server writes the text from the user record; the browser does not
    choose it.
  - It discourages leaks but cannot block them; the recording remains the
    record. Each policy change is audited in `pam.policy_set`.

### Upgrade notes
- **Migration 242** adds `org_pam_policy.watermark_internal`, off by default.
  No organization's sessions change on upgrade.
