### Added
- **Watch privileged session recordings in the console.** Administrators can
  play a recorded session in the browser, with play/pause and seek, from
  **Privileged Sessions**:
  - **Session History** has a *Watch* button for route sessions.
  - The new **Entry Sessions** tab lists PAM entry sessions and offers
    *Watch* once a recorded session has ended.
  The recording is fetched through the admin-only download routes, so every
  view is audited, and it is decrypted server-side when sealed. It plays with
  guacamole-common-js 1.5.0 (Apache-2.0).
