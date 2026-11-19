### Fixed
- **Desktop and phone sessions no longer end 30 minutes after sign-in.** The
  session sweeps were written for a person at a browser (idle 30 minutes,
  absolute 24 hours) and applied to every session whatever its client. The tray
  and the phone apps touch their session only when they refresh a token, an hour
  apart at best, so every one of their sessions was ended before the first
  refresh and the person was asked to sign in again all day, while the device's
  network access (which does not depend on the session) kept working. Sessions
  of native, device-bound clients now follow their client: they end after 30
  days without use (14 on the phone), 90 days after sign-in, or when no refresh
  token can keep them going (sign-out, a revoked device). A native client no
  longer rides a browser session or sets the browser's SSO cookie, so a console
  logout does not end the tray's session and the console cannot borrow a
  90-day one; the concurrent-session limit spends a browser session before a
  native one. Everyone signs in once more after the upgrade (sessions that were
  already ended stay ended).
