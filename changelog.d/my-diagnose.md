### Added
- **"Why can't I connect?" on My Devices.** A person can check their own
  device from the console and read what is wrong and what to do, in English
  or Turkish. The answer comes from `POST /api/v1/access/my/diagnose`, which
  judges the caller's newest-reporting device (or one they name) from the
  fleet's record of it and the newest diagnostic bundle it sent. A device
  that is not the caller's answers 404.
- **Operators can read a support code.** `POST /api/v1/access/diagnose/decode`
  turns the `OX1-…` code a user read out from the agent into the causes it
  stands for.
