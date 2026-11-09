### Added
- **Risky command warnings for privileged SSH sessions.** The PAM policy takes
  a list of regular expressions. After a recorded SSH session ends, its text
  transcript is matched line by line, and a session with matches raises a
  `pam.risky_command` audit event (with the lines) and a
  `pam.session.risky_command` webhook (patterns and line numbers, no text).
  It warns after the fact and blocks nothing. Migration 243.
