### Added
- **"Why can't I connect?" on the phone.** The mobile app's Settings now has the
  same screen as the desktop app, backed by the same checks (name lookup, reaching
  the server, certificate, clock, credentials, identity), in English or Turkish,
  with a copyable support code. Two checks a phone has nothing to say about, the
  separate agent service and the tunneler process, are skipped instead of being
  reported as failing, and the screen offers no repair button: an app in its
  sandbox cannot flush a resolver or restart a service, so it says what is wrong
  and what to do. The engine's report gains `can_repair` (false on a phone); an
  agent that does not say is assumed able.
