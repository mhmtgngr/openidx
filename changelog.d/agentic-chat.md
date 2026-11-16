### Added
- **Ask the assistant from "Why can't I connect?" (migration 261).** When the
  organization has chosen a model, the card on My Devices shows a question box.
  The answer to every question carries the rule engine's own diagnosis, and the
  model only narrates it in plain words (English or Turkish); it can look up the
  person's own devices through read-only tools and cannot change anything. When no
  model is configured, or it fails or declines, the person sees the diagnosis alone.
  `POST /api/v1/access/my/assist/messages`. Conversations are kept on the server for
  30 days (never taken from the browser, which could forge turns), belong to the
  person who started them, and each person is limited to 20 questions in 10
  minutes, counting failed attempts. `AGENTIC_DENY_PRIVATE_MODEL_HOSTS=true` makes
  a deployment that hosts several organizations refuse self-hosted model addresses
  on private networks.
