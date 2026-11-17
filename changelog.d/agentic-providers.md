### Added
- **Choose the model behind the assistant (migration 260).** Per organization:
  none (the default — the assistant answers in the built-in wording and no model
  is called), Claude through the Anthropic API (official Go SDK), or a model the
  organization runs behind an OpenAI-compatible endpoint (Ollama, vLLM, LM Studio,
  llama.cpp). Set on the Agent Fleet page or `PUT /api/v1/access/agentic/settings`.
  The API key is stored encrypted and never returned. Choosing the cloud model
  needs a recorded consent (who and when) and masking above "off"; a database
  check holds both. `ANTHROPIC_API_KEY` supplies a key for organizations that
  store none. A model that declines a request is treated as no answer, not
  retried.
