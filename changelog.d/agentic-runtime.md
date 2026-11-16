### Added
- **Runtime for the platform's AI assistants (`internal/agentic`).** A
  provider-neutral conversation contract, a registry of typed tools and a
  bounded loop (8 steps, 20 tool calls, a token budget and a 45 s deadline per
  turn). Every tool call is checked for who is asking, whether the organization's
  mode allows that tier of tool, and whether the arguments name something the
  person owns, before it runs; what comes back is masked (e-mail, IP address,
  secrets; host names and user names too at the strict level) and fenced as data.
  No model is wired up yet and nothing in the product calls the runtime.
  Three read-only tools are registered in the access service: diagnose my
  device (the same verdict as the "Why can't I connect?" card), list my devices,
  and, for operators, recent automatic actions.
