### Added
- **`openidx-agent doctor` says why a device cannot connect.** It runs on the
  device alone, with no server and no AI: agent setup, sign-in state, name
  lookup, connection, TLS, proxy, clock, Ziti identity, agent service and
  tunnel. The answer is plain language in English or Turkish with one thing to
  do for each problem. `--fix` clears the name lookup cache and restarts the
  agent service when those are the cause, then checks again; `--json` and
  `--export` produce a versioned diagnostic bundle (schema 1) that carries no
  token, key or proxy password. This is the first slice of the "user can't
  connect" work in `docs/plans/2026-11-16-agentic-architecture-design.md`.
