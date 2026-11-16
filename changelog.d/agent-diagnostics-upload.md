### Added
- **Devices can send their diagnostic bundle.** `POST /api/v1/access/agent/diagnostics`
  (agent credential, device-signed, at most 64 KiB) stores what the agent's
  doctor found in the new `agent_diagnostics` table (migration 257) and
  answers with the rule engine's verdict. The bundle is parsed strictly and
  filed under the device whose credential sent it, whatever it claims. Each
  device keeps its twenty most recent bundles; all expire after 30 days.
  No agent sends one yet.
