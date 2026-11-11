### Added
- **Agent version telemetry and update rings (v253).** Every report carries the agent's version and its last
  update outcome; the Agent Fleet page shows a Version column with a filter and flags failed updates.
  `GET/PUT /api/v1/access/agent/settings` gains `update_channel` (stable|beta), `update_pin_version`,
  `update_rollout_percent` and `update_paused`, edited in the new Updates card; `/agent/config` answers each
  device with its target (rollout by `fnv(agent_id) % 100`). The service checks 5-15 minutes after start,
  then every 6h±30m, obeys pause and pin, and downgrades to a pin with `REINSTALLMODE=vomus` (the MSI now
  allows downgrades). Beta tags (`agent-v*-beta.*`) publish to the `agent-beta` channel. Linux packages get an
  `openidx-agent-update.timer`. Alert `OpenIDXAgentUpdateFailing` on `openidx_agents_update_failing`.
- **Remote fleet commands (v254).** The Agent Fleet row menu gains "Actions…": restart, collect logs (a tar.gz of
  the agent and tunnel logs plus agent.json with its tokens redacted, at most 8 MiB, downloadable with its
  SHA-256), check for updates now, change options (log level, tray hidden, tunnel on/off), enroll again with the
  sealed fleet token, and uninstall (detached `msiexec /x`, needs a written reason). `POST/GET
  /api/v1/access/agents/:id/commands`, `GET …/:cid/artifact`, `DELETE …/:cid` (operator; reenroll and uninstall
  need fresh MFA). The service receives each command once in `/agent/config` (the tray never does) and answers
  `POST /api/v1/access/agent/commands/:id/result`; unanswered commands expire after 24 hours.
