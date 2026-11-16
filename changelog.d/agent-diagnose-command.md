### Added
- **The server can ask a device to diagnose itself.** A new fleet command,
  `diagnose` (migration 258), makes the agent run its doctor from inside the
  service, where the tunnel's live state is known on every platform, and
  answer with the diagnostic bundle; the server files it as the device's
  diagnostic. Operators find it in the fleet's command list.
- **"Why can't I connect?" now asks the device.** When a person checks a
  device that is online and has sent no recent report, the server queues one
  `diagnose` command for it (never a second while one is waiting) and the
  console card refreshes once on its own about 40 seconds later. An agent
  older than this release answers the command as unknown and the card keeps
  the answer it had.
