### Added
- **"Why can't I connect?" in the desktop app.** Settings has a new screen that
  runs the agent's own diagnosis on this computer (the same checks as
  `openidx-agent doctor` and the tray) and says in plain words, in English or
  Turkish, what is wrong and what to do. When something failed, "Try to fix"
  asks the agent to apply the repairs that are safe to repeat (clear the
  name-lookup cache, restart the agent) and shows what became of each, including
  one that needs administrator rights. A short support code can be copied to read
  to support. The phone app does not show it: it has no agent service or tunnel
  to look at.
