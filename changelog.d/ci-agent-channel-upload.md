### Fixed
- **An agent release moves the agent channel again.** The channel upload lost
  a line continuation, so the shell ran Uninstall-OpenIDXAgent.ps1 as a
  command and agent-v0.6.0-beta.2 published its versioned release but left
  the channel behind. The release guard now refuses a broken continuation.
