### Fixed
- **The MSI smoke test accepts a pre-release agent.** Its registry check compared
  the installed `Version` ("0.6.0-beta.3") with the numeric part only ("0.6.0"),
  so every `agent-v*-beta.*` release went red after the MSI had built and
  published. It now compares with the full release string.
