### Fixed
- **A tunnel supervisor test no longer races the fake tunneler.** It read the
  start record before the child had written it.
