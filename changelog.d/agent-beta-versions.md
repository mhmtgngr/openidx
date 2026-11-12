### Fixed
- **Agent pre-releases (agent-vX.Y.Z-beta.N) build and update in order.**
  The release guard accepted only X.Y.Z, the MSI got an invalid package
  version, and the updater treated 0.6.0-beta.1 as equal to 0.6.0, so a
  device on the beta would never take the stable release. Pre-releases now
  sort before their release (semver order), and the MSI package version is
  the numeric core while the registry keeps the full version.
