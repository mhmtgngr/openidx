### Fixed
- **The Add-a-device download button offers the newest installer.** When the
  agent downloads directory holds several installers for one platform, the
  manifest now advertises the highest version parsed from the filename instead
  of whichever file the directory listed first. At the same version Windows
  prefers the MSI, macOS the pkg, and Linux the x86-64 deb, then the x86-64
  rpm, then the ARM packages.

### Documentation
- **Keep agent installers outside the repo checkout.** The access-service
  wrapper template sets `AGENT_DOWNLOADS_DIR` to a runtime directory, and the
  configuration reference explains why the relative default is fragile.
