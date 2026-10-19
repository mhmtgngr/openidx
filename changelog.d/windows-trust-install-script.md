### Added
- **Hand-install script for the Windows agent.** `agent/scripts/trust-and-install-openidx-agent.ps1`
  trusts the project's code-signing certificate (embedded, pinned by SHA-256,
  refused unless CA:FALSE and code-signing only), downloads the MSI the
  server's agent manifest names, refuses it unless its SHA-256 and
  Authenticode signer both match, and installs it; `-Token`, `-TrustOnly` and
  `-RemoveTrust` cover the other cases. `scripts/check-trust-script.sh` fails
  CI when the certificate changes and the script's copy does not.

### Fixed
- **Go-live runbook.** `docs/runbooks/go-live-windows.md` said the release's
  `install-openidx-agent.ps1` imports the code-signing certificate; it does
  not, and it writes the release's server IP into the hosts file. The runbook
  now points at the new script, and enrolment at Add a device → Open in app.
