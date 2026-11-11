### Added
- **Zero-touch Windows agent rollout.** `Install-OpenIDXAgent.ps1` (Intune
  Win32 app, GPO startup script, by hand) verifies the MSI against the release
  manifest's SHA-256 and its Authenticode signature, then installs and enrolls
  with a fleet token; `-Detect` and `-Uninstall` cover Intune's detection and
  removal. `Uninstall-OpenIDXAgent.ps1` and `make-mst.ps1` (GPO transforms)
  ship alongside. New runbooks: `docs/runbooks/agent-intune.md` and
  `docs/runbooks/agent-gpo.md`.
- **MSI properties `TUNNEL_ENABLED`, `SERVER_CA`, `PROXY_URL`, `LOG_LEVEL` and
  `KEEP_ENROLL_TOKEN`.** With `KEEP_ENROLL_TOKEN=1` (the default) the agent
  keeps the fleet token sealed (DPAPI on Windows) and the service finishes an
  enrolment that failed at install time, retrying after 1, 5 and 15 minutes,
  then hourly. A 403 `agent_revoked` deletes the token.
- **Intune detection registry.** The MSI writes
  `HKLM\SOFTWARE\OpenIDX\Agent` `Version`, `InstallDir` and `ServerUrl`.

### Changed
- **The MSI enrolls on upgrade too**, so a new `SERVER_URL` takes effect, and
  an uninstall removes `%ProgramData%\OpenIDX\agent` and the tunnel's leftover
  DNS rules and adapter.
- **`install-openidx-agent.ps1` is replaced by `Install-OpenIDXAgent.ps1`.** The
  old script's `-Token` is now `-EnrollToken`, and it no longer edits the hosts
  file.

### Security
- **The enrolment token no longer reaches verbose MSI logs.** The enrol custom
  action and its property are hidden, so `msiexec /l*v` writes `**********`.
