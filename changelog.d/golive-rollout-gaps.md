### Added
- **MFA policies can be scoped to groups.** A policy's conditions may name
  groups; it then applies only to their members (matched by group name), so an
  organization can bring units under a second-factor requirement one at a
  time. The console's policy form offers the groups; the table shows which
  groups a policy covers. Other conditions are still refused.
- **Add a device shows the Windows trust-and-install path.** When the server
  serves `trust-and-install-openidx-agent.ps1` beside the MSI, the agent
  manifest's `windows` entry carries `trust_script`, and the wizard walks the
  user through downloading it and running the one command for this server,
  instead of a bare MSI download that ends in an "Unknown publisher" warning.
- **My Devices shows an offline agent.** The person's own devices page marks an
  agent that has stopped reporting within `AGENT_LIVENESS_TIMEOUT` as Offline,
  the way Agent Fleet already does, so "compliant but not trusted" is visible
  to the person it affects. `GET /api/v1/access/my-devices` now returns
  `last_report_at` and `live` per agent.
- **Rollout docs.** The Windows go-live runbook gains the DNS prerequisite
  (controller and router names in corporate DNS, no hosts entries), a section
  on running beside the VPN, the Windows posture checks to create, and the
  group-scoped MFA step; the GlobalProtect guide names the firewall rule that
  replaces block-direct on Windows; a Turkish end-user guide
  (`docs/kullanici-rehberi-tr.md`) covers sign-in, MFA, the agent and access.
