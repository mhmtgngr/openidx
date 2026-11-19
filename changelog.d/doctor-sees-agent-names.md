### Fixed
- **`openidx-agent doctor` no longer warns about tunnel DNS on a device where the
  agent answers the names itself.** With the organization's name resolution set
  to `agent`, the command-line doctor (a separate process) could not see that the
  service had taken the names over, and reported `DNS_INTERCEPTED` on exactly the
  devices that mode is for. The service now reports it on its status pipe and the
  doctor reads it from there, as the fleet "diagnose" command already did.
