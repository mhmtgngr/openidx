### Added
- **The agent can answer the names of tunneled applications itself (Windows).**
  With the organization's name resolution set to `agent`, a device next to a VPN
  client that enforces its own DNS (GlobalProtect answers every UDP/53 question
  with a fake NXDOMAIN) resolves the names of its tunneled applications through
  a loopback responder and per-name NRPT rules instead of the tunneler's DNS.
  It proves the path with a probe name before it touches anything, answers only
  services the tunneler lists as dialable, and removes its rules when the tunnel
  or the setting goes away. The doctor's name check reports it as handled.
