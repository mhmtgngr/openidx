### Fixed
- **The Windows tunneler gets the system directories on its PATH.** It sets
  its DNS server, interface metric and NRPT rules by running powershell and
  netsh; on a PC whose machine PATH had lost System32 every one failed with
  ENOENT, so no name ever resolved to the overlay. The agent now starts it with
  %SystemRoot%\System32 (and PowerShell, Wbem) first.
- **A device identity can be re-issued on controllers without re-enroll.**
  OpenZiti 1.6.x answers 404 to POST /identities/{id}/re-enroll, so an identity
  enrolled under an old controller address could never get a fresh token. The
  access service now creates a one-time enrollment through POST /enrollments.
