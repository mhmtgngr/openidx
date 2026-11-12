### Fixed
- **The Windows disk-encryption check runs manage-bde by absolute path.**
  Run by bare name from the service, Go refused it as "found relative to
  current directory" and every Windows device reported the check as an error
  instead of BitLocker on or off.
