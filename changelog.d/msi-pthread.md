### Fixed
- **The Windows MSI carries libwinpthread-1.dll whenever it carries libvpx.**
  vcpkg's libvpx-1.dll imports it. The build copied it only from a MinGW
  directory the runner lacks, and the "agent starts" check passed because the
  runner's PATH has MinGW. A real PC upgrading to 0.6.0 got 0xC0000135, the
  service never started (1920) and the upgrade rolled back (1603). The launch
  check now runs with a clean PATH and checks the DLL import closure.
