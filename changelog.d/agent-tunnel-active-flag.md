### Fixed
- **The tray no longer says Network: Error for a working tunnel.** ziti-edge-tunnel
  1.18.x reports a top-level Active=false while its TUN interface is up and its
  identity is active; the agent read that as down. It now counts as inactive
  only when the tunneler has no TUN address.
