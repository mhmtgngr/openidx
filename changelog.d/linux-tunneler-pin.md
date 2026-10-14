### Security
- **The Linux agent now runs only the tunneler it shipped with.** The deb and rpm
  packages bake the SHA-256 of their bundled `ziti-edge-tunnel` into the agent at
  build time, one pin per architecture, as the Windows MSI already did. The agent
  hashes the held binary before it starts it and refuses any other file, reporting
  the tunnel as `degraded` with a pin error. A build that bundles the tunneler but
  cannot pin it now fails.
