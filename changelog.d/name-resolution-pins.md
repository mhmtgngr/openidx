### Added
- **A setting for who answers the names of tunneled applications, and the pins behind it
  (migration 264).** Next to a VPN client that enforces its own DNS the tunneler never
  hears the question, so the names of tunneled applications do not resolve. Network
  policy has a new choice, `name_resolution`: `tunnel` (the default, nothing changes)
  or `agent`. With `agent`, every network resource with exactly one DNS name (no
  wildcard, hosts or ranges) gets a *pin*, a stable overlay address from
  `100.127.0.0/16`, unique across the whole install (every organization shares one
  overlay) and shown beside the resource
  (`pin_ip`, read-only). The service intercepts the name and the pin, and the router
  forwards a dial of the pin to the name, so a device that knows nothing about pins
  keeps working as before. The policy a device receives carries `name_resolution` and
  `name_pins` (only the resources that device can dial: all of them while assignment
  is not enforced, the person's assigned ones when it is) with its own digest, so the
  organization-wide policy version the console compares does not become per device.
  Nothing changes for an organization that does not turn it on: its policy version is
  the same digest as before. The agent side that answers the names is a separate change.
