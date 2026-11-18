### Fixed
- **A new overlay service is dialable in seconds, not after two minutes.** The
  hosting router sees a service the moment its Bind policy grants it access,
  opens a Bind session and asks the controller for a terminator. A session only
  lists the edge routers an existing service-edge-router policy allows, and the
  reconciler created that policy last, after Bind and Dial, so the controller
  refused the first request (`invalid edge router for session`) and the router
  retried only after about 2 minutes 12 seconds. Every service the platform
  creates at runtime was undialable for that long: a network resource, a route's
  service, a service added from the Ziti page, a PAM entry's service. The policy
  now goes first. Measured on the box with the policy created ahead: the
  terminator was established in 8 ms and a TCP connection through the overlay
  worked one second after the service appeared, against 2m12s before. Existing
  services are untouched; only the order in which a new one is provisioned changes.
