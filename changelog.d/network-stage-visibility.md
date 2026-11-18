### Changed
- **The network stage of the overlay reconcile now says what it did.** A stored
  network resource that never reached the overlay used to leave no trace: the
  pass dropped it, or refused its target, and kept the reason only in memory,
  where the admin API shows it for a resource somebody happens to open. Now the
  first pass that leaves a resource out logs one warning naming the resource,
  its organization and the reason (`network resource is not on the overlay`),
  the pass that lets it back in logs one line (`network resource status
  changed`), and every change to the set of network services a pass wants logs
  one line with the count and the service names (`network services: desired set
  changed`). A resource that stays in the same state is not logged again, so a
  broken one costs one line, not one every 30 seconds; a debug line per pass
  carries the count. No behavior of the reconcile itself changes.
