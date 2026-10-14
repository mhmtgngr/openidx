### Added
- **Orphaned network-resource objects on the Ziti controller are found and,
  when enabled, removed.** A periodic sweep (one replica every 15 minutes)
  lists the configs, services and policies the network reconciler writes for
  an application and compares them with the database. Ones whose application
  no longer owns a network service, such as configs left by a reconcile that
  failed before creating the service or by a prune whose config deletes
  failed, are reported by default (`ZITI_ORPHAN_SWEEP=observe`) and deleted
  under `ZITI_ORPHAN_SWEEP=enforce`, policies first, with an audit event per
  object. Objects younger than `ZITI_ORPHAN_SWEEP_GRACE_MINUTES` (30) are
  left alone, one run deletes at most `ZITI_ORPHAN_SWEEP_MAX_DELETES` (20),
  and nothing outside the reconciler's own naming is ever touched. Counted in
  `openidx_ziti_network_orphans_total`.
