### Added
- **Autonomy settings and safe automatic fixes (migration 259).** Each
  organization has a mode — `off`, `observe` (the default), `tier0`, `tier1` —
  and a kill switch, at `GET/PUT /api/v1/access/agentic/settings` (change:
  admin). `AGENTIC_MODE` can hold every organization lower than its admins
  chose. When a device's own report shows a cause with a safe fix, `observe`
  only writes it to a ledger (`GET /api/v1/access/agentic/actions`); `tier0`
  also restarts the agent or collects its logs; `tier1` also asks it to update.
  A fix is not applied to the same device more than twice a day, never while
  the kill switch is on, and re-enrolment is never automatic. Every outcome is
  an audit event (`agentic.fix.applied|observed|suppressed`,
  `agentic.settings.updated`, `agentic.killswitch.set`).
