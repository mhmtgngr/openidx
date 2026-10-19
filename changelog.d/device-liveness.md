### Added
- **A device that stops reporting stops being trusted.** `AGENT_LIVENESS_TIMEOUT` (default `10m`; `0` turns it off) bounds how long an agent may go without reporting and keep `#device-trusted`. A sweep on the grace-period ticker (now every minute) takes the attribute away and severs the device's live circuits; the device stays active, so its next compliant report restores trust. Audit event `agent.stale`.
- **Single sign-on and privileged sessions can ask for a live device.** `SSO_DEVICE_GATE` (off|observe|enforce) refuses an OIDC sign-in to an application whose resource conditions require a trusted device unless the person has an active, compliant agent reporting within the timeout. `PAM_DEVICE_GATE` does the same for every privileged session an internal user launches; vendors are not held to it. Observe mode records `access.device.would_deny` / `pam.device.would_deny`, counted on Security → Enforcement under **Live device**.
- **Agent Fleet shows offline devices.** The agent list carries `last_report_at` and `live`; a device past the timeout shows **Offline · N min**.
- **Silent-fleet alert.** `openidx_agents_silent` and `openidx_agents_recent` gauges and the `OpenIDXAgentsMostlySilent` alert (over half of the devices seen in the last day silent for 30 minutes).

### Changed
- **Suspended devices carry none of their user's access.** A device identity whose agent is not active (grace expiry, a disabling kill switch, pending) keeps only its own markers: no groups, applications or trust.

### Fixed
- **A disabling kill switch left the user's devices able to dial back in.** It now suspends the user's agents, untrusts their known devices and re-syncs their identities (`devices_suspended` in the result).
- **Revoking an agent from Agent Fleet cut less than revoking it from the user's page.** Both now run the same revoke: sessions terminated, identity deleted, known device untrusted, the device's refresh tokens and sessions revoked.

### Upgrade notes
- `AGENT_LIVENESS_TIMEOUT` defaults to `10m`. Under `POSTURE_DEVICE_TRUST_GATE=enforce`, a device switched off for more than ten minutes loses `#device-trusted` until it reports again. Set `AGENT_LIVENESS_TIMEOUT=0` to keep the old behaviour.
