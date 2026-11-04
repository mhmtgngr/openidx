### Added
- **Agent Fleet names each device's owner.** An Owner column shows the person
  a device belongs to, or **Unclaimed** for a device enrolled with a fleet
  token that nobody has claimed. A fifth summary card counts unclaimed and
  refused devices, the list filters by owner state, and search matches the
  owner. `GET /api/v1/access/agents` returns `owner_user_id`,
  `owner_username`, `credential_refused` and `credential_refused_at`.
- **A refused credential is shown as such, not as "offline".** When the
  server refuses a device's agent credential (401), the device is reaching
  the server and being turned away. Agent Fleet shows **Credential refused ·
  enroll again**, My Devices shows **Not accepted** with an **Enroll again**
  button, the Windows tray says `device: NOT ACCEPTED · enroll it again`,
  tells the person once, and offers **Enroll this device again** (opens Add a
  device), and the mobile client's banner says to enrol again.
  `GET /api/v1/access/my-devices` returns `credential_refused` per agent.

### Changed
- **Re-enrolling a device from a person's session claims an ownerless
  device.** A device enrolled with a fleet token belonged to no one, and
  enrolling it again from Add a device did not change that, so it never
  appeared in its user's My Devices and its posture never reached their
  network access. Now that enrolment makes it theirs.
- **The Windows agent service takes up a new enrolment without a restart.**
  After a refused sync it re-reads `agent.json` and uses the credential an
  enrolment made while it ran wrote there.
- **The agent stops reporting while its credential is refused.** After three
  refused syncs in a row it stops posting reports the server would refuse,
  until a sync is accepted again.

### Security
- **A person cannot take over a colleague's device by enrolling it again.**
  An enrolment from one person's session whose device fingerprint names a
  device another person owns is refused (409 `agent_owned_by_another_user`)
  before any credential is minted, and audited as `agent.enroll_denied`.
  A fleet-token enrolment may still re-enrol an owned device; the owner
  stays.
- **A run of refused agent credentials is audited once.** Each refusal is
  still recorded as `agent.auth_failed`; the access service now also writes
  one `agent.auth_failed_persistent` record when a run of refusals for an
  enrolled device first reaches six, and counts the run on the device's row
  (migration 238: `enrolled_agents.auth_failed_at`, `auth_fail_count`). A
  request naming an agent id that does not exist counts nothing.

### Upgrade notes
- Migration 238 adds two columns to `enrolled_agents`; it runs on start.
- Devices installed with a fleet token (`-Token`) show as **Unclaimed** in
  Agent Fleet after the upgrade. Each user claims theirs by signing in on it
  and choosing **My Devices → Add a device → Open in app**; see the Windows
  go-live runbook, wave 1.
