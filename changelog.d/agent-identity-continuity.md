### Added
- **One machine stays one agent (Faz B8.4).** The agent fingerprints the OS machine id alone (`win2:` MachineGuid,
  `nix2:` machine-id, `mac2:` IOPlatformUUID); the hostname is an attribute. Renaming a PC keeps its row. For at least
  three releases the agent also sends `device_fingerprint_prev` (the old hostname-folded value) and enrolment moves the
  old row to the stable fingerprint.
- **Fleet lifecycle routes** (operator, fresh MFA): `PUT /api/v1/access/agents/:id/owner`,
  `POST /agents/:id/reinstate` (lifts a revoke so the device may enrol again on the same agent id),
  `POST /agents/:id/retire` (sessions and Ziti identity go, the fingerprint is freed),
  `DELETE /agents/:id?purge=1` (retired rows only). `GET /agents?include_retired=1` lists retired devices.
  Audit `agent.owner_changed`, `agent.reinstated`, `agent.retired`, `agent.purged`.
- **Agent self-heal.** `openidx-agent enroll --token` seals the fleet token (`enroll-token`). After repeated 401s the
  service enrols itself again with it. A 403 (revoked or retired) deletes the sealed token.

### Upgrade notes
- Migration 252 (`agent_identity_continuity`): `enrolled_agents` gains `hostname, retired_at, reinstated_at,
  owner_changed_by, owner_changed_at`. Duplicate live rows per `(org_id, device_fingerprint)` are retired, keeping the
  newest, and the unique key now excludes retired rows.
