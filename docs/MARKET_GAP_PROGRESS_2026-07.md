# §7.2 Market-Gap Closure — Progress & Remaining Waves

Status snapshot after the 2026-07-23 push. This tracks the §7.2 roadmap from
`docs/MARKET_REANALYSIS_AND_GTM_2026-07.md`.

## Closed this cycle (all merged to main + live-verified)

| Gap / Wave | PR | What shipped |
|-----------|----|--------------|
| Outbound SCIM client | #543 | OpenIDX provisions users/groups OUT to Okta/Entra/Slack/... (SCIM 2.0 client, outbox worker, fan-out on inbound writes) |
| HR-driven JML | #544 | BambooHR source of truth for joiner/mover/leaver (directory-connector type; manager resolution; safety valve) |
| Token Exchange (RFC 8693) + DCR (RFC 7591/7592) | #545 | Agent-identity substrate: token exchange with delegation `act`, dynamic client registration + management |
| EDR/MDM posture ingestion | #546 | CrowdStrike/Intune/Jamf device compliance → the Ziti-bound posture pipeline (non-compliant device → circuit cut) |
| SSF/CAEP transmitter + receiver | #547 | First OSS SSF/CAEP with native network termination (receiver actuator severs the overlay) |
| Mid-session + governance-revoke network termination (A3 + B2) | #549 | Posture/risk degrade AND access-review/cert/JIT revoke sever live Ziti circuits |
| JIT network grants (B1) | #551 | Approve a network_service request → time-bound `jit-<id>` Ziti attribute opens the dial → expiry removes it + severs the circuit |
| Usage metering (A4) | #553 | Daily rollup of Ziti fabric usage (overlay logins, service dials) per org/service/identity from unified_audit_events; GET /api/v1/audit/usage |
| MCP / AI-agent gateway (D1) | #555 | Agent token → per-tool allowlist → forward to MCP server over dark Ziti service → audited. Network-enforced agent containment. |

Migrations v95–v103 applied live. Every feature has DB-backed tests + a live
end-to-end proof against `openidx.tdv.org`.

## Remaining §7.2 waves (follow-up PRs)

Each is a large, multi-file, often cross-service build. Recommended order:

### A2 — Per-org overlay scoping (MSP unlock)
Remove the hardcoded fallback org from the Ziti path; namespace Ziti
attributes/service names per org; org-RBAC on Ziti passthrough. Prerequisite for
the MSP channel + any multi-tenant SaaS offer.
- Touch: `internal/access/ziti*.go` (service/identity naming), `ziti_user_sync.go`
  (attribute namespacing), the reconciler, and every place a default org is
  assumed on the overlay path. Large; do behind a feature flag.



### D3 — K8s fabric subchart + HA controller (Raft) + Terraform provider
Production posture for platform buyers. Infra/packaging work.

## Notes for the next session

- Workers now running in access-service: EDR ingestion, network revocation.
  In oauth-service: SSF push. In provisioning-service: outbound SCIM.
- The `network_revocation_queue` (v100) + `severUserZitiCircuits` are the shared
  actuator for any "sever this user's circuits" need — reuse them for B1's
  kill-on-expiry and any future revocation source.
- All new secrets are encrypted via `secretcrypt` (needs `ENCRYPTION_KEY`).
