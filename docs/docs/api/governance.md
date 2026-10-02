# Governance Service API

Base URL: `http://localhost:8002`

The Governance Service manages access reviews, certification campaigns, and policies.

## Access Reviews

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/governance/reviews` | List reviews (paginated) |
| POST | `/api/v1/governance/reviews` | Create review campaign |
| GET | `/api/v1/governance/reviews/:id` | Get review details |
| PUT | `/api/v1/governance/reviews/:id` | Update review |
| PATCH | `/api/v1/governance/reviews/:id/status` | Update review status |

### Review Types

- `user_access` — Review individual user access rights
- `role_assignment` — Review role assignments, each named with what the role also grants through composite roles
- `application_access` — Review application access
- `privileged_access` — Review privileged/admin access

## Review Items

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/governance/reviews/:id/items` | List items to review |
| POST | `/api/v1/governance/reviews/:id/items/:itemId/decision` | Submit decision |
| POST | `/api/v1/governance/reviews/:id/items/batch-decision` | Batch decisions |

### Decision Values

- `approved` — Access confirmed
- `revoked` — Access should be removed
- `flagged` — Requires further investigation

## Access requests

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/governance/requests` | List requests (`?requester_id=me` for the caller's own) |
| POST | `/api/v1/governance/requests` | File a request: `resource_type`, `resource_id`, `resource_name`, `justification`, `priority`, `duration` (`4h`, `1d`, ...; empty for permanent where the type allows it) |
| GET | `/api/v1/governance/requests/:id` | Get a request |
| POST | `/api/v1/governance/requests/:id/approve` | Approve, as an approver of the request's current step |
| POST | `/api/v1/governance/requests/:id/deny` | Deny, likewise |
| POST | `/api/v1/governance/requests/:id/cancel` | Cancel a pending request, as its requester |

### Resource types

- `role`, `group`, `application` — an assignment, ended by the expiry sweep when the request has a duration
- `vault_credential` — a time-bound reveal of a vault secret; a duration is required
- `network_service` — a time-bound Ziti attribute
- `pam_entry` — a time-bound `connect` grant on a PAM entry, ending with the request's window; a duration is required. The requester must already see the entry (a standing grant of any action on it, directly, through a role or through a group); otherwise the answer is `404` with `pam_entry_not_found`, the same as for an entry that does not exist. A requester who can already connect gets `409` with `pam_entry_already_granted`, and a request with no duration `400` with `pam_entry_duration_required`. The request carries the entry's own name, so `resource_name` may be left out. The entry's launch approval, where the entry asks for one, is still taken at connect.

## Policies

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/governance/policies` | List policies |
| POST | `/api/v1/governance/policies` | Create policy |
| GET | `/api/v1/governance/policies/:id` | Get policy |
| PUT | `/api/v1/governance/policies/:id` | Update policy |
| DELETE | `/api/v1/governance/policies/:id` | Delete policy |
| POST | `/api/v1/governance/policies/:id/evaluate` | Evaluate policy |

### Policy Types

- `separation_of_duty` — Prevent conflicting role assignments
- `risk_based` — Dynamic access based on risk score
- `timebound` — Time-limited access grants
- `location` — Location-based access restrictions
