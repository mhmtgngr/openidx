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
| POST | `/api/v1/governance/requests/:id/approve` | Approve, as an approver of the request's current step. One person approves at most one step of a request: an approver of an earlier step gets `403` with `four_eyes`. An approver who no longer holds what made them one (the step's role or group, being the requester's manager or sponsor) gets `403` with `approver_no_longer_eligible`, on approve and on deny |
| POST | `/api/v1/governance/requests/:id/deny` | Deny, likewise |
| POST | `/api/v1/governance/requests/:id/cancel` | Cancel a pending request, as its requester |

An external (vendor) user's request starts with a step for their sponsor, and the policy's steps follow, with the sponsor not among their approvers. No auto-approve condition applies to it. A request whose chain has no approver after the sponsor, such as one no policy covers when the default administrator is the sponsor, is refused with `409` and `approval_chain_unbuildable`.

A request tells the people it concerns, under notification types each can switch off:
- the approvers of the step it waits at, when it reaches them (`approval_pending`);
- the requester, when it is approved, denied, within the hour before its access ends, and when that access ends or the request expires unanswered (`request_update`, with `kind` in the metadata: `approved`, `denied`, `expiring`, `window`, `unanswered`).

The same moments are published to the organization's webhook subscribers:

| Event | When |
|---|---|
| `access_request.created` | A request is filed |
| `access_request.approved` | The last approval granted the access; the payload carries `expires_at` for a time-bound one |
| `access_request.denied` | A request is denied |
| `access_request.expiring` | The access ends within the hour; published once per request |
| `access_request.ended` | The access ended with its window, or the request expired unanswered |

Each payload carries `request_id`, `requester_id`, `resource_type`, `resource_id`, `resource_name` and `status`.

### Resource types

- `role` — an assignment that carries the request's window (`expires_at`, migration v223). A token issued after the window's end no longer carries the role, the role-expiry sweep removes it within a minute and cuts the tokens that still do, and the expiry sweep ends the request. The request's end removes only the assignment its window made: an administrator's standing assignment of the same role stays, and of two windows on one assignment the later counts
- `group` — a membership that carries the request's window (`expires_at`, migration v224), as a role does. A token issued after the window's end no longer carries the group, the identity expiry sweep removes it within a minute and cuts the tokens that still do, and the expiry sweep ends the request. The request's end removes only the membership its window made: a membership the user held before the request stays, and of two windows on one membership the later counts. A SCIM push of the group keeps each kept member's window
- `application` — an assignment that ends with the request's window (`expires_at`, migration v222). It is refused from the window's end; the expiry sweep then removes it. A standing assignment stays standing, and of two windows on one assignment the later counts
- `vault_credential` — a time-bound reveal of a vault secret; a duration is required
- `network_service` — a time-bound dial to one of the organization's Ziti services, named by its id in the service mirror (`ziti_services`); a duration is required. Fulfilling it gives the requester the attribute `jit-<request-id>`, and the access service writes a Dial policy that opens the service to that attribute alone, until the window ends. A service that does not exist, is another organization's or is disabled answers `404` with `network_service_not_found`, and a request with no duration `400` with `network_service_duration_required`. The request carries the service's own name
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
