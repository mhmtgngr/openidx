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
- `role_assignment` — Review role assignments
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
