### Added
- **Rollout assistant for agent updates (migration 262).** The platform now
  watches an organization's agent update and says how it is going and what the
  next step is: `GET /api/v1/access/agent/rollout` (operator) gives the target
  version, the ring, a verdict (waiting, ready, failing, paused, complete) with
  its reasons and counts, and the proposed step. The rules in `internal/rollout`
  decide; devices that are offline are not waited for, a failure in a small
  sample counts, and a ring is given an hour after each change before the next
  is proposed. Widening a ring is always a proposal an administrator approves
  (`POST .../rollout/proposals/{id}/approve`, which re-checks that nothing has
  moved and the rules still recommend it, otherwise 409); a failing rollout is
  proposed for a pause, and at `tier0`/`tier1` the pause is taken automatically
  (once a day at most, never under the kill switch) and shown in the action
  ledger. A card on the Agent Fleet page shows it, in English and Turkish.
