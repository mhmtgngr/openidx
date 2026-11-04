package migrations

// Migration 238: a device whose credential the server refuses.
//
// requireEnrolledAgent answers 401 to an agent that presents the wrong token
// for its row, and audited each refusal, hourly, forever: a device whose token
// had drifted (wintest, 2026-09-08 to 2026-11-04) left thousands of
// agent.auth_failed records and nothing anyone looked at. The row now carries
// the run of refusals: auth_failed_at is the latest refusal, auth_fail_count
// the refusals since the last accepted request (reset to 0 when one is
// accepted). The console reads them to tell "offline" from "its credential is
// refused, enroll it again", and the access service writes one
// agent.auth_failed_persistent record when the run first reaches its
// threshold instead of one alert-worthy record per hour.
//
// Columns under the table's existing org policy; down drops them.

var agentAuthFailuresUp = `-- Migration 238: refused agent credentials.
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS auth_failed_at TIMESTAMPTZ;
ALTER TABLE enrolled_agents ADD COLUMN IF NOT EXISTS auth_fail_count INTEGER NOT NULL DEFAULT 0;
`

var agentAuthFailuresDown = `-- Rollback migration 238.
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS auth_fail_count;
ALTER TABLE enrolled_agents DROP COLUMN IF EXISTS auth_failed_at;
`
