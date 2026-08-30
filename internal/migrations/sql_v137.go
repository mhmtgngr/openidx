package migrations

// Migration v137 — per-client assignment gate.
//
// Turning application assignment into a real grant needs an enforcement point
// for applications that have no published route: those are reached by getting a
// token for the client, so the gate belongs at /oauth/authorize. It is opt-in
// per client and defaults to false, because a blanket gate on deploy day would
// lock every operator out of first-party clients (admin-console, API Service)
// that have no assignments yet.
var applicationRequireAssignmentUp = `-- Migration 137: per-client assignment gate.
ALTER TABLE applications
  ADD COLUMN IF NOT EXISTS require_assignment BOOLEAN NOT NULL DEFAULT false;
`

var applicationRequireAssignmentDown = `-- Rollback migration 137.
ALTER TABLE applications DROP COLUMN IF EXISTS require_assignment;
`
