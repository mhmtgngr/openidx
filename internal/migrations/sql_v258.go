package migrations

// Migration 258: the "diagnose" fleet command.
//
// agent_commands.kind gains 'diagnose': the server asks a device to run its
// own doctor and answer with the diagnostic bundle, which the result handler
// files in agent_diagnostics (v257). The CHECK is replaced rather than
// dropped, so an unknown kind is still refused by the database.

var agentCommandDiagnoseUp = `-- Migration 258: diagnose command kind.
ALTER TABLE agent_commands DROP CONSTRAINT IF EXISTS agent_commands_kind_check;
ALTER TABLE agent_commands ADD CONSTRAINT agent_commands_kind_check
  CHECK (kind IN ('restart', 'collect_logs', 'reenroll', 'set_options', 'update_now', 'uninstall', 'diagnose'));
`

var agentCommandDiagnoseDown = `-- Rollback migration 258.
DELETE FROM agent_commands WHERE kind = 'diagnose';
ALTER TABLE agent_commands DROP CONSTRAINT IF EXISTS agent_commands_kind_check;
ALTER TABLE agent_commands ADD CONSTRAINT agent_commands_kind_check
  CHECK (kind IN ('restart', 'collect_logs', 'reenroll', 'set_options', 'update_now', 'uninstall'));
`
