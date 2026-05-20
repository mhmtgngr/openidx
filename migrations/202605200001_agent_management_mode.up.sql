-- 202605200001: Record the Android management mode on enrolled_agents.
--
-- Phase 1 added is_device_owner (boolean). BYOD work-profile mode
-- introduces a third state — Profile Owner — so a boolean no longer
-- captures the device's management posture. management_mode is the
-- richer field:
--
--   device_owner   — fully managed device (QR / factory-reset provisioned)
--   profile_owner  — managed work profile on a personal device (BYOD)
--   unmanaged      — app installed without device-admin privileges
--
-- is_device_owner is kept for back-compat and continues to be set in
-- tandem (true only when management_mode = 'device_owner').

ALTER TABLE enrolled_agents
    ADD COLUMN IF NOT EXISTS management_mode VARCHAR(32);

-- Backfill: existing Device-Owner rows map to the new enum.
UPDATE enrolled_agents
   SET management_mode = 'device_owner'
 WHERE management_mode IS NULL
   AND is_device_owner = TRUE;

CREATE INDEX IF NOT EXISTS idx_enrolled_agents_management_mode
    ON enrolled_agents(management_mode);
