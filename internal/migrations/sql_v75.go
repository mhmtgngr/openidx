package migrations

// Migration v75 — add known_devices.device_type.
//
// The device-trust auto-approval path (internal/identity/device_trust_approval.go
// isCorporateDevice) filters known_devices on a `device_type` column the table
// never had (v19 created it without one): the query errored on every call, the
// error was swallowed by the bare .Scan, and the function always returned
// false — so the `auto_approve_corporate_devices` org setting (v39) was
// silently inert. Adding the column makes the check executable: the
// name-based match works with existing rows immediately, and device_type can
// be populated to 'corporate' by MDM/admin tooling. Plain statements only —
// the runner's splitSQL cannot handle DO $$ blocks.
var knownDevicesDeviceTypeUp = `-- Migration 075: known_devices.device_type (corporate-device auto-approval was inert).
ALTER TABLE known_devices ADD COLUMN IF NOT EXISTS device_type VARCHAR(50);`

var knownDevicesDeviceTypeDown = `-- Rollback 075
ALTER TABLE known_devices DROP COLUMN IF EXISTS device_type;`
