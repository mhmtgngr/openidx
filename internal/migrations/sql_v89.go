package migrations

// Migration v89 — pam_entries.renderer (clientless remote-access renderer).
//
// A PAM entry can be opened by different CLIENTLESS renderers in the browser:
//   - 'guacamole' (default) — Apache Guacamole renders RDP/SSH/VNC server-side
//     via guacd (today's behavior; unchanged for every existing entry).
//   - 'wasm-ssh'  — an in-browser terminal (xterm.js) speaks SSH over a WS->TCP
//     relay that dials the target over the Ziti overlay. Lightest/fastest.
//   - 'novnc'     — noVNC over the same WS relay (framebuffer, no guacd).
//   - 'support'   — a WebRTC remote-support session to an enrolled agent
//     (screen share / take-over), not a protocol connection.
//
// This only records the desired renderer; the launch path dispatches on it. The
// permission/approval gate (pamEntryAllowed) is unchanged and applies to every
// renderer. Additive + idempotent; backfills existing rows to 'guacamole' so
// there is no behavior change.
var pamEntryRendererUp = `-- Migration 089: pam_entries.renderer (clientless renderer selection).
ALTER TABLE pam_entries ADD COLUMN IF NOT EXISTS renderer VARCHAR(16) NOT NULL DEFAULT 'guacamole';
UPDATE pam_entries SET renderer = 'guacamole' WHERE renderer IS NULL OR renderer = '';
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'pam_entries_renderer_check'
    ) THEN
        ALTER TABLE pam_entries
            ADD CONSTRAINT pam_entries_renderer_check
            CHECK (renderer IN ('guacamole', 'wasm-ssh', 'novnc', 'support'));
    END IF;
END $$;`

var pamEntryRendererDown = `-- Rollback 089.
ALTER TABLE pam_entries DROP CONSTRAINT IF EXISTS pam_entries_renderer_check;
ALTER TABLE pam_entries DROP COLUMN IF EXISTS renderer;`
