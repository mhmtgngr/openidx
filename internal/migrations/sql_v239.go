package migrations

// Migration 239: how a privileged RDP session checks the target's
// certificate, and what crosses the session besides the screen.
//
// RDP certificate. GuacamoleClient.CreateConnection wrote ignore-cert=true on
// every RDP connection it created, so guacd accepted whatever certificate the
// target presented and the server-to-target leg was open to a man in the
// middle off the overlay. Checked against guacd 1.6.0 and a self-signed xrdp
// target: with ignore-cert the session paints; without it, and with a wrong
// pinned fingerprint, guacd refuses ("Certificate validation failed"); with
// the right fingerprint it paints. pam_entries now says which of those it
// wants:
//
//   rdp_cert_mode  'verify' (the default for a new entry): the certificate
//                  must validate; 'pin': it must match one of
//                  rdp_cert_fingerprints (the way to trust a self-signed
//                  server without trusting everything); 'ignore': any
//                  certificate is accepted, which the console marks.
//
// Every RDP-protocol entry that exists is set to 'ignore', which is what it
// already did, so nothing that works today stops working on upgrade; each is
// shown as "certificate not checked" until an administrator pins or verifies
// it.
//
// Clipboard and file transfer. An entry's free-form settings could turn on
// drive redirection or SFTP and point them anywhere (drive-path,
// sftp-root-directory), and nothing but the external-user hardening ever
// turned them off. They are now columns the launch reads, and the settings
// keys are reserved:
//
//   allow_copy / allow_paste  clipboard out of / into the session (default
//                             true: today's behaviour)
//   allow_file_transfer       drive redirection and SFTP (default false)
//
// An entry whose settings already enabled drive or SFTP keeps
// allow_file_transfer = true, and one whose settings disabled the clipboard
// keeps it disabled, so the upgrade changes no session. The settings keys are
// left in place and ignored from now on.
//
// Columns under the table's existing org policy; down drops them.

var pamSessionChannelsUp = `-- Migration 239: RDP certificate checking and session channels.
ALTER TABLE pam_entries ADD COLUMN IF NOT EXISTS rdp_cert_mode VARCHAR(10) NOT NULL DEFAULT 'verify';
ALTER TABLE pam_entries ADD COLUMN IF NOT EXISTS rdp_cert_fingerprints TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE pam_entries ADD COLUMN IF NOT EXISTS allow_copy BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE pam_entries ADD COLUMN IF NOT EXISTS allow_paste BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE pam_entries ADD COLUMN IF NOT EXISTS allow_file_transfer BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE pam_entries DROP CONSTRAINT IF EXISTS pam_entries_rdp_cert_mode_check;
ALTER TABLE pam_entries ADD CONSTRAINT pam_entries_rdp_cert_mode_check
    CHECK (rdp_cert_mode IN ('verify', 'pin', 'ignore'));

-- What every existing RDP entry already did.
UPDATE pam_entries SET rdp_cert_mode = 'ignore'
 WHERE entry_type IN ('rdp', 'windows_app_host');

UPDATE pam_entries SET allow_file_transfer = true
 WHERE lower(COALESCE(settings->>'enable-drive', '')) = 'true'
    OR lower(COALESCE(settings->>'enable-sftp', '')) = 'true';
UPDATE pam_entries SET allow_copy = false
 WHERE lower(COALESCE(settings->>'disable-copy', '')) = 'true';
UPDATE pam_entries SET allow_paste = false
 WHERE lower(COALESCE(settings->>'disable-paste', '')) = 'true';
`

var pamSessionChannelsDown = `-- Rollback migration 239.
ALTER TABLE pam_entries DROP CONSTRAINT IF EXISTS pam_entries_rdp_cert_mode_check;
ALTER TABLE pam_entries DROP COLUMN IF EXISTS allow_file_transfer;
ALTER TABLE pam_entries DROP COLUMN IF EXISTS allow_paste;
ALTER TABLE pam_entries DROP COLUMN IF EXISTS allow_copy;
ALTER TABLE pam_entries DROP COLUMN IF EXISTS rdp_cert_fingerprints;
ALTER TABLE pam_entries DROP COLUMN IF EXISTS rdp_cert_mode;
`
