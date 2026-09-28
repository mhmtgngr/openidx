package migrations

// Migration v210 -- clear the settings values that named a domain this project
// does not own, where they are still the shipped defaults.
//
// Migration 014 seeded the system settings document with a support address
// at a domain this project does not own, and the console's settings handler
// defaulted its support address and its WebAuthn relying party ID and origin
// to the same domain. The project has never owned it (SECURITY.md), so anyone
// may register it. The defaults are empty now; this clears the stored copies.
//
// ONLY VALUES THAT CANNOT BE WORKING ARE TOUCHED. Each statement matches the
// exact shipped value and nothing else, so an address or a relying party an
// administrator typed stays as it is. The support address is displayed and
// read by nothing else. The WebAuthn fields in admin_console_settings are not
// the relying party a passkey is bound to -- that is the identity service's
// WEBAUTHN_RP_ID -- so clearing them invalidates no passkey. A row reaches
// admin_console_settings only when an administrator saves or resets the
// console settings, which wrote the defaults in with whatever was changed.
//
// updated_at and updated_by are left alone: this is not an administrator's
// change, and the settings page reports those as the last one.
//
// Down restores nothing. Putting the domain back is the one outcome worth
// preventing, and which rows held the default is not recorded.

var unownedDomainDefaultsUp = `-- Migration 210: clear the unowned-domain defaults still stored in the settings.
UPDATE system_settings
   SET value = jsonb_set(value, '{general,support_email}', '""'::jsonb)
 WHERE key = 'system'
   AND value #>> '{general,support_email}' = 'support@openidx.io' /* domain-ok: the shipped default */;

UPDATE admin_console_settings
   SET value = jsonb_set(value, '{support_email}', '""'::jsonb)
 WHERE key = 'general'
   AND value ->> 'support_email' = 'support@openidx.io' /* domain-ok: the shipped default */;

UPDATE admin_console_settings
   SET value = jsonb_set(value, '{mfa,webauthn,relying_party_id}', '""'::jsonb)
 WHERE key = 'security'
   AND value #>> '{mfa,webauthn,relying_party_id}' = 'openidx.io' /* domain-ok: the shipped default */;

UPDATE admin_console_settings
   SET value = jsonb_set(value, '{mfa,webauthn,relying_party_origin}', '""'::jsonb)
 WHERE key = 'security'
   AND value #>> '{mfa,webauthn,relying_party_origin}' = 'https://openidx.io' /* domain-ok: the shipped default */;
`

var unownedDomainDefaultsDown = `-- Migration 210 down: no-op. The cleared values named a domain this project
-- does not own; putting them back is what the migration exists to prevent.
SELECT 1;
`
