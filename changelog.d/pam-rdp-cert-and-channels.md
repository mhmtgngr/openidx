### Security
- **PAM RDP sessions check the target's certificate.** The broker used to
  create every RDP connection with `ignore-cert=true`, so a machine between the
  broker and the target could read the session and the injected credential.
  Each RDP entry now has a certificate mode: **Verify** (the default for a new
  entry), **Pin fingerprint** for a self-signed server, or **Do not check**.
  Verify and Pin also hold the session to NLA or TLS, because guacd checks no
  certificate on a standard-RDP-security session.
- **Clipboard and file transfer are entry policy, not free-form settings.**
  Each session entry now has *Copy out*, *Paste in* and *File transfer* (drive
  redirection for RDP, SFTP for SSH, in a directory the server chooses).
  Settings keys such as `ignore-cert`, `enable-drive`, `drive-path`,
  `enable-sftp`, `sftp-*`, `disable-copy`, `disable-paste` and `typescript-*`
  are reserved and no longer reach the broker. Only an administrator can open a
  channel, weaken the certificate check or pin a new certificate. An editor who
  tries gets `403 session_policy_admin_only`. Every change is audited as
  `pam.entry_policy_changed`.

### Added
- **Read the target's certificate.** In an RDP entry's dialog, *Read the
  target's certificate* shows the fingerprint, subject, validity and whether
  the server trusts it, and *Pin this certificate* pins it
  (`POST /pam/entries/{id}/rdp-certificate`, administrators only, audited as
  `pam.entry_certificate_read`).
- **Badges on the connection list.** RDP entries show *cert not checked* or
  *cert pinned*. Entries that allow file transfer show *files*.

### Upgrade notes
- **Migration 239.** It keeps every existing session behaving as it did:
  - Existing RDP entries are set to **Do not check**, which is what the broker
    already did. They show *cert not checked* until an administrator pins or
    verifies them.
  - An entry whose settings turned on drive or SFTP keeps file transfer.
  - An entry whose settings turned off the clipboard keeps it off.
  - New entries verify the certificate and have no file transfer.
- **Check targets before switching to Verify or Pin.** A target that offers
  only standard RDP security refuses sessions in Verify or Pin mode until TLS
  or NLA is enabled on it. *Read the target's certificate* reports this case.
