# PAM maturity assessment

An honest view of where OpenIDX privileged access management stands: what is
production-grade, what is newer, and what is deliberately not built.

## Mature

These capabilities are in production use, covered by integration tests and
documented in [Privileged Access (PAM)](privileged-access.md).

| Area | What it does |
|------|--------------|
| Session brokering with credential injection | RDP, SSH, VNC and web sessions are brokered; the vaulted credential is injected server-side and never reaches the user. |
| Recording | Sessions are recorded, sealed against tampering, retained per policy and replayed in the console player. |
| Watermark | Live sessions carry a user/time watermark. |
| Risky-command warnings | SSH sessions flag risky commands to the user and the audit trail. |
| Checkout controls | Break-glass, dual-control and exclusive checkout on vaulted secrets. |
| Approvals | Pre-session access requests with an approver workflow. |
| Moderated sessions | A session can wait until a moderator joins to watch it. |
| SSH CA | Short-lived SSH certificates issued by the OpenIDX CA. |
| Cloud JIT | Just-in-time cloud role elevation. |
| RDM import | Import of Remote Desktop Manager data sources into PAM entries. |
| External vendor rules | Vendor users are held to locked policy (approval, recording, moderation). |
| Device gate | Sessions can require a trusted, compliant device. |
| Audit | Every checkout, reveal, session and policy change lands in the unified audit log. |

## Credential rotation

A rotation engine (`internal/credentials`) rotates vaulted secrets on a
schedule, on demand, or on checkout, with 8 connectors: `ssh`, `ssh_key`,
`postgres`, `mysql`, `aws_iam`, `gcp_sa`, `directory` and `generate_only`.
Each run is recorded in a ledger; a failed run keeps the previous version
current.

Rotation is now visible from PAM: every connection entry with a vaulted
secret shows a chip (*Rotated every N h · last OK hh:mm*, *Rotation FAILED*
or *Not rotated*) and an **Enable rotation** action that prefills the
connector from the entry. The engine is mature; the PAM surface is new.

## Out of scope

- **Account discovery.** OpenIDX does not scan hosts or directories for
  unmanaged privileged accounts. Accounts are onboarded explicitly (console
  or RDM import).
- **Service-account dependency mapping.** Rotation does not discover or
  update services, scheduled tasks or config files that embed a rotated
  credential. Use rotation on accounts whose consumers read from the vault.

## Runbook: enable rotation on an SSH entry

Prerequisites: the entry has a vaulted secret, and a separate vault secret
holds an admin credential (password or private key) that may change the
target user's password on the host.

1. Open **PAM → Connections**. The entry shows **Not rotated**.
2. Click **Enable rotation** (circular-arrows icon). The policy form opens
   with connector **SSH** and host, port and username taken from the entry.
3. Fill the admin fields: **Admin secret**, **Admin username**, **Admin auth**
   and the target's **Host key** (`ssh-keyscan -t ed25519 <host>`).
4. Choose the interval (for example 24 hours) and keep **Enabled** checked.
5. Create the policy. Then open **Vault → Secrets → (secret) → Rotations**
   and click **Rotate now** once to prove it end to end.
6. Back in PAM the chip reads **Rotated every 24 h · last OK hh:mm**. Connect
   to the entry to confirm the injected credential works.

If the chip shows **Rotation FAILED**, read the error on the secret's
Rotations tab. The previous version stays current, so sessions keep working.

## Runbook: roll back rotation

1. **Stop further rotations.** In **Vault → Rotation Policies**, edit the
   policy and uncheck **Enabled** (or delete it). The PAM chip returns to
   **Not rotated**.
2. **Restore a known credential if needed.** If the host must go back to a
   password you control, set it on the host, then add it as a new version
   on the vault secret (**New version**). Sessions inject the current
   version, so the entry works again immediately.
3. Check the audit log for `credential.rotation_*` events to confirm no run
   is in flight.
