# 0004 — Native clients for privileged sessions: a launcher beside Guacamole, not a replacement

- **Status:** Proposed
- **Date:** 2026-11-06
- **Approved by:** _pending_ — @mhmtgngr decides. Drafted by an AI agent after
  an evaluation of mRemoteNG requested by the maintainer. Nothing here is
  decided until the maintainer confirms it in writing.

## Context

Administrators asked whether [mRemoteNG](https://github.com/mRemoteNG/mRemoteNG)
could manage systems instead of Guacamole, or be added to the Windows client.

**What Guacamole does in OpenIDX is server-side, and the product's wedge
depends on it** ([ADR 0001](0001-product-focus-and-trusted-core.md): access
"approved and recorded"). A launch passes the entry's gates in
`connectPamEntry` (`internal/access/pam_launch.go`: connect grant, single-use
approval, step-up, device gate), then guacd connects from the server with the
vault credential injected, so the person never sees it
(`internal/access/guacamole.go`). The server records and seals the session
(`guac_recording_sealer.go`), keeps transcripts and legal holds, enforces
moderation (four-eyes, live), and the kill switch ends it. The person needs a
browser and nothing else, which is what third-party access needs
([ADR 0002](0002-third-party-access-and-temporary-privilege.md)).

**mRemoteNG is a client-side connection manager.** Facts from its repository
(`v1.78.2-dev`, November 2026):

- Windows only, C#/.NET 10, tabbed RDP/VNC/SSH/Telnet/HTTP; active, but
  releases are nightly pre-releases.
- **GPL-2.0.** OpenIDX is Apache-2.0: its code, connectors and plugin
  contract (`mRp.Contracts.dll`) cannot be linked into or shipped with
  OpenIDX. Starting it as a separate program is the only clean boundary.
- The session runs from the person's PC straight to the target. It records
  nothing server-side and has no moderation or remote termination.
- Credentials come from its own file or from connectors for Delinea,
  Passwordstate and 1Password (`mRemoteNGDocumentation/howtos/credvault.rst`).
  It has no OpenIDX connector; writing one would be GPL code.
- Its command line loads a connections file (`/cons`); it cannot open one
  named connection from the command line. Its parser
  (`mRemoteNG/Tools/Cmdline/StartupArgumentsInterpreter.cs`) reads only
  `cons`/`c`, `reset*` and `noreconnect`, so a launcher can hand it a
  one-connection file but the person still has to open the connection.
- Its 1.78.2 notes fix SQL injection, command injection, XXE and path
  traversal in the same release.
- It already documents fronting a PAM proxy (`howtos/cyberark-psm.rst`): the
  connection goes to the proxy, and the proxy records. That is the model this
  ADR keeps.

OpenIDX already has a native path for SSH: `POST /pam/connect/ssh` issues a
short-lived, principal-scoped certificate from the org CA
(`internal/access/ssh_ca.go`), and `openidx-connect` uses it. The Windows
tray launches PAM entries only through the browser
(`agent/internal/desktoppam`).

**Checked against real software on 2026-11-06** (throwaway database and a
user-level `sshd` on loopback; nothing live touched):

- A certificate from the real `handleSSHConnect` (one-minute TTL) logged in
  to a stock OpenSSH server configured only with `TrustedUserCAKeys` set to
  the org CA: `Accepted certificate ID "openidx:<user>:<login>"`.
- After the certificate expired, a new login was refused
  (`Certificate invalid: expired`, `Permission denied (publickey)`), but a
  session opened before expiry was still running five seconds after it.
- The managed Windows test PC already has `mstsc.exe` and Windows OpenSSH
  (`OpenSSH_for_Windows_10.0p2`); mRemoteNG is not installed.

## Options

1. **Replace Guacamole with mRemoteNG.** Loses server-side recording,
   moderation, termination, credential hiding and clientless access. Ships
   a GPL Windows-only tool as the PAM client. Rejected.
2. **Embed mRemoteNG in the Windows client.** Licence conflict (GPL-2.0 into
   Apache-2.0), a .NET runtime beside the Go agent, and the same lost
   controls as option 1 for every session it opens. Rejected.
3. **Keep Guacamole as the brokered path; add an opt-in native launch to the
   tray, using the client already on the PC.** The server decides through
   the same gates and hands out a short-lived credential over the Ziti
   tunnel; the tray opens `mstsc` (RDP) or Windows OpenSSH (SSH). An
   administrator who prefers mRemoteNG may choose it as the launcher; the
   agent starts it as a separate process and ships none of it.
4. **Do nothing.** Administrators keep using local tools outside OpenIDX,
   with standing credentials and no record at all.

## Decision (proposed)

Option 3, in this order, and only after M1 (the feature freeze in
[ADR 0001](0001-product-focus-and-trusted-core.md) holds):

1. **Native launch is an entry property, off by default.**
   `pam_entries.allow_native_launch`; an administrator enables it per entry,
   and the entry's gates apply unchanged. A recorded or moderated entry
   cannot enable it.
2. **SSH first.** `desktoppam.NativeLaunch` asks `POST /pam/connect/ssh` for a
   certificate, writes it to a file only the person can read, starts
   OpenSSH through the tunnel, and deletes the file when the process ends.
3. **RDP second.** A single-use credential (vault checkout, minutes-long TTL,
   rotated at check-in) and a generated `.rdp` file opened by `mstsc`; the
   password goes to the Windows credential store for the session and is
   removed after it, never into the file.
4. **mRemoteNG last, optional.** If installed and chosen, the agent writes a
   one-connection file and starts `mRemoteNG.exe /cons <file>`, with the
   same credential handling; the person opens the connection from the
   tree, since mRemoteNG has no switch to open it. No mRemoteNG code is
   distributed.
5. **Every native launch is a `brokered_sessions` row marked native and
   unrecorded**, visible on Privileged Sessions.

## Consequences

- Administrators get the local client's display, clipboard, multi-monitor
  and performance for entries that allow it, without standing credentials.
- **A native session gives up controls**, and the console must say so where
  the switch is: no server recording, no live moderation, and the kill
  switch only stops the credential: an open RDP or SSH session lasts until
  the person ends it (an SSH certificate's TTL limits new logins, not a
  session already open).
- Recording native RDP would need an RDP gateway or proxy on the server: a
  separate decision, not taken here.
- Guacamole stays the default and the only path for third-party users,
  recorded entries and moderated entries.
- OpenIDX takes no GPL dependency. mRemoteNG support is a launcher choice
  and may be dropped without affecting the product.
