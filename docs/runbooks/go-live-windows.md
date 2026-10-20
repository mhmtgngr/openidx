# Runbook: going live with Windows devices

How an organization whose people use Windows laptops, installed by hand (no
GPO or Intune), goes from "OpenIDX is running" to "no live, compliant device,
no access", in waves, without locking anyone out on day one. The controls
themselves move from observe to enforce as [enforce-rollout.md](enforce-rollout.md)
describes; this file is the order around them.

The rule being made true: a person reaches the network and privileged
sessions only from a device whose agent is **active**, **compliant** and
**reporting** (within `AGENT_LIVENESS_TIMEOUT`, default 10 minutes); web
applications marked as needing a trusted device follow once everyone has the
agent.

## What people use

| | |
| --- | --- |
| Second factor | Any TOTP app: Google Authenticator, Microsoft Authenticator (TOTP mode), or the OpenIDX app. Or Windows Hello / a security key (passkey). The QR code is on **Profile → Security**. |
| Device | Until the MSI is signed with a public certificate: `trust-and-install-openidx-agent.ps1` (see wave 0, step 2), run once as Administrator. Then, on the same PC, **My Devices → Add a device → Open in app**, which hands the enrolment code to the agent. |

## Wave 0: before anyone signs in

1. Installers are served: place the MSI from the agent release (check its
   SHA-256 against the release's `latest.json`) in `AGENT_DOWNLOADS_DIR` (on
   the reference box `~/oidx-runtime/downloads`; the access service gets the
   variable from a systemd drop-in, since `run-access.sh` builds its own
   environment; see `deployments/apisix-edge/README.md`).
   `GET /downloads/agent-manifest.json` must list `windows`.
2. Code signing: the MSI is signed with the project's own certificate
   ("OpenIDX Code Signing"), so a machine that has never seen it shows
   "Unknown publisher" and SmartScreen warns. Either:
   - sign releases with a public OV/EV code-signing certificate (no script
     needed; the clean answer), or
   - put `agent/scripts/trust-and-install-openidx-agent.ps1` next to the MSI
     in `AGENT_DOWNLOADS_DIR`, and have each person download it from
     `https://<host>/downloads/trust-and-install-openidx-agent.ps1` and run, in
     an Administrator PowerShell:

     ```
     powershell -ExecutionPolicy Bypass -File .\trust-and-install-openidx-agent.ps1 -Server https://<host>
     ```

     It trusts the embedded certificate (pinned by SHA-256; it refuses one
     that is not CA:FALSE and code-signing only) in LocalMachine Root and
     TrustedPublisher, downloads the MSI the server's manifest names, refuses
     it unless the SHA-256 matches and the Authenticode signature is valid and
     made by that certificate, and installs it. `-Token` also enrolls;
     `-TrustOnly` and `-RemoveTrust` do only the certificate.

   Not `install-openidx-agent.ps1` from the agent release: it imports no
   certificate, and it writes the release's built-in server IP into the
   machine's hosts file for the Ziti controller and router names.

   Whoever holds the signing key can sign software these machines then run
   without a warning, so keep the key off the application server.
3. Users and groups are in (directory sync or by hand); applications are
   assigned to groups.
4. MFA policy (**MFA Management → Policies**): `required_methods = [totp, webauthn]`,
   `grace_period_hours = 168`. Leaving methods empty enforces nothing for a
   person who has no factor yet.
5. Agent checks (**Agent Fleet → checks section**): firewall `critical`, BitLocker
   `high`, screen lock `high`, OS version `high`. A critical failure makes the
   device non-compliant; a high one starts its grace period.
6. Network resources defined; tunnel policy `always_on = true`. Windows does
   not block direct access yet (`block_direct` is reported as a gap), so keep
   the VPN until the tunnel has been proved on real machines.

## Wave 1: pilot (5–10 people, IT included, one week)

```
POSTURE_DEVICE_TRUST_GATE=observe
ACCESS_ASSIGNMENT_ENFORCE=true
PAM_DEVICE_GATE=observe
SSO_DEVICE_GATE=observe
AGENT_LIVENESS_TIMEOUT=10m
```

Mark network resources and privileged targets' applications
`require_device_trust` (resource conditions). Each pilot user enrols a factor,
installs the agent and enrols the device.

Watch, daily:

- **Security → Enforcement**: would-deny counts, including **Live device**.
- **Agent Fleet**: compliance, tunnel, **Offline** badges.
- Alerts `OpenIDXAgentsMostlySilent`, `OpenIDXAgentTunnelDown`.
- Audit: `agent.stale`, `access.device.would_deny`, `pam.device.would_deny`.

Proof to collect before wave 2: stop the agent service on one pilot laptop;
within about 11 minutes it shows Offline, loses `#device-trusted`, its overlay
sessions end, and its SSO/PAM attempts record would-deny. Start the service;
access returns without an administrator.

## Wave 2: unit by unit

```
POSTURE_DEVICE_TRUST_GATE=enforce
PAM_DEVICE_GATE=enforce
SSO_DEVICE_GATE=observe
```

Network resources and privileged sessions now need a live, compliant device.
Web/SSO stays observed until every unit has the agent. Bring units in by
adding their groups to the MFA policy scope and assignments; help them through
the grace week.

## Wave 3: everything enforces

```
SSO_DEVICE_GATE=enforce
CONTINUOUS_VERIFY_ENABLED=true
```

Close the observe window (enforce-rollout.md step 3).

## When someone is locked out

| Situation | What to do |
| --- | --- |
| Lost phone / authenticator | **MFA Management → users → Reset MFA** on their row; they enrol again from Profile. |
| Grace period over, no factor | Issue a bypass code (**MFA Bypass Codes** page), then they enrol. |
| Laptop off for a while | Nothing: the next report restores trust. |
| Device non-compliant | Agent Fleet → the device's posture shows the failing check. |
| Device lost or stolen | Revoke it (user's devices page or Agent Fleet): sessions, identity and tokens go. |
| Person leaves | Kill switch with disable: sessions, tokens and devices are cut. |

## Limits worth knowing

- The SSO and PAM device gates check the **person**, not the browser: they
  prove the person has a live, compliant device, not that this sign-in comes
  from it.
- SAML sign-ins are not gated by assignment or device.
- Windows does not block direct (non-tunnel) access to internal networks.
