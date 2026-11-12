# Agent code signing

The Windows agent (exe and MSI) is Authenticode-signed, and every update
manifest (`latest.json`) is signed with the same key. Today that key is a
**self-signed** certificate. An OV/EV certificate will replace it; this runbook
covers both, and the switch is designed to need no flag day.

Where the certificate lives:

| File | Role |
|---|---|
| `agent/packaging/openidx-codesign.cer` | Public half used by packaging and the trust script |
| `agent/internal/updater/release-publisher.cer` | Byte copy embedded in the agent: the pinned manifest publisher (a test keeps the two identical) |
| `agent/internal/updater/release-publisher-next.cer` | Optional second pinned publisher, embedded. Empty means none |
| `WINDOWS_CERT_PFX_BASE64`, `WINDOWS_CERT_PASSWORD` (repo secrets) | Private key: signs the exe, the MSI and `latest.json` in CI |
| `AGENT_MANIFEST_SIGNING_KEY` (box env) | Same private key, PEM: re-signs the box mirror's `latest.json` and the downloads manifest |

## Now: self-signed

Windows does not trust the self-signed certificate on its own, so SmartScreen
and `msiexec` warn unless the certificate is in the machine's stores. Push it
before (or with) the agent:

- **Intune:** Devices > Configuration > Create > Windows 10 and later >
  Templates > Trusted certificate. Upload `openidx-codesign.cer` twice: once
  with destination store **Computer certificate store - Root**, once with
  **Trusted Publishers** (use a custom OMA-URI
  `./Device/Vendor/MSFT/RootCATrustedCertificates/TrustedPublisher/<thumbprint>/EncodedCertificate`
  for the second if the template lacks it). Assign to the agent device group.
- **GPO:** Computer Configuration > Policies > Windows Settings > Security
  Settings > Public Key Policies. Import the `.cer` into **Trusted Root
  Certification Authorities** and into **Trusted Publishers**. Link the GPO to
  the agent OU, `gpupdate /force`.
- **Single machine:** the served `trust-and-install-openidx-agent.ps1` imports
  the certificate into both stores and installs the MSI.

Update manifests do not depend on the Windows stores: the agent verifies them
against the embedded `release-publisher.cer` regardless.

See also the GPO and Intune deployment runbooks (`agent-gpo.md`,
`agent-intune.md`).

## Switching to OV/EV

The agent only acts on a manifest signed by a pinned publisher, so a release
signed with a new key would be refused by every installed agent. The overlap
release avoids that:

1. **Get the certificate.** For EV (and OV since 2023) the key lives on an HSM
   or a cloud signing service. Decide how CI reaches it (cloud KMS / signing
   service credentials as repo secrets) and keep the self-signed PFX secrets
   in place for now.
2. **Overlap release (signed with the OLD key).** Commit the new certificate's
   DER as `agent/internal/updater/release-publisher-next.cer`. Leave
   `release-publisher.cer` as is. Release `agent-vX.Y.Z`, mirror it, roll it
   out to 100%. Every agent now trusts old and new. Also push the new
   certificate via Intune/GPO if it is not chained to a public root (OV/EV
   are, so normally nothing to push).
3. **Wait** until the Agent Fleet page shows the whole fleet on the overlap
   version (or newer). Devices still below it would refuse step 4.
4. **Switch.** Replace the CI signing secrets with the new key, replace
   `agent/packaging/openidx-codesign.cer` and `release-publisher.cer` with the
   new certificate, empty `release-publisher-next.cer`, and set the box's
   `AGENT_MANIFEST_SIGNING_KEY` to the new key at the same time (the box
   re-signs `latest.json`, so it must use a key the fleet trusts: after step 3,
   either works). Release and mirror.
5. **Retire.** Once the fleet runs the switch release, remove the old
   self-signed certificate from the Intune/GPO profiles and delete the old
   PFX secrets.

The mirror script (`scripts/agent-mirror.sh`) checks upstream signatures
against both pinned files, so it accepts releases from either key during the
overlap.

## Notes

- `update_trusted_cert` in `agent.json` still **replaces** the pinned
  publishers (both of them) for installs that publish their own builds.
- The pinned certificate's validity window is enforced: rotate before it
  expires, using the same overlap procedure.
- `release-publisher-next.cer` that does not parse is ignored with a message,
  and a unit test fails the build, so a broken file cannot cost agents the
  current publisher.
- An OV/EV key held on an HSM cannot be exported to the box as
  `AGENT_MANIFEST_SIGNING_KEY`. In that case keep the manifest publisher a
  separate, exportable RSA key (its certificate is what the two `.cer` files
  pin) and use the OV/EV certificate for Authenticode only. Changing the
  manifest key follows the same overlap procedure.
