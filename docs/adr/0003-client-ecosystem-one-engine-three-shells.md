# 0003 — The client ecosystem: one engine, three shells, and the order of the platforms

- **Status:** Proposed
- **Date:** 2026-10-15
- **Approved by:** _pending_ — @mhmtgngr decides. Drafted by an AI agent from
  [docs/plans/2026-10-15-istemci-ekosistemi-analizi-ve-yol-haritasi.md](../plans/2026-10-15-istemci-ekosistemi-analizi-ve-yol-haritasi.md)
  (in Turkish), which holds the analysis, the findings with file references,
  the phased plan and the twelve decisions it needs (its §11). Nothing here is
  decided until the maintainer confirms it in writing.

## Context

OpenIDX ships four client code bases: the Go endpoint agent (`agent/`, a
Windows service with a tray and a Linux service), the Flutter app (`client/`,
a phone companion and an undistributed desktop shell), the Kotlin Android
agent (`agent-android/`, on hold) and the `openidx-connect` CLI. The
browser console, the end-user portal and BrowZer are the fifth surface.
Since v1.37.0 the agent gained a TPM device key, signed reports, signed
plugins, a bundled OpenZiti tunneler with a versioned organisation policy, and
a per-device overlay identity.

The analysis found:

- **Three clients tell three stories.** Windows has a full agent; Linux has
  an agent without a user interface and without a signed package; macOS has
  nothing; the phone has no tunnel; the console routes two enrolment paths to
  two different Android apps.
- **The same defect class recurs: the two ends do not speak the same
  language.** Five mismatches between server and client in three weeks
  (posture check fields, tunnel status, push approval, mobile dial, mark-read).
  The agent API has no OpenAPI definition and no contract test; CI never
  enrols an agent against a live server.
- **Enrolment is the weakest link.** Re-enrolment by a client-claimed
  fingerprint does not check who owns the record and may replace the device
  key; the Tier-0 door accepts any access token; on Windows the device's
  overlay private key is readable by every local account; a deep link's
  server is not validated.
- **The network layer stops at "split tunnel, and blocking only on Linux as
  root".** No full tunnel, no DNS design, no macOS or mobile tunnel,
  controller HA only on Helm, fleet alerts defined but not loaded.
- **Usability is fixed page by page.** The tray and the phone app are
  English only; nothing is in a store; the MSI is self-signed; push approval
  reaches the phone only while the app is open.

## Options

1. **Keep four code bases and fix each in place.** Least change; the
   duplication, the English-only shells and the missing platforms remain, and
   each fix lands in one client at a time.
2. **One engine, three shells.** The Go engine (`openidx-agent`) carries every
   capability on every platform; the shells are the Go tray on Windows, macOS
   and Linux, the Flutter app on Android and iOS, and one `openidx` CLI. The
   agent API is one OpenAPI contract with a CI contract test. The Flutter
   desktop shell and the Kotlin agent are frozen and deleted once the engine
   covers what they did. Platforms arrive in the order Windows and Linux
   (now), macOS (2027 Q1), mobile tunnel (a decision in 2027 Q2).
3. **Drop native clients; BrowZer and the browser only.** Simplest, but no
   posture, no device identity, no always-on tunnel; the entry wedge
   (privileged and third-party access without a VPN) loses the managed-device
   half.

## Decision (proposed)

Option 2, in the phases the plan lays out:

- **Phase 0 (fixes, inside M1):** re-enrolment proves ownership (the same
  enrolling user, an operator token, or a request signed with the existing
  device key); the Tier-0 door requires the `agent.enroll` scope and a fresh
  factor; one `RevokeDevice` for the fleet page, Access 360 and the kill
  switch; remote-support consent on by default with unattended sessions as a
  separate permission; the device's overlay key readable only by SYSTEM on
  Windows; an agent API contract test and an OpenAPI schema; fleet alerts
  loaded in Compose and Helm.
- **Phase 1 (with v2.0 LTS):** a store-ready phone app (#966), a trusted
  code-signing certificate, signed deb/rpm packages in a repository, Turkish
  and English in the tray and the phone app, TPM attestation collected in
  observe mode, a client section in the threat model.
- **Phase 2 (2027 Q1):** the macOS agent and package, block-direct on Windows
  and macOS, a full tunnel through an egress router, a DNS policy, controller
  HA on Compose, `openidx-agent doctor`, a live-controller CI job.
- **Phase 3 (2027 Q2):** background push, Play Integrity and App Attest, the
  mobile tunnel decision, MDM templates, the `openidx` CLI, generated SDKs.
- **Frozen:** the Kotlin Android agent (deleted after six months without
  demand) and the Flutter desktop shell (deleted when the Go tray covers macOS
  and Linux).
- **Rules:** a capability is written in the engine, never in a shell; the five
  device states carry the same words on every surface; an agent must work
  with a server up to two minor versions newer (N-2); every gate ships in
  observe before enforce.

## Consequences

- **Easier:** one place for every capability; one contract and one test that
  catches the recurring mismatch class; one tray to localise and package
  three times; a phone app that can finally be published.
- **Harder:** the Go tray must be built and tested on macOS and Linux, which
  CI does not do today; the macOS tunneler needs a packaging and permission
  decision; four security fixes touch `internal/access` and the agent's
  enrolment code, which need the maintainer's review before merge.
- **We will not:** add a client capability that the engine does not have;
  ship a switch the device cannot enforce as "applied"; keep two enrolment
  paths to two Android apps; or sign pull-request builds with the release key.
