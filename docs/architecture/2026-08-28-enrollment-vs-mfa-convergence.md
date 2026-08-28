# Device Enrollment vs. User MFA — is running both "normal"? And how we converge them

**Date:** 2026-08-28
**Status:** Accepted — implementation tracked as the "FastPass convergence" plan (Phase 1 push auto-registration, Phase 2 device-bound passkey).

## The question

When connecting an OpenIDX client, a user enrolls the device with a **code** and *then* also uses the app's **MFA** features (TOTP / push / passkey) separately. Is that normal, architecturally and for the end user? How do comparable products handle it?

## Short answer

**Yes — running both is architecturally correct.** Enrollment and MFA solve two different problems and every serious identity product keeps them as distinct layers. But the *sequence the user experienced* — "enroll with a code, then separately set up MFA" — is a **UX gap**, not an architecture requirement. Best-in-class products collapse the two into a single act: one enrollment turns the phone into the authenticator. OpenIDX already has all the parts to do the same; they are simply not wired together at enrollment time. This document explains why the layers are separate, what the leaders do, and what we are changing.

## Why the two layers are genuinely different

| | Device enrollment (the code) | User MFA (TOTP / push / passkey) |
|---|---|---|
| Question it answers | "Is this a **known device** on the network?" | "Is this really the **user**?" |
| Trust anchor | Device identity (Ziti overlay cert + `enrolled_agents` credential + `known_devices` record + posture) | User authentication factor(s) at login |
| When it happens | Once, at onboarding | Every login the risk engine deems risky |
| Lifetime | Persists until device is revoked | Per-session |
| NIST framing | Device identity / device attestation | Authenticator (AAL2/AAL3) |

Concretely in OpenIDX:

- **Enrollment** (`internal/access/agent_api.go` `HandleEnroll`, agent side `agent/internal/enrollment/enroll.go`): redeeming the code issues agent credentials, a Ziti overlay identity (`ensureAgentZitiIdentity`), and mirrors the device into IAM `known_devices` (`linkAgentToKnownDevice`). If the code was created from an MFA-verified console session, the device may be auto-trusted (`device_autotrust.go` `decideAutoTrust`). Enrollment does **not** authenticate the user to the agent — the agent authenticates as a *device*.
- **MFA** (`internal/oauth/service.go` login flow + `internal/identity/adaptive_mfa.go` risk policies): demanded at OAuth login based on risk (new device/location, impossible travel, IP reputation, policy). Factors: TOTP (`identity/service.go`), push number-match (`identity/pushmfa.go`), WebAuthn/passkey (`identity/webauthn.go`).

Because they are different layers, it is normal — and often desirable — to have both. A trusted device with a weak user factor is not the same assurance as a strong user factor on an unknown device. Keeping them separable is what lets the risk engine reason about each independently (and, for example, *reduce* MFA prompts on a trusted device).

## What the leaders do

The important nuance: leaders keep the two **concepts** separate internally but fuse them into **one user action** — enrolling the phone provisions a device-bound credential, so the enrolled phone *is* the authenticator from that moment on.

| Product | One app? | Enroll mechanism | Enroll = authenticator? | Strong factor |
|---|---|---|---|---|
| **Okta Verify (FastPass)** | yes | QR / link | **yes** — device-bound key provisioned at enroll; silent / one-tap login | device-bound passkey |
| **Microsoft Authenticator** | yes | QR + device registration | **yes** — passwordless phone sign-in key at setup | device-bound key + number match |
| **Duo Mobile** | yes | QR activation | **yes** — the activated device is the approver | Verified Duo Push (number match) + platform passkey |
| **OpenIDX (today)** | yes (Flutter client) | code / QR (`openidx://enroll`) | **no** — push/passkey are set up separately | pieces exist, not wired at enroll |

So the answer to "is this normal?" has two halves:
1. *Having* both layers — **normal and correct**.
2. *Experiencing* them as two separate setup chores — **below the modern bar**; the leaders converge them.

## What we are changing (the convergence)

The load-bearing insight is that OpenIDX's enrollment already resolves, server-side and with no extra login, exactly the identity context needed to provision MFA:

- `sess.CreatedByUID` — the user who created the code (from an MFA-verified console session)
- `sess.OrgID` — the tenant
- `sess.MFAVerified` — **server-verified** second-factor state (from the console `amr` claim; never client-supplied)

This is the same authorization model already used by push QR self-enrollment (`CompletePushEnrollment`: "the ticket is the authorization; no login required; org must match"). So we reuse the existing primitives rather than build anything parallel.

**Phase 1 — push auto-registration at enrollment.** When the mobile device redeems its code, it also registers itself as a push-MFA approver (reusing `RegisterPushMFADevice`), inheriting trust from `decideAutoTrust`. The phone becomes an approver immediately — no separate "set up push" step.

**Phase 2 — device-bound passkey + login preference (FastPass).** Right after enrollment the app provisions a device-bound WebAuthn passkey (reusing `Begin/FinishWebAuthnRegistration`, under the user's OAuth deep-link token), and the login flow learns to *prefer* push/passkey from the enrolled, trusted device — making subsequent logins one-tap and phishing-resistant, so enrollment "counts" as a strong factor.

Both phases are **additive** to the risk engine: we never bypass deny decisions or risk scoring; we only remove a redundant setup step and reorder/prefer methods for a device the server already trusts. The `mfa_verified` server-verified invariant is preserved end-to-end.

## Prerequisites / known blockers

- **Real push needs a Firebase project** (FCM HTTP v1) that is not yet provisioned; the existing **ntfy** fallback lets us demo the convergence today.
- **Device-bound passkeys need** `/.well-known/assetlinks.json` (Android) and `/.well-known/apple-app-site-association` (iOS) hosted for `openidx.tdv.org`.

## Bottom line

Keep both layers — that is the right architecture and matches Okta, Microsoft, and Duo. Close the UX gap by making a single enrollment turn the phone into the authenticator, exactly as those products do, using primitives OpenIDX already ships.
