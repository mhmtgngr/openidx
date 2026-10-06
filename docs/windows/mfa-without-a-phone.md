# MFA on Windows without a phone

A phone is **not** required for MFA on OpenIDX. The Windows client (the MSI's
service and tray) and the OpenIDX desktop app both sign in through your
browser, and the login page offers several phone-free second factors. The
recommended one on Windows is **Windows Hello**: fingerprint, face or PIN,
registered once as a passkey.

## Options (no phone)

| Method | How | Notes |
|---|---|---|
| **Windows Hello (passkey)** ✅ recommended | Fingerprint / PIN / face | Built into Windows via WebAuthn. Phishing-resistant. Register once, then authenticate with a gesture. |
| **Security key (FIDO2)** | YubiKey or similar | Registered on the same page as Windows Hello; works in any browser; phishing-resistant. |
| **TOTP** | Any authenticator app or password manager | Enroll a TOTP secret; generate 6-digit codes anywhere. |
| **Email OTP** | Code sent to your email | No phone; just your inbox. |
| **Backup codes** | One-time codes stored offline | Supplemental. |

Only **push approval** and **SMS OTP** need a phone.

## Set up Windows Hello from the tray

This is the path for a PC with the OpenIDX MSI installed. The device must be
enrolled; the tray says "Not enrolled" otherwise and the item explains what
to do.

1. Right-click the OpenIDX tray icon and choose **Set up Windows Hello
   sign-in**. Your browser opens the console's **Security Keys** page
   (`<server>/security-keys`). If the browser has no OpenIDX session yet, it
   asks you to sign in first, with your password and your current second
   factor; the page then loads.
2. Click **Add**, name the key, and follow the Windows Hello prompt
   (fingerprint, PIN or face), or touch your security key. If your account
   already has a second factor, the page asks for your password before the
   key is saved. The browser and Windows run the WebAuthn ceremony: the
   private key never leaves your device, and the tray holds nothing from it.
3. From now on the login page offers Windows Hello in two places:
   - **Sign in with a passkey**, above the password form, whenever the
     browser supports passkeys: one gesture, no password, no code.
   - As the **second factor** after your password, when a policy asks for
     one and a passkey is among your enrolled methods.

Windows Hello must be set up in Windows first (Settings → Accounts →
Sign-in options). Edge, Chrome and Firefox on Windows 10 and 11 all support
platform authenticators.

The Security Keys page is listed in the console's navigation for
administrators only; every signed-in person can open it by its address,
which is what the tray and the desktop app do.

## Set up Windows Hello from the desktop app

In the OpenIDX desktop app, the home screen's **Set up Windows Hello
sign-in** card opens the same page in your browser. The steps above apply.

## Privileged connections that ask for a recent second factor

A connection under **My Connections** can be refused because the session's
second factor is not recent enough (`step_up_required`). The tray then
offers to sign you in again. Accept, and the browser asks you to
authenticate afresh.

Sign in with Windows Hello. Either way works: the **Sign in with a passkey**
button on its own, or your password with Windows Hello as the second factor.
Windows Hello checks your fingerprint, face or PIN before it signs in, and
the authenticator reports that check to the server. The server counts a
passkey sign-in with that check as multi-factor: it records the session's
methods as `hwk user mfa` and stamps it as MFA-verified, so the connection
goes through.

A passkey that only checks that you are present counts as one factor, for
example a security key you touch but that asks for no PIN or fingerprint.
The server records `hwk` alone and does not stamp the session, so that
sign-in does not clear a step-up. Use such a key as the second factor after
your password, or set a PIN on it.

## Behind the scenes

- Registering and listing keys: `POST /api/v1/identity/mfa/webauthn/register/begin`,
  `POST .../register/finish` (with factor proof when the account already has a
  second factor), `GET .../mfa/webauthn/credentials`. These are self-service:
  any signed-in user may call them for their own account.
- Passkey-first sign-in: `POST /oauth/passkey-begin` and `/oauth/passkey-finish`.
  The finish step reads the user-verified (UV) flag from the signed
  authenticator data and records the session's `amr` from it: `hwk user mfa`
  with the flag, which also sets `mfa_verified_at` (what the step-up gate
  reads), and `hwk` without it. The sign-in asks for user verification as
  "preferred", the browser's default, so an authenticator that can verify the
  person does.
- Windows Hello as the second factor: `POST /oauth/mfa-webauthn-begin` and the
  matching finish, driven by the login page after a password sign-in.

Nothing device-specific is required beyond a browser with a platform
authenticator.
