# MFA on Windows without a phone

A phone is **not** required for MFA on OpenIDX. The desktop client signs in
through your browser, and the login page supports several phone-free second
factors. The recommended one on Windows is **Windows Hello**.

## Options (no phone)

| Method | How | Notes |
|---|---|---|
| **Windows Hello (passkey)** ✅ recommended | Fingerprint / PIN / face | Built into Windows via WebAuthn. Phishing-resistant. Register once, then sign in with a gesture. |
| **Security key (FIDO2)** | YubiKey or similar | Works in any browser; phishing-resistant. |
| **TOTP** | Any authenticator app or password manager | Enroll a TOTP secret; generate 6-digit codes anywhere. |
| **Email OTP** | Code sent to your email | No phone; just your inbox. |
| **Backup codes** | One-time codes stored offline | Supplemental. |

Only **push approval** and **SMS OTP** need a phone.

## Set up Windows Hello (recommended)

1. In the OpenIDX desktop app, open **Set up Windows Hello sign-in** (home
   screen). It opens the browser to the **Security Keys** page.
2. Click **Add** and follow the Windows Hello prompt (fingerprint / PIN / face).
   The browser + Windows handle the WebAuthn ceremony — the private key never
   leaves your device.
3. Sign out and sign in again: choose **passkey** and authenticate with Windows
   Hello. No phone, no code to type.

Backend: the WebAuthn registration/authentication endpoints are
`/api/v1/identity/mfa/webauthn/register/{begin,finish}` and the passkey-first
login is served by the OAuth login page. Nothing device-specific is required
beyond a browser that supports platform authenticators (Edge/Chrome/Firefox on
Windows all do).
