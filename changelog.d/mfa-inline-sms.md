### Added
- **SMS can be set up during sign-in, once SMS is really available.** When an MFA policy
  requires `sms` and the installation has SMS enabled with a real (non-mock) provider, the
  login page's "add a sign-in method" step offers a text message: enter the number, then the
  code (`POST /oauth/mfa/enroll/sms/begin` and `/finish`). It is never offered to external
  users, and with SMS disabled (the default) nothing changes. The availability check is
  repeated on every call.
- A test now pins that authenticator-app enrolment produces an `otpauth://` URI with
  SHA1, 30 seconds and 6 digits, the parameters Google and Microsoft Authenticator support.
