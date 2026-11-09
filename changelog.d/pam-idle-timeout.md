### Added
- **The PAM idle timeout is enforced.** A recorded privileged session with no
  keyboard, mouse or touch input for the policy's idle timeout, read from its
  recording, is ended with reason `idle_timeout` and audited. Unrecorded
  sessions are never judged, and a session whose last input the recording
  tail cannot show is kept.
