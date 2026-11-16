### Added
- **A rule engine for "why can't this device connect".** `internal/diagnose`
  takes the agent doctor's diagnostic bundle together with the server's own
  records (device status and liveness, posture, the access decision, the
  overlay's view of the service) and returns the causes in order of how much
  each explains, each with its fixes and who may carry them out (the user, a
  safe automatic fix, or a human approval). It is rules only: no database and
  no model. Nothing calls it yet; the upload endpoint and the self-service
  page follow.
