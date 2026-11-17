### Added
- **Open an application to a group with a plan (wave 3, migration 263).** On the
  Applications page an operator names an application and a group, each by name
  or id, and gets a plan before anything changes: whether it can be done,
  exactly what it does, what is worth reading first (an empty group, a group of
  half the organization or more, a privileged resource) and what a member of the
  group can do with it today, judged by the same decision engine the proxy uses.
  An administrator approves it (`POST /api/v1/access/plans/{id}/approve`), which
  makes the assignment only if the application and group are unchanged and then
  checks again what a member can now do and says so; the plan can be undone
  (`.../undo`), which removes exactly that assignment. A plan for access the
  group already has is "nothing to do" and is not stored. The rules are in
  `internal/accessplan`; no model is involved.
