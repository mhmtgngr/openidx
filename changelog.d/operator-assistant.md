### Added
- **Operations assistant.** Operators can talk to the organization's assistant
  about the agent rollout and about opening access: "how is the update going?",
  "open the wiki to Engineering". It can look up the rollout, applications,
  groups and the plans waiting, and lay out a plan to open an application to a
  group; the plan appears in the Access plans card and an administrator still
  approves it (the assistant cannot change access, a ring or a device, and a
  new kind of tool, "propose", is what makes that boundary explicit). It is the
  same conversation machinery as the device assistant (server-side, per person,
  limited, masked) and appears on the Applications and Agent Fleet pages when the
  organization has chosen a model (`POST /api/v1/access/assist/operator/messages`).
  The device assistant never offers these tools, whoever is asking.
