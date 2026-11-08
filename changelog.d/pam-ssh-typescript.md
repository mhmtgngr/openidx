### Added
- **Text transcripts of recorded SSH sessions.**
  - **What is recorded:** A recorded SSH session now also records what was
    typed and what the shell printed (guacd's typescript), beside its screen
    recording.
  - **Handling:** The transcript is sealed at rest, purged on retention and
    downloadable from the same place as the recording.
  - **Download:** Administrators download it from **Privileged Sessions →
    Entry Sessions → Transcript**, or with
    `GET /pam/sessions/{id}/typescript`. Each download is audited as
    `pam.typescript_downloaded`.
  - **Where it is written:** The path is the server's. The `typescript-*`
    settings stay reserved.
