### Added
- **PAM import reads Devolutions RDM's XML export, and takes it as a file.**
  File → Export in Remote Desktop Manager writes an XML `.rdm` document by
  default; the importer only understood the JSON export, so the default
  export was refused as "unrecognized". `POST /api/v1/access/pam/import/rdm`
  now accepts both. The XML maps like the JSON one: groups become folders,
  RDP sessions take their host from the entry's address, SSH sessions their
  host and port from the terminal settings, websites their URL, credentials
  their user name, and every other type is kept as a note with its settings
  preserved (password-like settings are never stored). The embedded icon
  pictures are dropped, which is most of an export's size. External entities in
  the file are not resolved and nesting is bounded. The import dialog gains a
  file chooser (`.rdm`, `.xml`, `.json`) next to the paste box.
