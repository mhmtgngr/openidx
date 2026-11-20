### Added
- **Publish an internal web application in one step, hidden from the internet.**
  Overlay Network → Network resources → *Publish an app*: a name, the address
  people type today and the groups who may use it. One call writes the network
  resource, its assignments and its trusted-device condition together or not at
  all; no proxy route, BrowZer flag or public host is created, so the
  application is reachable only through the OpenIDX agent's tunnel by the
  people it was assigned to, from a trusted device unless you untick that. A
  group or user of another organization is refused, as is a name and port that
  is already published and an address that points at the platform itself. The
  answer says what the installation actually enforces, and the dialog warns
  when assignment or device trust is not enforced yet instead of claiming the
  application is private. The published application appears in each assignee's
  *My Apps & Network* page with an Open button and in nobody else's.
  `POST /api/v1/access/network-resources/publish`.
