### Added
- **The ZTN tunnel turns on per group of devices.** The network policy gains
  `tunnel_scope` (`all`, `tagged`, `off`) and `tunnel_tags` (migration 256).
  Each device receives its own `always_on` in `/agent/config` and the report
  answer: everyone, the devices carrying one of the chosen tags, or nobody;
  the policy version covers it, so retagging a device moves its version.
  Existing organizations keep their behaviour (`always_on` true becomes
  `all`, false becomes `off`); new ones default to `tagged`. The Network
  Resources page gets a "Tunnel turns on for" control with a tag picker.
