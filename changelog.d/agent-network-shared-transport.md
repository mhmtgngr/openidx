### Added
- **Agent egress proxy and private CA on every path (Faz B8.9).** One shared
  `http.Transport` now serves the control plane, the updater and SSO. Proxy
  order: `proxy_url`, then `HTTPS_PROXY`/`NO_PROXY`, then on Windows the
  machine WinHTTP proxy (`WinHttpSettings`). `server_ca_pem` (alias of
  `server_ca`) is appended to the system roots. PAC is not evaluated. See
  `docs/runbooks/agent-network.md`.
