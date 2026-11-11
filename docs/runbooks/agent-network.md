# Agent egress proxy, private server CA and log level

`agent.json` (or the MSI properties `PROXY_URL`, `SERVER_CA`, `LOG_LEVEL`):

| key | meaning |
|---|---|
| `proxy_url` | Explicit `http(s)://host:port` proxy. Wins over everything else. |
| `server_ca_pem` (alias `server_ca`) | PEM root(s) **appended** to the system roots. Public endpoints stay trusted. |
| `log_level` | `debug`, `info`, `warn`, `error`. |

## Proxy resolution

All plain-HTTPS traffic (control plane, updater, SSO) uses one shared
`http.Transport`. Order:

1. `proxy_url`
2. `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` environment (Linux: put them in
   `/etc/openidx-agent/agent.env`)
3. Windows only: the machine WinHTTP proxy (`netsh winhttp set proxy ...`,
   registry `WinHttpSettings`), including its bypass list.

PAC / WPAD scripts are **not** evaluated. On a PAC-only network set `proxy_url`.
