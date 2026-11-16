# Connectors

A **connector** is a small service installed on one server inside your
organization's network. It opens an *outbound* connection to the OpenIDX
controller in the cloud and holds it, so internal applications behind it can
be published to users — without opening a single inbound firewall port.
Nothing on your network listens to the Internet; the connector dials out,
and user traffic rides back over that already-established, mutually
authenticated TLS link.

*(TR)* Connector, kurum ağınızın içindeki bir sunucuya kurulan küçük bir
servistir. Buluttaki OpenIDX denetleyicisine **dışa doğru** bağlanır; iç
uygulamalarınız, güvenlik duvarında hiçbir gelen port açmadan
kullanıcılara yayınlanır.

## Requirements

- A **Linux server** inside the network that can reach the internal
  applications you want to publish.
- **Docker or Podman** installed on that server.
- **Outbound HTTPS/TLS** from the server to the controller address.

| Direction | Port | Protocol | Purpose |
|---|---|---|---|
| Outbound | **1280/tcp** | TLS | Control channel to the controller (`--ctrl`) — enrollment and management |
| Outbound | **3022/tcp** | TLS | Data channel — user traffic to the published applications |
| Inbound | — | — | **None.** In private mode the connector accepts no inbound connection |

If a forward proxy or egress firewall sits between the server and the
Internet, allow the controller's host name on those two outbound ports.

## Installing a connector

The console wizard does everything but run the command. Walk it through:

1. Console → **Connectors** → **Add connector**.
2. **Choose or create a site.** A site groups connectors that can reach the
   same network segment (for example `istanbul-dc`, `azure-prod`). Resources
   you later publish are *placed on a site*, and any connector of that site
   can serve them.
3. The wizard shows **one command**. Copy it and paste it into a shell on
   the Linux server.
4. Watch the wizard: within a minute the connector enrolls and the status
   turns **Online**. Done.

### Anatomy of the command

The command looks like this (shortened):

```bash
curl -fsSL https://<controller>/connector.sh | sudo bash -s -- \
  --token 'eyJhbGci…' \
  --ctrl ctrl.example.com:1280 \
  --name ankara-dc-1
```

| Flag | Meaning |
|---|---|
| `--token` | The enrollment token. It is **single-use and short-lived**: it enrolls exactly one connector, then it is dead. If it expires before you run the command, re-issue from the wizard |
| `--ctrl` | The controller's public address and control port the connector dials out to (`host:1280`) |
| `--name` | The connector's name, also the container's: it runs as `oidx-connector-<name>` |

The script pulls the container image, enrolls with the token, stores the
resulting identity in a named volume (so restarts don't re-enroll), and
starts the container with `--restart=unless-stopped`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| **Token expired or already used** | Tokens are single-use and short-lived by design. Go back to Console → **Connectors** → the wizard and re-issue a fresh command. Nothing to clean up on the server if enrollment never completed |
| **Container starts, stays Offline** | Read the logs: `docker logs oidx-connector-<name>` (or `podman logs …`). Enrollment and dial errors are printed plainly |
| **"controller unreachable" in the logs** | An egress firewall or proxy is blocking the outbound ports. Verify from the server: `curl -vk https://<controller-host>:1280` should at least complete a TLS handshake. Check 3022/tcp the same way |
| **Clock skew** | Enrollment tokens are time-bounded; a server clock minutes off can make a fresh token look expired. Check `timedatectl` and NTP |

## Uninstalling

Run the same script with `--uninstall`:

```bash
curl -fsSL https://<controller>/connector.sh | sudo bash -s -- --uninstall --name ankara-dc-1
```

It stops and removes the container and deletes the identity volume —
**no credentials remain on the server**. Then delete the connector entry in
Console → **Connectors** so the controller forgets it too.

## Publish your first app

With the connector Online, publish something through it:

1. Console → **App Publish** (or **Network → Add a resource** for raw
   TCP targets), create a resource or proxy route pointing at an internal
   address the connector's server can reach, for example
   `http://intranet.local:8080`.
2. **Place it on the new site.** That is what routes its traffic through
   your connector.
3. Assign the application to a user or group — assignment is the grant;
   see [Zero Trust Network](network-access.md) for how dial policies are
   derived.
4. Verify as that end user: open **My Apps & Network** and reach the app.
   For anything sensitive, run `tools/darkprobe` to prove an unauthorized
   identity *cannot* reach it.

From here, everything in the [ZTNA guide](network-access.md) — posture
checks, BrowZer clientless access, justification prompts — applies to
traffic flowing through your connector unchanged.
