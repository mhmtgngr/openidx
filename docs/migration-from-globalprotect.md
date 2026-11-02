# Moving from GlobalProtect to OpenIDX network resources

This guide takes an organization from a Palo Alto GlobalProtect VPN to
OpenIDX network resources reached through the OpenZiti tunneler on each
device. It covers the inventory, the CSV import, a pilot, the cutover and the
rollback. Both can run side by side for as long as the pilot needs, so nothing
here is a flag day.

## What changes

| GlobalProtect | OpenIDX |
|---|---|
| A gateway, and a tunnel to the whole corporate network once connected | No inbound port; each device dials only the services it is assigned, over the overlay |
| Split-tunnel include routes / access routes | A network resource's **network target**: hosts, CIDRs, DNS names, ports, protocols |
| Security policy rules on the firewall (source user/group → destination → service) | The resource's **assignments** (users, groups) and **conditions** (trusted device, risk) |
| HIP profiles | Posture checks on the agent; a resource that requires a trusted device is reachable only from a compliant device |
| Always-on / on-demand connect method | The organization's **network policy** (always on, split tunnel) |

A network resource is an application of kind `network`. The access service's
Ziti reconciler turns each one into a service named `openidx-net-<id>`:

- an `intercept.v1` config, so the device's tunneler captures the addresses,
  ports and protocols of the target;
- a `host.v1` config, so the router hosting the service forwards to the
  address that was dialed (restricted to the same addresses, ports and
  protocols) or to a fixed forward address and port;
- a Bind policy for the routers (`#ziti-routers`) and a Dial policy for the
  assignees' enrolled devices.

The router that hosts the service has to reach the target. Put an edge router
in each network the resources live in (Ziti Network → Fabric shows the
routers and mints an enrolment token for a new one).

## 1. Inventory the GlobalProtect rules

Export three things from Panorama or the firewall:

1. **Access routes** of each GlobalProtect gateway configuration (Network →
   GlobalProtect → Gateways → Agent → Client Settings → Split Tunnel). These
   are the networks clients route through the tunnel today.
2. **Security policy rules** whose source zone is the GlobalProtect tunnel
   zone: source user or group, destination address (objects and groups
   resolved to CIDRs or FQDNs), application/service (resolved to ports and
   protocols).
3. **HIP profiles** referenced by those rules.

Then group the rules into resources by what people think of as one thing: "file
servers", "lab network", "ERP database". One resource per rule is too fine;
one resource for the whole access route is the VPN again. A good resource has
one owner who can say who should reach it.

Write down, for each resource, the user groups from the source column. These
groups should exist in OpenIDX (synced from the directory, or created there)
before the import, because the import assigns a resource to a group by name.

HIP profiles map to posture checks (Ziti Network → Security → Posture). A
rule that required a HIP match becomes a resource that requires a trusted
device. The import does not set conditions; set them on the resource after.

## 2. Write the CSV

The import reads a CSV with a header row. Columns may come in any order and
only `name` is required:

| Column | Meaning |
|---|---|
| `name` | The resource's name, as users and administrators will see it |
| `hosts` | IP addresses or host names, separated by `;` |
| `cidrs` | Networks, separated by `;` (e.g. `10.0.0.0/16`) |
| `dns_names` | Domains, separated by `;`; a leading `*.` matches every name under it |
| `ports` | Ports and ranges, separated by `;` (e.g. `445;8000-8100`); empty means every port |
| `protocols` | `tcp`, `udp` or both separated by `;`; empty means both |
| `forward_address`, `forward_port` | A fixed target the router forwards to instead of the dialed address (a jump host, a load balancer) |
| `group` | An OpenIDX group to assign the resource to |

Lines starting with `#` are comments. An example:

```csv
name,hosts,cidrs,dns_names,ports,protocols,group
# From rule "GP-FileShares"
File servers,fs1.corp.example;fs2.corp.example,,,445,tcp,Finance
# From rule "GP-Lab"
Lab network,,172.16.0.0/16,,22;3389;8000-8100,,Engineering
# From access route "corp-intranet"
Intranet,,,*.intranet.corp.example,80;443,tcp,All Staff
```

A target may not point at the platform: the routers that host the service
are the platform's own hosts. Loopback, link-local (including
`169.254.169.254`), unspecified and multicast addresses, `localhost`, this
host's addresses and name, the controller's host, CIDRs broader than
`NETWORK_TARGET_MIN_PREFIX` (default `/16`, IPv6 `/48`) and anything
overlapping `NETWORK_TARGET_DENY_CIDRS` (comma-separated; by default the
docker bridge, while the podman, CNI and docker networks actually present
are found from the host's interfaces) are refused, as are `100.64.0.0/10`, the
other reserved ranges, IPv6 addresses that embed a refused IPv4 one, names
under wildcard-DNS services such as nip.io (`NETWORK_TARGET_DENY_DOMAINS`
adds more) and ports in `NETWORK_TARGET_DENY_PORTS`. Write IPv4 addresses
as dotted quads: other numeric spellings (`127.1`, `0177.0.0.1`) are refused. DNS names are
judged by their spelling only, so keep the router hosts' egress rules as the
backstop for a name that resolves somewhere it should not. Split a larger
corporate network into /16s, or a platform administrator raises the limit.

Each row is validated on its own: an address that does not parse, a CIDR that
covers every address (`0.0.0.0/0`), or a port outside 1-65535 is reported on
its row and does not stop the others. At most 500 rows per file.

## 3. Import

Validate first; nothing is written with `dry_run=true`:

```sh
curl -sS -X POST "https://<host>/api/v1/access/network-resources/import?dry_run=true" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: text/csv" \
  --data-binary @gp-resources.csv | jq '.failed, (.rows[] | select(.error) )'
```

Fix the rows it reports, then import for real (the same request without
`dry_run`). The answer lists each row with the new resource's id; a group
that was not found is a warning on its row and leaves the resource unassigned.

Then, in the console (Ziti Network → Network Resources):

- check each resource's addresses and ports, and its overlay state, which
  should read **Synced** within a reconcile pass (30 seconds);
- open **Access** on a resource to add users or groups the CSV did not name;
- set conditions (trusted device, risk ceiling) on resources that had a HIP
  profile.

## 4. Pilot

Pick a pilot group of a few people from different teams, with GlobalProtect
still installed. Before the first device, make sure the controller and the
edge router advertise names the devices resolve from corporate DNS
(`docs/runbooks/go-live-windows.md`, wave 0, step 0); a router that
advertises a `*.localtest.me` name is reachable from nowhere but its own host.

1. Install the OpenIDX agent on their devices and enrol them. The agent runs
   the OpenZiti tunneler; the Agent Fleet page's **Tunnel** column shows each
   device's tunnel state once the agent reports it.
2. Assign the pilot group to the resources. Under
   `ACCESS_ASSIGNMENT_ENFORCE=observe` every enrolled device may dial every
   network resource, with the per-resource marker beside it; under
   `enforce` only assignees' devices may. Check `GET
   /api/v1/access/assignment-report` before enforcing: it lists who would lose
   reach.
3. Keep the network policy on demand and split tunnel during the pilot, so
   GlobalProtect keeps carrying everything the resources do not cover.
4. Ask the pilot users to disconnect GlobalProtect and work for a few days.
   What they could not reach is a resource missing from the CSV, a port
   missing from a resource, or a target the hosting router cannot reach.

Watch:

- `OpenIDXAgentTunnelDown`: a device reports in while its tunnel is down;
- `OpenIDXTunnelDialFailures`: dials failing across the fleet. A resource
  whose overlay state is **Error** says why on hover.

## 5. Cutover

Move groups across in waves, largest last:

1. Assign the wave's groups to their resources.
2. Turn on **Always on** in the network policy once every device in the
   organization runs the agent; leave **Split tunnel** on unless policy
   requires every packet to go through the overlay.
3. Remove the wave's users from the GlobalProtect gateway's allowed users
   (or the portal's agent configuration), so their client stops connecting.
4. After the last wave, turn on **Block direct corporate access** if the
   corporate networks should be reachable only through the overlay, and
   retire the gateway's access routes. The agent enforces the block on Linux
   devices where it runs as root; Windows and macOS devices report it as not
   enforced (`docs/AGENT-TUNNEL.md`, "The organization's network policy"), so
   block direct access for them at the network if it matters: on the Palo
   Alto, a security rule from the user zones to the corporate ranges that
   permits only the hosts of the OpenIDX edge routers (the overlay's exit),
   with the former GlobalProtect rules below it disabled. The Network policy
   card shows how many devices run the current policy.

Keep the GlobalProtect gateway and its configuration for at least one month
after the last wave.

## 6. Rollback

Nothing in OpenIDX blocks GlobalProtect, so rolling back is giving users the
VPN again:

1. Add the affected users back to the gateway's allowed users; their client
   reconnects with its old configuration.
2. Turn **Always on** off in the network policy so the tunneler does not
   compete for the same addresses. Where both intercept the same CIDR, the
   OpenZiti tunneler's routes win, so remove the network target of any
   resource that should go back to the VPN (Ziti Network → Network
   Resources → Remove target); the reconciler removes its overlay service and
   the devices stop intercepting it. The resource and its assignments stay,
   so moving forward again is putting the target back.
3. If one resource is wrong rather than the whole move, fix or remove only
   that resource's target.

## Reference

- API: `api/openapi/access-service.yaml`, tag *Network Resources*.
- How the overlay, identities and policies fit together:
  `docs/how-network-access-works.md`.
