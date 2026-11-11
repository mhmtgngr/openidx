# Split-site hosting: an edge router in Azure

This guide puts an OpenZiti edge router in an Azure VNet so that applications
running in Azure are published "dark": no public endpoint, reachable only
through the overlay, with traffic leaving the fabric inside Azure rather than
hair-pinning through the on-premises box.

The control plane (OpenIDX, the Ziti controller, the on-premises router) stays
on premises. Azure gets one router per VNet that hosts applications.

## How sites work

A **site** is a place applications live and routers run. The on-premises box
is the `default` site. You create another, for example `azure`, and enroll a
router into it. Every edge router carries the role attribute `site-<slug>`
beside `ziti-routers`; a network resource or a Ziti-enabled proxy route in the
`azure` site is bound (Ziti Bind) only by routers with `site-azure`. If the
site has no router, the service does not converge and reports
`no router in site "azure"` rather than being hosted from the wrong place.
Resources without a site stay in the default site, exactly as before sites.

## Network requirements

The Azure router needs **outbound** reach to:

| Destination | Port | Why |
|-------------|------|-----|
| `ctrl.<your domain>` (the controller) | 1280/tcp | Enrollment and the control channel |
| The on-premises router's link listener | 3022/tcp | The fabric link between sites |

Pick one of:

- **Site-to-site VPN or ExpressRoute** already in place: use the private
  addresses, nothing is exposed to the internet.
- **Public endpoints with an allowlist**: publish 1280 and 3022 on premises and
  allow only the Azure router's egress IP (a NAT gateway or a static public IP
  on the VM).

The Azure router itself listens on 3022/tcp for devices and other routers. Its
**advertised address** is the name or IP they reach it at.

## DNS records

Create these in corporate DNS (and in public DNS when clients come from the
internet):

| Record | Points at |
|--------|-----------|
| `ctrl.<domain>` | The Ziti controller (on premises) |
| `openidx.<domain>` | The OpenIDX console and APIs |
| `browzer.<domain>` | The BrowZer bootstrapper |
| `*.apps.<domain>` | The access proxy (`ACCESS_APPS_DOMAIN`) |

Set `ZITI_CTRL_PUBLIC_ADDRESS=ctrl.<domain>:1280` on the access service so
enrollment tokens and the router onboarding command name a reachable
controller.

## Fix the on-premises router's controller endpoint

The bundled router config (`deployments/docker/ziti-router/config.yml`) points
at `tls:ziti-controller.localtest.me:1280`, which only resolves inside the box.
A router in another site cannot use that name, and the controller advertises
the same name. Change `ctrl.endpoint` to `tls:ctrl.<domain>:1280` in the copy
inside the `ziti_router_data` volume (the volume copy wins after first start)
and restart the router.

## Enroll the Azure router

1. In the console open **Ziti Network > Overview > Add router**.
2. Choose **New site...**, slug `azure`, name `Azure West Europe` (or pick an
   existing site).
3. Name the router and enter its advertised address, for example
   `router.azure.<domain>` or the VM's private IP when every client comes over
   the VPN.
4. Click **Create router** and copy the command. The enrollment token is
   single-use and is shown only once.
5. On a Linux VM in the Azure VNet with Docker installed, run the command. It
   looks like:

   ```bash
   docker run -d --name azure-router-1 --restart=unless-stopped \
     -p 3022:3022 -v azure-router-1-data:/ziti-router \
     -e ZITI_ENROLL_TOKEN='<jwt>' \
     -e ZITI_CTRL_ADVERTISED_ADDRESS=ctrl.<domain> -e ZITI_CTRL_ADVERTISED_PORT=1280 \
     -e ZITI_ROUTER_ADVERTISED_ADDRESS=router.azure.<domain> -e ZITI_ROUTER_PORT=3022 \
     -e ZITI_ROUTER_MODE=host \
     openziti/ziti-router:1.6.12
   ```

   The image tag comes from `ZITI_ROUTER_IMAGE_TAG` and should match the
   controller's version.
6. The dialog shows the enrollment state; it turns **Online** when the router
   has enrolled and connected.

The same is available through the API:
`POST /api/v1/access/sites` with `{"slug":"azure","name":"Azure West Europe"}`,
then `POST /api/v1/access/ziti/fabric/routers/enroll-token` with
`{"name":"azure-router-1","site_slug":"azure","advertised_address":"router.azure.<domain>"}`.
Both are install-administrator operations and need a fresh second factor.

## Publish an Azure application dark

1. Register the application with `kind=web` and its internal URL (the App
   Service's private endpoint or VNet address).
2. **Publish** it and choose the site **Azure** in the publish dialog. It is
   published at `https://<label>.<ACCESS_APPS_DOMAIN>`.
3. Enable Ziti on the route (`ziti_enabled`). The reconciler binds its service
   to `#site-azure`, so the Azure router dials the application from inside the
   VNet.
4. Turn on "reachable from the agent" so enrolled devices intercept it too.

For a non-web resource (RDP, SQL, file shares) create a **network resource**
and pick the site in its target; the CSV import takes a `site` column.

## Keep the application dark

Set an **access restriction** on the Azure App Service (or an NSG rule on the
VM) that allows only the Azure router's address. Anything else, including the
public internet, is refused; users reach the application through the access
proxy or the agent, both of which go through the router.

Check it from outside: a direct request to the App Service should answer 403,
and the same application through `https://<label>.<ACCESS_APPS_DOMAIN>` or an
enrolled device should answer 200.

## Not yet automated

Provisioning the router VM is manual. A Terraform `edge-router` module (VM plus
cloud-init that runs the command above) is planned for
`deployments/terraform/azure`.
