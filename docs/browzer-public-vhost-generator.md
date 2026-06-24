# BrowZer public vhost generator

The access-service renders the **public per-app nginx vhosts** for every
BrowZer-enabled route, so publishing/un-publishing a clientless app needs no
hand-edit of the front nginx config.

## What it generates

For each `ziti_enabled AND browzer_enabled AND enabled` route, one TLS server
block is written to `BROWZER_VHOST_CONFIG_PATH`:

```nginx
server {
    listen 443 ssl;
    server_name <app>.tdv.org;
    ssl_certificate     <BROWZER_VHOST_SSL_CERT>;
    ssl_certificate_key <BROWZER_VHOST_SSL_KEY>;

    # hop-mode routes only: external-IdP form_post OIDC callbacks
    # (login.microsoftonline.com POSTs cross-site → BrowZer's SW can't
    # intercept → bootstrapper 403s non-GET). Route them to the hop (the
    # real app), bypassing the bootstrapper.
    location ~ /(signin-oidc|signout-callback-oidc)$ {
        proxy_pass http://127.0.0.1:<hop-port>;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
    }

    location / {                              # clientless overlay
        proxy_pass <BROWZER_BOOTSTRAPPER_ADDR>;  # bootstrapper demuxes by Host
        proxy_ssl_verify off; proxy_ssl_server_name on; proxy_ssl_name $host;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400s;
    }
}
```

The block is regenerated at boot and on every feature toggle
(`RegenerateConfigs`, alongside the bootstrapper targets, router, and hop
configs).

## Config

| Env | Default | Meaning |
|-----|---------|---------|
| `BROWZER_VHOST_CONFIG_PATH` | _(unset → disabled)_ | Where the server blocks are written |
| `BROWZER_BOOTSTRAPPER_ADDR` | `https://127.0.0.1:8445` | Upstream the `location /` forwards to |
| `BROWZER_VHOST_SSL_CERT` | `/etc/nginx/tdv-fullchain.pem` | Cert path **as seen by the front nginx** |
| `BROWZER_VHOST_SSL_KEY` | `/etc/nginx/tdv-key.pem` | Key path **as seen by the front nginx** |
| `BROWZER_OIDC_CALLBACK_PATHS` | `signin-oidc,signout-callback-oidc` | form_post callback suffixes routed to the hop (hop-mode only) |

Only **hop-mode** routes get the OIDC callback bypass — they own a host-side
upstream (the hop). Direct-mode external-IdP apps would need their own host-side
proxy; not yet generated.

## Front nginx wiring (one-time, operator)

The front nginx (`oidx-nginx`) consumes the generated file via a **wildcard
include** and reloads on change.

1. End the `http {}` block of the hand-maintained `nginx.conf` with:
   ```nginx
   include /shared-config/browzer-vhosts.conf;
   ```
   (wildcard-safe: nginx still starts if the file isn't generated yet). Remove
   any hand-written per-app BrowZer server blocks — the generator owns them now.
2. Mount the shared config dir and use the poll-reload entrypoint
   (`deployments/docker/oidx-nginx-entrypoint.sh`, mirrors the hop):
   ```sh
   podman run -d --name oidx-nginx --network host \
     -v /tmp/oidx-tls/tdv-fullchain.pem:/etc/nginx/tdv-fullchain.pem:ro \
     -v /tmp/oidx-tls/tdv-key.pem:/etc/nginx/tdv-key.pem:ro \
     -v /home/cmit/openidx/web/admin-console/dist:/usr/share/nginx/html:ro \
     -v /tmp/oidx-tls/nginx.conf:/etc/nginx/nginx.conf:ro \
     -v /tmp/oidx-ziti/browzer-config:/shared-config:ro \
     -v /home/cmit/openidx/deployments/docker/oidx-nginx-entrypoint.sh:/oidx-nginx-entrypoint.sh:ro \
     --entrypoint /bin/sh docker.io/library/nginx:alpine /oidx-nginx-entrypoint.sh
   ```

> **nginx.conf bind-mount caveat:** editing the bind-mounted `nginx.conf` (atomic
> rename) changes the inode, so the running container keeps the old file — a base
> config edit needs `podman restart oidx-nginx`. The *generated* vhosts live in a
> **directory** mount, so the entrypoint sees fresh writes and reloads on its own.
