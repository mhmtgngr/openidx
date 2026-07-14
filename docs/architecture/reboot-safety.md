# OpenIDX box — reboot safety & boot order

Roadmap item #2 from the system-design review. On the single-VM box (rootless
podman + `systemd --user`, `linger=yes`), a reboot must bring the whole stack
back with **no manual steps**. This documents what starts, in what order, and
how to verify.

## Coverage (every OpenIDX-critical unit is `enabled`)

| Layer | Unit(s) | Notes |
|-------|---------|-------|
| **Datastores** | `container-oidx-pg.service`, `container-oidx-redis.service` | ⚠️ These were the gap — `oidx-pg`/`oidx-redis` had `restart=none` and **no unit**, so a cold boot would have lost Postgres/Redis. Now covered. |
| **APISIX etcd** | `container-apisix-docker2_etcd_1.service` | APISIX's config store. Rootless `unless-stopped` isn't enough (user `podman-restart.service` is disabled), so it gets its own unit. |
| **Edge** | `container-oidx-apisix.service`, `container-oidx-nginx.service` | :443 edge + SPA host. |
| **Overlay** | `container-oidx-ziti-controller.service`, `container-oidx-ziti-router.service`, `container-oidx-browzer.service`, `container-oidx-browzer-hop.service` | OpenZiti + BrowZer data plane. |
| **PAM broker** | `oidx-pam-broker.service` (oneshot) | `podman start pam-guac-db pam-guacd pam-guacamole`. |
| **App services** | `oidx-{identity,oauth,governance,provisioning,audit,admin-api,access,gateway}.service` | `Restart=always`, `RestartSec=5s`. |
| **Backups** | `oidx-pg-backup.timer`, `oidx-pg-restore-verify.timer` | Daily / weekly, `Persistent=true`. |

The container units reuse the **existing** containers (`ExecStart=podman start
<name>`, generated with `podman generate systemd --name` — no `--new`), so a
reboot restarts the same containers with their exact config. Copies of the three
gap-fillers live in `deployments/systemd/generated/` for reference.

## Boot order (dependency-correct)

systemd starts `default.target.wants` roughly in parallel; correctness comes from
each layer tolerating a not-yet-ready dependency:

```
1. etcd  ──►  2. APISIX            (config store before the edge)
   oidx-pg, oidx-redis  ──►  app services + pam-broker
   ziti-controller  ──►  ziti-router  ──►  browzer / browzer-hop
```

The app services `Restart=always` (5s), so if they start before `oidx-pg` is
accepting connections they simply retry until it is — a cold boot may log a
couple of failed starts per service, then converge. No manual intervention.

## Install / re-create the gap-filler units

```bash
for c in oidx-pg oidx-redis apisix-docker2_etcd_1; do
  podman generate systemd --name --files --restart-policy=always "$c"
done
mv container-*.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable container-oidx-pg.service container-oidx-redis.service container-apisix-docker2_etcd_1.service
loginctl enable-linger "$USER"
```

> Enable, don't `start`, when the containers are already running — the notify
> handshake can otherwise kill the live container. The units take over on the
> next boot.

## Verify

```bash
# Every critical container has an enabled unit:
for c in oidx-pg oidx-redis apisix-docker2_etcd_1 oidx-apisix oidx-nginx \
         oidx-ziti-controller oidx-ziti-router oidx-browzer oidx-browzer-hop; do
  printf '%s: %s\n' "$c" "$(systemctl --user is-enabled container-$c.service)"
done
systemctl --user is-enabled oidx-pam-broker.service \
  oidx-{identity,oauth,governance,provisioning,audit,admin-api,access,gateway}.service
loginctl show-user "$USER" -p Linger      # must be Linger=yes

# The real test is an actual reboot in a maintenance window; after it:
systemctl --user --failed
curl -s -o /dev/null -w '%{http_code}\n' https://openidx.tdv.org/health   # expect 200
```

## Still out of scope / notes
- **A true reboot** is the only complete proof — schedule one in a window. Everything above is static verification that the units are enabled and dependency-tolerant.
- Non-OpenIDX containers on the shared box (n8n, ollama, qdrant, the separate `server_*`/`tdv-*` stacks) are their owners' responsibility; several rely on `restart=unless-stopped` without a user unit and would need the user `podman-restart.service` enabled to boot — left as-is to avoid touching non-OpenIDX infra.
