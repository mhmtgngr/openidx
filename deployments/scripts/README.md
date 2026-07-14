# OpenIDX box operations scripts

## Postgres backups (`pg-backup.sh` / `pg-restore-verify.sh`)

Automated, rotated backups of the OpenIDX database from the `oidx-pg` podman
container, written to a **host** directory so they survive container loss, plus
a weekly restore-verify (a backup you have never restored is not a backup).

**Install on the box (systemd user units):**

```bash
install -Dm755 deployments/scripts/pg-backup.sh          ~/oidx-runtime/scripts/pg-backup.sh
install -Dm755 deployments/scripts/pg-restore-verify.sh  ~/oidx-runtime/scripts/pg-restore-verify.sh
install -Dm644 deployments/systemd/oidx-pg-backup.service         ~/.config/systemd/user/oidx-pg-backup.service
install -Dm644 deployments/systemd/oidx-pg-backup.timer           ~/.config/systemd/user/oidx-pg-backup.timer
install -Dm644 deployments/systemd/oidx-pg-restore-verify.service ~/.config/systemd/user/oidx-pg-restore-verify.service
install -Dm644 deployments/systemd/oidx-pg-restore-verify.timer   ~/.config/systemd/user/oidx-pg-restore-verify.timer
systemctl --user daemon-reload
systemctl --user enable --now oidx-pg-backup.timer oidx-pg-restore-verify.timer
loginctl enable-linger "$USER"   # so timers fire while logged out
```

**Run on demand / check:**

```bash
systemctl --user start oidx-pg-backup.service          # backup now
systemctl --user start oidx-pg-restore-verify.service  # verify latest restores
systemctl --user list-timers 'oidx-pg-*'               # next scheduled runs
journalctl --user -u oidx-pg-backup.service -n 30      # last backup log
ls -lh ~/oidx-runtime/backups/                         # dumps + .sha256 + .schema_version
```

**Restore for real (disaster recovery):**

```bash
latest=$(ls -t ~/oidx-runtime/backups/openidx-*.dump | head -1)
# into a fresh DB, then cut over — do NOT drop the live DB until verified:
podman exec oidx-pg psql -U openidx -d postgres -c "CREATE DATABASE openidx_restored;"
podman exec -i oidx-pg pg_restore -U openidx -d openidx_restored --no-owner --no-privileges < "$latest"
```

Defaults (override via env in the service unit if needed): container `oidx-pg`,
db/user `openidx`, output `~/oidx-runtime/backups`, retention 14 days.

> ⚠️ These dumps live on the same VM as the database. For real durability, also
> ship them off-box (e.g. `rclone`/`az storage` to object storage) — a roadmap
> follow-up. This job covers container-loss and fat-finger recovery today.
