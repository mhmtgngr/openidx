# OpenIDX box operations scripts

## Secret file permissions (`harden-secret-perms.sh`)

The service env files carry plaintext secrets (DB / Guacamole / Ziti passwords,
JWT secret, encryption key, internal service token). They must be **owner-only**
— everything runs as the same `systemd --user` user, so `0600` files / `0700`
dirs break nothing.

```bash
./deployments/scripts/harden-secret-perms.sh          # idempotent; run at every deploy
```

Locks down `~/.config/oidx/common.env`, `~/oidx-runtime/run-access.sh`, the ziti
password, and the code-signing key material. (Historically `run-access.sh` was
`775` and `common.env` `664` — world-readable. Fixed.)

> ⚠️ **Rotation is a separate, deliberate step.** Any secret that was ever
> world-readable should be rotated — but rotating the **JWT secret** or
> **encryption key** invalidates live tokens / re-keys encrypted columns, and
> rotating DB/broker passwords needs a coordinated restart. Do these in a
> maintenance window, one at a time, not as a drive-by. `harden-secret-perms.sh`
> only fixes *exposure going forward*.



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
