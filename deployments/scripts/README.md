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

Defaults (override in `~/.config/oidx/backup.env`, which both units read if it
exists): container `oidx-pg`, db/user `openidx`, output `~/oidx-runtime/backups`,
retention 14 days.

The local dumps live on the same VM as the database. They cover container loss
and mistakes, not the loss of the VM. The off-box copy below covers that.

### Off-box encrypted copy

When `OIDX_BACKUP_OFFBOX_TARGET` is set, `pg-backup.sh` encrypts each new dump
with [age](https://age-encryption.org) and uploads it. It never uploads a dump
without encrypting it. Without a usable recipients file, or without `age`, the
off-box step fails. The local dump is kept either way.

| Variable | Meaning |
|---|---|
| `OIDX_BACKUP_OFFBOX_TARGET` | Where the copy goes. `remote:bucket/openidx` is an [rclone](https://rclone.org) remote. `ssh://user@host[:port]/path` uses rsync over ssh. `/path` or `file:///path` is a local or mounted directory. |
| `OIDX_BACKUP_AGE_RECIPIENTS` | File of age recipient public keys (`age1…`, or ssh public keys), one per line. Required with a target. |
| `OIDX_BACKUP_OFFBOX_RETENTION_DAYS` | Delete off-box copies older than this many days (default 30; `0` keeps them all). Only files named `openidx-*.dump.*` are deleted. |
| `OIDX_BACKUP_TEXTFILE_DIR` | node-exporter textfile collector directory. When set, the script writes `openidx_backup.prom` with `openidx_backup_last_success_timestamp_seconds{kind="local"}` and `{kind="offbox"}`. |
| `OIDX_BACKUP_AGE_IDENTITY` | The private key that decrypts the copy. Only the restore drill needs it, and it does not belong on the box (see below). |

Each run uploads four files: `openidx-<ts>.dump.age` (the ciphertext),
`openidx-<ts>.dump.sha256` (the plaintext dump's hash, checked after
decryption), `openidx-<ts>.dump.schema_version`, and last
`openidx-<ts>.dump.age.sha256`. The restore drill uses only copies that have
this last file, so it never picks up an upload that stopped partway.

The result of the last off-box attempt is in `$OIDX_BACKUP_DIR/last-offbox.json`
(`timestamp`, `result`, `target`, `object`, `bytes`, `error`). The script exits
2 when the local dump succeeded and the off-box copy failed, so the systemd unit
shows as failed.

**Set up (once):**

1. Make a key pair **off the box**, for example on an administrator's
   workstation. Keep the identity file somewhere the box cannot reach, such as a
   password manager or an offline copy. Anyone with the box and the key could
   read every backup.

    ```bash
    age-keygen -o openidx-backup.key          # private: keep OFF the box
    age-keygen -y openidx-backup.key          # prints the public key (age1...)
    ```

    You can list a second recipient, such as a break-glass key held by someone
    else. Any one of the recipients can decrypt.

2. On the box, install `age` and the transfer tool (`rclone`, or `rsync` +
   `ssh`), then write the public keys and settings:

    ```bash
    sudo apt-get install -y age rclone          # or rsync for ssh://
    install -Dm600 /dev/stdin ~/.config/oidx/backup-recipients.txt <<'EOF'
    age1...your-public-key...
    EOF
    install -Dm600 /dev/stdin ~/.config/oidx/backup.env <<'EOF'
    OIDX_BACKUP_OFFBOX_TARGET=offsite:openidx-backups/box1
    OIDX_BACKUP_AGE_RECIPIENTS=/home/cmit/.config/oidx/backup-recipients.txt
    OIDX_BACKUP_OFFBOX_RETENTION_DAYS=30
    OIDX_BACKUP_TEXTFILE_DIR=/home/cmit/oidx-runtime/textfile
    EOF
    rclone config                               # create the "offsite" remote
    ```

    For `ssh://`, use a key that can only write to the backup directory. If the
    storage supports it, use a bucket or account that cannot delete or
    overwrite objects (object lock, or append-only), so that whoever takes the
    box cannot also delete the backups. In that case, set
    `OIDX_BACKUP_OFFBOX_RETENTION_DAYS=0` and let the storage's own lifecycle
    rule expire old copies.

3. Run it once by hand and check the result:

    ```bash
    systemctl --user daemon-reload
    systemctl --user start oidx-pg-backup.service
    cat ~/oidx-runtime/backups/last-offbox.json
    ```

**Alerting.** The `OpenIDXBackupStale` rule in `deployments/monitoring/alerts.yml`
fires when either kind has not succeeded for 26 hours. It needs node-exporter
reading the textfile directory, which the `node` job in `prometheus.yml`
scrapes:

```bash
podman run -d --name oidx-node-exporter --network host --pid host \
  -v /home/cmit/oidx-runtime/textfile:/textfile:ro \
  docker.io/prom/node-exporter:latest \
  --web.listen-address=127.0.0.1:9100 --collector.textfile.directory=/textfile
```

**Restore drill (do it monthly, and after any change to the keys).** Run it
from a machine that holds the identity, which should not be the box. It fetches
the newest complete copy, checks the ciphertext's hash, decrypts it, checks
the plaintext's hash, and restores it into a throwaway Postgres container with
no network. That container is removed afterwards. The live database is never
touched.

```bash
OIDX_BACKUP_OFFBOX_TARGET=offsite:openidx-backups/box1 \
OIDX_BACKUP_AGE_IDENTITY=~/secure/openidx-backup.key \
  deployments/scripts/pg-restore-verify.sh --from-offbox
```

The throwaway container uses the image of `oidx-pg` when that container exists
on the machine, and `docker.io/library/postgres:16-alpine` otherwise. Set
`OIDX_RESTORE_IMAGE` to the image of the Postgres version the box runs.

**Restore for real from off-box (the VM is gone):** fetch and decrypt the copy
the same way, then restore it as in "Restore for real" above:

```bash
rclone copy --include 'openidx-<ts>.dump*' offsite:openidx-backups/box1 ./restore/
cd restore
sha256sum openidx-<ts>.dump.age | cut -d' ' -f1 | diff - openidx-<ts>.dump.age.sha256
age -d -i ~/secure/openidx-backup.key -o openidx-<ts>.dump openidx-<ts>.dump.age
sha256sum openidx-<ts>.dump | cut -d' ' -f1 | diff - openidx-<ts>.dump.sha256
```
