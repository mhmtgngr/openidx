# §5.2 — operational controls

Monthly, and after any incident. **Every one of these is operator-run**: they
verify a *running install*, and no amount of CI can substitute — a test proves
the code can do the thing, this proves your deployment does.

Fill in a dated row when you run one. Empty means not done.

Set `$OPENIDX` to your deployment's base URL and `$TOKEN` to an admin token
before running anything below.

## Identity and session

### Default admin rotated; ≥2 admins; MFA on all of them

```sh
# The seeded admin must no longer authenticate with the default password.
curl -sS -o /dev/null -w '%{http_code}\n' -X POST "$OPENIDX/oauth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Admin@123"}'      # expect 401
```

Then Console → **Users**, filter by role `admin`: at least two, each with a
TOTP factor **and** a hardware or backup factor.

| Date | Who | Default rejected | Admin count | All MFA-enrolled |
|---|---|---|---|---|
| | | | | |

### Revoke and kill-switch actually sever

Revoke a test session in Console → **Sessions**, then try to refresh with that
session's refresh token — it must fail. Then run the kill switch on a test
user and confirm IAM, PAM and Ziti all report severed (the handler reports
partial failures rather than claiming success; read what it says).

| Date | Who | Refresh died | Kill switch: IAM / PAM / Ziti | Output |
|---|---|---|---|---|
| | | | | |

### Offered MFA factors are deliverable

A typo'd provider used to fall back to a mock silently — that class is closed
in code (`SMS_PROVIDER=mock` is now *not configured*, and production refuses
to start with it), but "configured" still is not "delivering". Send yourself
a real SMS OTP and a real email OTP, and approve one real push.

| Date | Who | SMS arrived | Email arrived | Push approved |
|---|---|---|---|---|
| | | | | |

### JWT signing key age ≤ 90 days

```sh
curl -sS "$OPENIDX/.well-known/jwks.json" | jq '.keys[] | {kid, alg}'
```

Nothing in the code reminds you. Compare each `kid` against when you rotated
it; rotate anything older than 90 days.

| Date | Who | Oldest key age | Rotated? |
|---|---|---|---|
| | | | |

## The access model (the §1 spine)

### Three users, four surfaces, one answer

Pick three users. For each, compare **My Apps & Network** ↔ **Access 360** ↔
the **assignment report** ↔ what they can actually dial or launch. All four
must agree. This is the control that catches the project's defining defect
class before a user does.

| Date | Who | Users checked | All four agreed | Divergence found |
|---|---|---|---|---|
| | | | | |

### A review revoke propagates

Revoke a test grant in a certification campaign, then within the sweep
interval confirm it is gone from the portal, refused by the proxy, and absent
from the overlay.

| Date | Who | Portal | Proxy | Overlay | Elapsed |
|---|---|---|---|---|---|
| | | | | | |

## Platform

See [SECURITY-HARDENING.md](../SECURITY-HARDENING.md) for the full
config-gate list — it is the enforced source of truth; this is the periodic
read of it.

### Health, scrape, and a human on the end of the page

Each service serves `/ready` on its own port — there is no path prefix.
Against the compose stack:

```sh
for p in 8001 8002 8003 8004 8005 8006 8007 8008; do
  printf '%s ' "$p"
  curl -sS -o /dev/null -w '%{http_code}\n' "http://localhost:$p/ready"
done
# 8001 identity · 8002 governance · 8003 provisioning · 8004 audit
# 8005 admin-api · 8006 oauth · 8007 access · 8008 gateway
```

All eight ready, Prometheus scraping all eight, and at least one alert route
that reaches a person who is awake.

| Date | Who | 8/8 ready | 8/8 scraped | Alert reached a human |
|---|---|---|---|---|
| | | | | |

### The audit pipeline is a pipeline

Perform a test admin action; confirm it appears in `unified_audit_events`
**and** in the SIEM forwarder, and that hash-chain verification passes.

| Date | Who | In DB | In SIEM | Chain verified |
|---|---|---|---|---|
| | | | | |

### Backups ran, and one was restored

The CronJob/timer ran in the last 24 h **and** the most recent restore-verify
passed. A backup nobody has restored is a hypothesis.

| Date | Who | Last backup | Last restore-verify | Passed |
|---|---|---|---|---|
| | | | | |

### No `latest` tags; digests pinned

```sh
kubectl get pods -n openidx -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' \
  | sort -u
```

Nothing ending in `:latest`; every image pinned by digest.

| Date | Who | `latest` found | Digests pinned |
|---|---|---|---|
| | | | |

### Observability endpoints are not open with default credentials

Grafana, Prometheus, Jaeger, Alertmanager: reachable only from where they
should be, and never with a shipped default credential.

| Date | Who | Result |
|---|---|---|
| | | |
