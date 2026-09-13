# Runbook: OpenIDX under a DDoS attack

Companion to the design's §5.7 (`docs/architecture/2026-09-13-global-scale-cell-architecture-and-ddos.md`)
and the game-day drill (`scripts/ddos-drill.sh`, `test/load/ddos/`). This is
the full version of the six-step summary in the design.

**The one thing to hold on to:** the VERIFY path — validating an
already-issued token — is stateless, answered at the edge and APISIX, and must
not move under any attack. Everything below protects the ISSUE, ADMIN and EVENT
planes without touching VERIFY. If a step would risk VERIFY, it is the wrong
step.

## 0. Know it is an attack, not a launch

| Signal | Where |
|---|---|
| `edge_requests_total` ≥ 5× baseline | edge provider dashboard |
| `openidx_admission_rejected_total{plane="issue"}` > 0 | Prometheus (once task 3.5 lands) |
| `openidx_rate_limit_local_fallback_seconds` > 0 | rate-limit Redis is down — handle that first (task 0.7) |
| A single tenant host / ASN / country dominates the edge logs | edge analytics |
| `bot_gate` audit rows spike | audit search, action `bot_gate` |

A real launch looks like a broad, well-distributed rise with normal success
rates. An attack concentrates: one source set, one path, or one tenant, with
success rates falling. If success rates are fine and only volume is up, do not
mitigate — scale (§4).

## 1. Declare and record

Open an incident. From this point every change is written down with a
timestamp: what, where, why, and the exact revert. The audit trail and the edge
change log are the record; a mitigation nobody can reverse cleanly is a second
outage waiting.

## 2. Turn the edge to "under attack"

At the edge provider (the module under `deployments/terraform/modules/edge-*`):

- **Cloudflare:** set the zone to "I'm Under Attack", or flip
  `challenge_login_paths = true` and `terraform apply` the edge root to put a
  managed challenge on the credential-submitting paths.
- **AWS:** raise the WAFv2 rate-based rule sensitivity; if Shield Advanced is
  on, engage the SRT.
- **Azure:** switch the Front Door WAF policy custom rules from the game-day
  thresholds to attack thresholds.

Raise the static cache TTLs so discovery, JWKS and the SPA are served entirely
from the edge and never reach the origin.

## 3. Find the source and cut it narrowly

Identify the dominant tenant, ASN or country from edge analytics. Prefer the
narrowest cut that stops the attack:

- **One tenant is the source or the target:** lower that tenant's APISIX
  `limit-count` budget. The tenant sees its own 429s; its neighbours are
  untouched — this is the whole point of per-tenant budgets.
- **One ASN or country:** an edge rule scoped to it, never a global one.
- **A credential spray:** confirm `BOT_GATE=enforce` (task 1.4); it should
  already be challenging the targeted accounts. If it is in `observe`, promote
  it now — the observe rows tell you the false-positive cost before you do.

Never cut by the origin's own address ranges or by a rule that also catches
VERIFY traffic.

## 4. Give the ISSUE plane room, take it from ADMIN

- Scale ADMIN (`admin-api`, `governance`, `provisioning`) down toward
  `minReplicas` and let ISSUE (`oauth`, identity auth) scale up. The admin
  console going slow is an accepted cost; login is not.
- Check the Postgres connection budget (the pgcat gauge once task 2.2 lands).
  If the ISSUE admission queue-wait p95 is climbing, raise the ISSUE HPA max.
- Do not touch VERIFY replicas; they are not the bottleneck and must stay warm.

## 5. If a whole cell is the target

Cells are the blast-radius boundary (design §4.2). If one cell is under an
attack you cannot shed, its tenants are the only ones affected. Do not move
tenants mid-attack. Confirm neighbour cells' SLOs are flat (the proof the cell
model exists to give) and ride it out with the steps above scoped to that cell.

## 6. Stand down, in reverse

When `edge_requests_total` and admission rejections return to baseline, revert
the changes in the reverse order they were made — ADMIN scale, then source
cuts, then the edge attack mode — one at a time, watching the signals after
each. Record the timeline (`cell_id`, every rule change, durations) to the
incident and to `docs/evidence/`. If `BOT_GATE` was promoted to enforce for the
incident, decide deliberately whether it stays: the incident's observe→enforce
data is the input.

## Rehearse it

`scripts/ddos-drill.sh --url https://<staging-cell>` runs the six attack
scenarios against a staging cell and writes a summary to `docs/evidence/`.
`scripts/ddos-drill.sh --check` (and `make ddos-drill`) validate the scenarios
without a cluster. A runbook nobody has rehearsed is a wish; run the live drill
each quarter (Phase 5).
