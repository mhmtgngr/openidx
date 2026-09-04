# contractcheck

Detects frontend/backend API **response-shape mismatches** in the admin console:
the class of silent bug where the backend returns one JSON shape and the
frontend reads a different key off it, so the UI shows `NaN`, an empty list, or a
blank page while every request returns HTTP 200.

Real examples this caught in one run:

- `/api/v1/mfa/enrollment-stats` returned `any_mfa`, UI read `mfa_enabled_count` -> `NaN%`
- `/api/v1/mfa/policies` returned `{data:[]}`, UI read `{policies,total}` -> created policy invisible
- `/api/v1/identity/passwordless/settings` returned a bare object, UI read `{settings}` -> looked unsaved
- `/api/v1/analytics/{usage,api-usage,feature-adoption,risk}` returned flat/array, UI read a wrapper -> blank analytics pages
- `/api/v1/audit/reports/{exports,scheduled}` returned bare arrays, UI read `{exports}`/`{reports}` -> empty lists
- `/api/v1/identity/notifications/unread-count` returned `unread_count`, UI read `count` -> badge stuck at 0

## How it works

1. **Static extract**: scans `web/admin-console/src` for calls of the form
   `api.get<{ key1: ...; key2: ... }>('/api/v1/...')` and records, per GET
   endpoint with a plain string path, the top-level keys the frontend expects.
   This is the frontend contract with no guessing about "what the UI reads".

2. **Live probe** (`-probe`): calls each such GET endpoint against a running
   deployment with a bearer token and diffs the declared keys against the actual
   top-level JSON keys. A declared key absent from the response is a real bug.

Only GET endpoints with a static string path and an inline object-literal generic
are checked; everything else (named-type generic, template-string path, array
generic) is counted under "skipped" so coverage is honest.

## Usage

```sh
# List every extracted frontend GET contract (no network):
go run ./tools/contractcheck

# Diff those contracts against a live deployment behind its edge router
# (exit 1 on any mismatch):
#   token file default: /tmp/admintoken.txt   base default: https://openidx.tdv.org
go run ./tools/contractcheck -probe -token-file /tmp/admintoken.txt

# Diff them against services started directly, with no edge router in front
# (this is what CI does):
go run ./tools/contractcheck -probe -local -token-file /tmp/smoke-admin-token

# JSON output:
go run ./tools/contractcheck -probe -json
```

### `-local`: why a single base URL is not enough

The console talks to one origin; nginx sends `/api/v1/` to APISIX, and APISIX
forwards each prefix to a different service — with `/api/*` as a catch-all to
admin-api, which is how `/api/v1/ispm/...`, `/api/v1/privacy/...` and the rest
resolve without a rule of their own.

CI has no edge router: the eight services are started on their own ports. Probing
one of them as `-base` answers **404 for every path that service does not own** —
54 of 76 endpoints, reported as "unverified", which reads like coverage and is
really a wall of misses. `-local` routes each path to the service the edge would
forward it to, using the same prefix map (`edge.go`, pinned against
`deployments/apisix-edge/seed-edge-routes.sh` by `edge_test.go`).

## In CI

The `smoke` job in `.github/workflows/ci.yml` starts the stack, runs
`scripts/smoke-test.sh` (which mints an admin token to `SMOKE_TOKEN_OUT`), then
runs this tool with `-probe -local`. Exit code is the gate: a missing-key
mismatch fails the build.

## Limitations

- Only verifies **read-shape** contracts (GET response top-level keys). It does
  not check request bodies, nested field names, or POST/PUT/PATCH round-trips.
- Endpoints needing path params or specific state show up as "unverified"
  (non-200), not as mismatches.
- Field-level type drift inside a present key is not detected; add a generated
  type layer (OpenAPI from the Go structs) to kill that class permanently.
- Shapes are compared against **the probed deployment's configuration**. A
  handler that answers a short shape when a feature is off (as
  `/api/v1/access/ziti/status` does with no Ziti configured) will report keys as
  missing even though the enabled shape carries them — declare those keys
  optional in the frontend, which is what the wire actually promises.
