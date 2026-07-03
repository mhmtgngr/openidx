# Production hardening: OPA fail-closed guard + require vault KEK (W3.12 + W3.13)

> Final Workstream 3 items, shipped together (both are production-config concerns).

## W3.12 — OPA fail-open posture (verify + regression test; **no prod gap found**)

The survey flagged the OPA middleware's fail-open (`internal/common/middleware/opa.go`: when OPA is
unreachable, `if devMode { c.Next() }` allows the request). Investigation shows **this cannot happen
in production**: every service passes `devMode = cfg.IsDevelopment()` (admin-api, governance,
provisioning `main.go`), and `IsDevelopment()` is `Environment == "development"|"dev"` — false in
production. So in prod the middleware already fails **closed** (403 on unreachable OPA). `devMode` is
not a standalone config field, so there is nothing to assert in `ValidateProduction`.

To lock the invariant against a future refactor that might decouple `devMode` from `IsDevelopment()`
or flip the prod default, add a **regression test** `TestOPAAuthzFailClosedInProduction`
(`internal/common/middleware`): with an unreachable OPA client, `devMode=false` → **403**,
`devMode=true` → 200. (Also confirmed the separately-flagged `checkIPThreat` fail-open is a
deliberate, documented posture per the prior audit — no change.)

Observation (not in scope): OPA authz is opt-in (`ENABLE_OPA_AUTHZ`, default false); a prod deploy
that leaves it off has no OPA policy layer. That's an intentional opt-in (inline policy DSL is the
alternative), so not made a hard failure here.

## W3.13 — Require an explicit vault KEK in production (real `ValidateProduction` addition)

`vault.KeyringFromConfig` falls back to `ENCRYPTION_KEY` when neither `VAULT_KEK` nor `VAULT_KEKS`
is set (fail-closed only if that's also unusable). That silently couples the PAM vault's
key-encryption key to the general encryption key, defeating independent rotation/scoping of the most
sensitive secret store. Add a critical check to `Config.ValidateProduction`:

```go
if c.VaultKEK == "" && c.VaultKEKs == "" {
    criticalIssues = append(criticalIssues,
        "vault_kek or vault_keks must be set in production; do not rely on the ENCRYPTION_KEY fallback for the vault key-encryption key")
}
```

Config already has `VaultKEK`/`VaultKEKs` (`vault_kek`/`vault_keks`, envs `VAULT_KEK`/`VAULT_KEKS`),
fed into `KeyringFromConfig` by admin-api/governance/access. Test: a new `TestValidateProduction`
case "Fails without an explicit vault KEK"; the two existing pass-in-prod cases get a `VaultKEK` set.

## Testing
- `go test ./internal/common/config -run TestValidateProduction` (new vault-KEK case + updated pass
  cases) and `./internal/common/middleware -run TestOPAAuthzFailClosedInProduction` green.
- `go build ./...`, `go vet`, `gofmt`, `orgscope -fail ./internal` clean.

## Out of scope
Making `ENABLE_OPA_AUTHZ` mandatory in prod; the `checkIPThreat` posture (verified intentional).
This closes Workstream 3 and the readiness-finalization plan.

## Critical files
- `internal/common/config/config.go` (`ValidateProduction` vault-KEK check) + `config_test.go`.
- `internal/common/middleware/opa_failclosed_test.go` (new regression test). `opa.go` unchanged.
