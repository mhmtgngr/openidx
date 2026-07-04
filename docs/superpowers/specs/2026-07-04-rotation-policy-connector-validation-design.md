# Make all rotation-connector types creatable via CreatePolicy

**Goal:** `validatePolicyInput` currently accepts only `directory` and `generate_only`, so
`ssh`, `postgres`, `ssh_key`, and `mysql` rotation policies can't be created through the API
(they need a direct DB insert). Make every **registered** connector creatable, with each
connector validating its own `connector_config`.

**Verified current state:**
- `internal/credentials/engine.go:161 validatePolicyInput` hardcodes a `switch in.ConnectorType`:
  `directory` (checks `directory_id`+`username`), `generate_only` (no reqs), `default` → error
  "connector_type must be one of {directory, generate_only}".
- `Service.rotators map[string]Rotator` is keyed by `Type()` (engine.go:32) — the source of truth
  for which connectors are registered.
- Connectors already have config parsers that validate required fields: `sshConfigFromMap`,
  `pgConfigFromMap`, `mysqlConfigFromMap`. `directory` validates inline (no parser);
  `generate_only` has no config.
- Sole API caller: `cmd/admin-api/main.go:304` registers all 6 (directory, generate_only, ssh,
  ssh_key, postgres, mysql). The one other `NewService` caller, `test/integration/rotation_test.go`,
  inserts policies via **raw SQL** (bypasses `validatePolicyInput`) → unaffected.
- No existing test exercises `validatePolicyInput`.

## Design — optional `ConfigValidator` interface (mirrors the `ValueGenerator` pattern)

Add to `rotator.go`:
```go
// ConfigValidator lets a connector validate a policy's connector_config at CreatePolicy time.
// Optional: a connector without it (e.g. generate_only) imposes no config requirements.
type ConfigValidator interface {
	ValidateConfig(cfg map[string]any) error
}
```

Each config-bearing connector implements it by delegating to its existing parser (no field-list
duplication):
- `sshRotator`, `sshKeyRotator`: `ValidateConfig(cfg) { _, err := sshConfigFromMap(cfg); return err }`
- `postgresRotator`: `_, err := pgConfigFromMap(cfg); return err`
- `mysqlRotator`: `_, err := mysqlConfigFromMap(cfg); return err`
- `directoryRotator`: `ValidateConfig` checks `directory_id`+`username` (move the logic out of
  `validatePolicyInput`; matches its existing `Apply` check)
- `generateOnlyRotator`: **does not implement** it (no config requirements)

Rewrite `validatePolicyInput` to delegate:
```go
func (s *Service) validatePolicyInput(in PolicyInput) error {
	rot, ok := s.rotators[in.ConnectorType]
	if !ok {
		return fmt.Errorf("%w: unknown connector_type %q (no registered connector)", ErrInvalidPolicy, in.ConnectorType)
	}
	if cv, ok := rot.(ConfigValidator); ok {
		if err := cv.ValidateConfig(in.ConnectorConfig); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
		}
	}
	if in.IntervalSeconds < 0 {
		return fmt.Errorf("%w: interval_seconds must be >= 0", ErrInvalidPolicy)
	}
	return nil
}
```

**Behavior change:** the accepted set is now "any registered connector type" instead of a
hardcoded pair; config validation is delegated to the connector. This makes future connectors
API-creatable automatically (once registered) with no engine change. Unregistered types are
rejected with a clearer error.

## Testing
New `internal/credentials/policy_validation_test.go` — construct a `Service` via `NewService(nil,
nil, rotators, nil, 24, logger)` (validatePolicyInput touches neither db nor vault) registering the
real ssh/ssh_key/postgres/mysql rotators (`NewSSHKeyRotator(nil)` etc. — `ValidateConfig` only calls
the parser) + a `generate_only` + a directory stub. Cases:
- each connector type with a valid `connector_config` → nil.
- each with a missing required field → `ErrInvalidPolicy` (mentions the missing field).
- `generate_only` with empty config → nil.
- unknown type `"nope"` → `ErrInvalidPolicy` "unknown connector_type".
- `interval_seconds = -1` → `ErrInvalidPolicy`.

## Scope / risk
- Single small PR, `internal/credentials` only (+ no `cmd` change — admin-api already registers all).
- Not in the DB/migration path; no box-behavior change beyond the API now accepting these types.
- Out of scope: exposing these connector types in the admin-console UI (separate frontend follow-up);
  cloud-IAM connector.

## Open question (resolve at impl)
- Whether to keep a defensive nil-guard if `in.ConnectorConfig` is nil before delegating (the parsers
  handle a nil map via `cfg[key]` returning zero values, so likely fine — confirm).
