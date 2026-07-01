# P1 — Fix DB sslmode validation drift (validate the effective sslmode)

## Context

`Config.ValidateProduction()` (`internal/common/config/config.go:824`) blocks
startup in production on critical misconfigs. For the database it checks the
standalone field `c.DatabaseSSLMode` (`:862`), and the production-warnings helper
(`:808`) does the same. But the actual connection is built from
`c.DatabaseURL` — `internal/common/database/database.go:44`
`pgxpool.ParseConfig(connString)` where `connString == c.DatabaseURL` — so the
`sslmode` embedded in `DATABASE_URL` is what governs the wire, **not** the
`DatabaseSSLMode` field.

These two can drift: an operator sets `DatabaseSSLMode=require` (gate passes)
while `DATABASE_URL=postgres://…?sslmode=disable` (plaintext wire). This is
exactly the docker-compose prod situation — `docker-compose.prod.yml` hardcodes
`sslmode=disable` in every service's `DATABASE_URL`. The prod validator is
satisfied while DB traffic is unencrypted.

## Approach

Validate the **effective** sslmode — the one that actually connects.

### `effectiveDatabaseSSLMode()` helper

Add to `internal/common/config/config.go`:

```go
// sslmodeRe extracts the sslmode from a DATABASE_URL (URL "?sslmode=" or DSN
// "sslmode=" form).
var sslmodeRe = regexp.MustCompile(`sslmode=([a-zA-Z-]+)`)

// effectiveDatabaseSSLMode returns the sslmode that will actually govern the DB
// connection. The value embedded in DatabaseURL wins, because the pool is built
// from that URL verbatim (pgxpool.ParseConfig); the standalone DatabaseSSLMode
// field is only a fallback for when the URL omits it. This prevents a passing
// production gate while DATABASE_URL carries sslmode=disable.
func (c *Config) effectiveDatabaseSSLMode() string {
	if m := sslmodeRe.FindStringSubmatch(c.DatabaseURL); len(m) == 2 {
		return m[1]
	}
	return c.DatabaseSSLMode
}
```

Requires adding the `regexp` import.

### Use it in the two checks

- `ValidateProduction()` `:862` — replace the `c.DatabaseSSLMode == "" ||
  c.DatabaseSSLMode == "disable"` condition with
  `mode := c.effectiveDatabaseSSLMode(); mode == "" || mode == "disable"`. Keep
  the existing critical message (it already reads "database_ssl_mode must be
  'require'…"); optionally clarify it also covers the URL's sslmode.
- Production-warnings helper `:808` — same substitution so the warning tracks the
  effective value too.

### Behavior

| DatabaseURL sslmode | DatabaseSSLMode field | effective | prod result |
|---|---|---|---|
| `disable` | `require` | `disable` | **critical** (was: passed — the drift) |
| `require` | `disable` | `require` | passes (URL authoritative) |
| (none) | `require` | `require` | passes (field fallback — unchanged) |
| (none) | `disable`/empty | `disable`/empty | critical (unchanged) |

All existing `TestValidateProduction` cases use an **empty `DatabaseURL`**, so
they fall through to the field and behave exactly as today.

## Out of scope (deliberate)

- The audit also noted `ziti_admin_password` weak-default isn't covered by the
  prod validator — a separate validator item, not this drift. Noted, not fixed
  here.
- Changing `docker-compose.prod.yml`'s `sslmode=disable` itself — that's a deploy
  decision (prod terminates TLS at the gateway / uses a private network); this
  change makes the validator *honest* about it (it will now correctly flag a prod
  bring-up whose DB wire is plaintext, which is the intended signal).

## Testing

Add to `TestValidateProduction` (`internal/common/config/config_test.go`), reusing
the otherwise-valid prod config shape:

- **URL `sslmode=disable` + field `require` → error** mentioning
  `database_ssl_mode` (the drift is now caught).
- **URL `sslmode=require` + field `disable` → no error** (URL authoritative; the
  connection is actually TLS).
- Optionally a unit test of `effectiveDatabaseSSLMode()` for URL-form, DSN-form,
  and empty-URL-fallback.

`go build ./...`, `go vet ./...`, `gofmt`, `go run ./tools/orgscope -fail
./internal`, and `go test ./internal/common/config/...` all green (existing cases
unaffected).

## Verification checklist

- [ ] `effectiveDatabaseSSLMode()` added (URL sslmode wins, field fallback);
  `regexp` imported.
- [ ] `ValidateProduction()` + warnings helper use the effective sslmode.
- [ ] New tests: URL-disable+field-require fails; URL-require+field-disable passes.
- [ ] build / vet / gofmt / orgscope / config tests green; existing cases still pass.
