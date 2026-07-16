# OpenIDX Architecture Review — Design Patterns & Structural Health

> An infrastructure-architect pass over the codebase, focused on design patterns,
> coupling, and structural maintainability (not availability — that's covered in
> `always-available-auth-plan.md`). Evidence is cited by file + measurement.

**Overall:** the *system* architecture is sound (clean service boundaries, shared
DB with RLS, good middleware layering, real resilience primitives). The weakness
is **within** the services: a handful of god-objects that fuse HTTP handling,
business logic, and raw SQL into one struct, plus duplicated bootstrap and an
inconsistent error contract. None of this is on fire; all of it raises the cost
of every future change. Ranked by ROI below.

---

## 1. God-object services fusing 3 layers 🔴 (highest-value refactor)

The domain `Service` structs have grown to fuse HTTP handlers + business logic +
data access in a single type:

| File | Lines | Methods on `*Service` | Raw SQL strings | `gin.Context` handlers |
|------|------:|----------------------:|----------------:|----------------------:|
| `internal/identity/service.go` | **6,299** | **165** | 55 | 73 |
| `internal/oauth/service.go` | 3,982 | 71 | 8 | many |
| `internal/admin/service.go` | 3,439 | 86 | — | — |
| `internal/access/service.go` | 2,936 | 48 | — | — |
| `internal/governance/service.go` | 3,032 | — | 47 (DB calls) | — |

`identity.Service` with **165 methods** and **145 direct `db.Pool` calls** is a
textbook god-object. It violates SRP three ways at once: the same struct parses
HTTP, enforces domain rules, and writes SQL. Consequences:

- **Untestable business logic** — you can't unit-test "is this MFA enrollment
  valid" without a live Postgres and a gin context.
- **Merge contention** — every feature touches the same 6k-line file.
- **No seam for the read-replica** you just built — `Reader()` can't be adopted
  cleanly because queries are scattered inline across 145 call sites.

**Pattern to apply — split into three collaborators (Repository + Service + Handler):**

```
identity/
  handler.go      // gin: parse/validate request, call service, format response
  service.go      // domain logic, no gin, no SQL — depends on a Repository interface
  repository.go   // interface: UserRepository { GetByID, Create, ... }
  postgres_repo.go// the pgx implementation (the only place SQL lives)
```

This is the **Repository pattern + hexagonal ports**. Benefits that compound:
- business logic becomes unit-testable with a fake repo (no DB),
- SQL lives in one file per aggregate (the read-replica `Reader()` gets adopted
  *inside* the repo, invisibly to callers),
- handlers shrink to translation, so the error contract (§3) is enforced in one place.

**Don't big-bang it.** Strangler-fig: extract one aggregate at a time (start with
`User`), leave the old methods delegating to the new repo until empty. *Effort: L,
incremental.*

> ✅ **Reference implementation landed.** `internal/identity/user_repository.go`
> defines `UserRepository` (interface) + `PostgresUserRepository` (pgx impl) with
> `GetByID`/`GetByUsername`/`Exists`. `identity.Service.GetUser` now **delegates**
> to it (behavior-preserving), the repo reads via `db.Reader()` (adopting the
> Tier 1.6 read replica), and returns the `ErrUserNotFound` sentinel. The payoff
> is proven in `user_repository_test.go`: service logic is now unit-tested with a
> **fake repo and no database** (previously impossible). This is the template —
> extend it method-by-method and roll the same shape to the other services.

---

## 2. Duplicated service bootstrap 🟡 (easy, high-consistency win)

All 8 `cmd/*-service/main.go` repeat the same ~40-line dance: `config.Load` →
`NewPostgres(TLS)` → `NewRedisFromConfig` → `gin.New` + recovery + otel →
`NewHealthService` + register PG/replica/Redis checks → `http.Server` → graceful
shutdown. It's copy-pasted 8×, and the drift is already visible (the readiness
checker registration had to be edited in 7 files by hand this week).

**Pattern — a `service.Bootstrap` / functional-options builder** in
`internal/common/server`:

```go
app := server.New("identity-service",
    server.WithPostgres(),          // reads cfg, adds PG + replica health checks
    server.WithRedis(),
    server.WithTracing(),
    server.WithRouter(setupRoutes), // service supplies only its routes
)
app.Run()                            // health, metrics, TLS, graceful shutdown for free
```

Each `main.go` drops from ~250–500 lines to ~30, and cross-cutting changes
(add a health check, change shutdown order, add a probe) happen **once**. There's
already `internal/server/graceful.go` and the health package — this consolidates
them into one entrypoint. *Effort: M. Very high consistency ROI.*

---

## 3. Inconsistent error contract + info disclosure 🟡🔴 (security + UX)

`grep` finds **250+ sites** returning `gin.H{"error": err.Error()}` straight to
the client — worst offenders `identity/handlers_advanced_mfa.go` (59),
`access/ziti_fabric_handlers.go` (38), `identity/service.go` (30). Two problems:

- **Information disclosure** (a real security issue): raw `err.Error()` leaks SQL
  fragments, internal hostnames, driver messages, file paths to callers.
- **No consistent contract**: some paths return `{"error": "..."}`, OAuth paths
  return RFC-6749 `{"error": "invalid_grant", ...}`, others return `{"message"}`.
  Clients can't program against it.

**Pattern — a typed error + one central renderer** (extends the Tier 2
`writeServerOrUnavailable` idea you already have in `oauth/unavailable.go`):

```go
// internal/common/apierror
type APIError struct { Status int; Code string; Public string; Err error }
func Render(c *gin.Context, err error)   // logs Err (with detail), returns Public only
```

Handlers `return apierror.NotFound("user")` / `apierror.Internal(err)`; the
renderer logs the *real* error server-side and emits a **safe, structured** body.
Kills the disclosure class and gives every service one error shape. *Effort: M
(mechanical, do alongside §1 handler extraction).*

> ✅ **Renderer hardened (foundation for adoption).** The `AppError` +
> `HandleError` machinery already existed in `internal/common/errors` but was
> used at only ~53 sites vs **402** raw `err.Error()` leaks, and — worse — it
> **never logged** the wrapped internal error, so coerced 500s vanished silently.
> `HandleError` now documents/guarantees the client only sees safe fields, and a
> new `HandleErrorWithLogger(c, err, logger)` logs the real cause server-side for
> 5xx (with request id + path) while keeping it out of the response. Tests in
> `render_test.go` prove both: a DB error with a password/hostname is logged but
> **not** leaked to the body. Remaining work is the mechanical migration of the
> 402 call sites onto this renderer (do it as handlers are extracted per §1).

---

## 4. `context.Background()` on request paths 🟡 (correctness/observability)

~50 `context.Background()` uses in non-test code, incl. **11 in
`oauth/service.go`** and **7 in `common/database`** on what look like
request-scoped paths. Where this replaces the request context it **breaks
cancellation, timeouts, and trace propagation** — a slow client or a cancelled
request keeps a DB query running, and the span is orphaned. (Legit uses exist:
background workers, graceful-shutdown detach — those should be obvious and
commented.)

**Action:** audit each; on a request path, thread `c.Request.Context()` (with a
bounded `WithTimeout`) instead of `Background()`. The Tier 2 DB timeouts only
help if the request context actually reaches the driver. *Effort: S–M, mechanical.*

---

## 5. `config.Config` god-struct 🟢/🟡 (lower priority)

`internal/common/config/config.go` is 1,095 lines with **194** env/mapstructure
bindings — one flat struct every service loads wholesale. It works and is
centralized (a virtue), but a service gets 194 fields it mostly ignores, and
there's no compile-time signal for "which service needs which config."

**Optional pattern — embedded sub-configs** (`DBConfig`, `RedisConfig`,
`OAuthConfig`, `TenantConfig`) composed into the top struct, so services depend on
the slices they use. Low urgency; do it only if config churn becomes painful.

---

## 6. What's already good (keep / lean into) 🟢

- **Middleware layering** — `internal/common/middleware` is clean, composable,
  and now the shared verify path. Good use of the decorator pattern.
- **Resilience primitives** — `internal/common/resilience` circuit breaker with
  distributed state + registry is genuinely good; underused (§ availability plan
  extends it).
- **Health checker registry** — interface-based, criticality-aware, extensible.
  The right pattern; just register it from a shared bootstrap (§2).
- **RLS-at-checkout** — `database/rls.go` `PrepareConn` hook is an elegant,
  centralized tenant boundary. Exactly where cross-cutting policy belongs.
- **Migrations** — versioned, up/down, gated. Solid.
- **Test presence** — 271 test files for 389 source files is a healthy ratio; the
  gap is *unit*-testability of the god-objects (§1), not test discipline.

---

## 7. Prioritized roadmap

| # | Item | Pattern | Effort | Payoff |
|---|------|---------|--------|--------|
| 1 | Extract Repository + Handler from god-object services (strangler, start `identity.User`) | Repository / Hexagonal | L (incremental) | Testable logic, SQL in one place, read-replica adoption, less merge pain |
| 2 | Shared `server.Bootstrap` builder for all `cmd/*-service` | Functional options / Template method | M | 8× less boilerplate, one place for cross-cutting infra |
| 3 | Central typed error renderer; kill `err.Error()` leakage | Typed errors + single renderer | M | Closes info-disclosure, one client contract |
| 4 | Audit `context.Background()` on request paths | Context propagation | S–M | Real cancellation/timeouts/tracing |
| 5 | (Optional) split `config.Config` into sub-configs | Composition | S | Clarity; low urgency |

**Sequencing:** 2 first (cheap, immediate consistency, unblocks nothing but pays
daily), then 1+3 together on one service as a **reference implementation**
(`identity` → repo/handler/service with the typed error renderer), then roll the
pattern service-by-service. 4 can be done opportunistically as files are touched.

The theme: the *macro* architecture is right (services, shared DB, RLS, middleware,
resilience). The debt is *micro* — inside the services, three layers are fused.
Separating them (Repository + Handler + typed errors) is the single highest-value
maintainability investment, and it's the same seam that makes the read-replica and
error-contract work land cleanly.
