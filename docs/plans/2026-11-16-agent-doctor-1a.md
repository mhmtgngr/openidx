# Agent Doctor (slice 1a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `openidx-agent doctor` diagnoses, offline and without any LLM, why this device cannot connect, prints the cause in English or Turkish, emits a versioned diagnostic bundle, and applies two safe local repairs on `--fix`.

**Architecture:** A new package `agent/internal/doctor` holds the bundle schema, a set of pure check functions over an injectable `Probes` interface, an orchestrator that orders checks and skips the ones whose prerequisite failed, repairs behind an injectable `Actions` interface, and a renderer. The CLI command gathers `Inputs` (from `agent.LoadConfig`, falling back to `ipc.Query`) and calls the package. Nothing in this slice talks to the server beyond unauthenticated reachability probes.

**Tech Stack:** Go (agent module `github.com/openidx/openidx/agent`, its own go.mod), cobra, stdlib `net`, `net/http`, `crypto/x509`. No new dependencies.

**Spec:** `docs/plans/2026-11-16-agentic-architecture-design.md` (row 1a of "Dalga 1").

## Deviations from the spec (decided while reading the code)

- **No `pkg/diagbundle`.** The agent module has no `replace` to the root module, so a root package is not importable. The schema lives in `agent/internal/doctor/bundle.go`; slice 1c mirrors it server-side with a wire-parity test (pattern: `agent/internal/checks/wire_test.go`).
- **Sealed-token re-enrol and tunneler restart via the supervisor move to slice 1b.** Both are methods on the running `*agent.Agent`; a separate CLI process has no write channel to the service (the tray pipe is read-only). 1a repairs are the two a standalone process can do: flush DNS, restart the agent service.
- **No captive-portal probe to a third-party host.** The doctor only contacts the configured server. A captive portal or TLS inspection shows up as `TLS_UNTRUSTED`; slice 1c maps it to a cause.
- **Tunnel state on Linux is `skipped` in 1a** (`ipc.Query` is Windows-only). Slice 1b runs the doctor inside the service, which supplies `a.TunnelStatus()` on every OS. `Inputs.Tunnel` is already the seam for that.

## Global Constraints

- All work in worktree `/home/cmit/openidx/.claude/worktrees/agent-doctor`, branch `feat/agent-doctor`. The worktree guard refuses compound Bash (`;`, `&&`, pipes): one plain command per call.
- Commits: `git -c user.name=cmit -c user.email=mehmetgungor@gmail.com commit -s -m "..."`, ending with `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`.
- Run agent tests from `agent/`: `go test ./internal/doctor/ ./cmd/openidx-agent/`. Also `go vet ./...` and `gofmt -l .` must be clean, and `GOOS=windows go build ./...` and `GOOS=darwin go build ./...` must pass.
- The bundle must never contain: `auth_token`, enrollment tokens, proxy credentials, key material, log bodies. Hostnames and IPs are allowed in the bundle (it goes to the device's own server) but not in anything named "support code" (slice 1b).
- User-facing text exists in both `en` and `tr`; a census test enforces it.
- Unit tests use fakes only: no real network, no real service control, no sleeping.
- Tests in this module must not use internal topology addresses; use `198.51.100.0/24`, `192.168.1.x`, `10.0.0.x`, and `*.example.test` hostnames (CI guard `check-no-internal-topology`).
- Add `changelog.d/agent-doctor.md` (never edit `CHANGELOG.md`).
- Do not merge or push to `main`; the owner merges explicitly.

## Review Focus

1. **Device not enrolled / config missing** → `doctor` still runs, reports `NOT_ENROLLED`, skips server checks, exits 1, does not panic on nil config. (Task 5 test)
2. **Non-admin user cannot read `agent.json`** (it holds the auth token) → falls back to `ipc.Query` on Windows; elsewhere reports `CONFIG_UNREADABLE` with the "run as administrator/root" action. (Task 8 test)
3. **Proxy URL with credentials** (`http://user:pass@proxy:8080`) → bundle `net.proxy_host` carries host:port only; the password appears nowhere in JSON or text output. (Task 2 test)
4. **Network that hangs instead of refusing** → every probe has its own timeout (5 s) and the whole run a 25 s deadline; a hung probe yields `fail` with its timeout code, later checks still run. (Task 5 test)
5. **Server URL is an IP literal or carries a port** → DNS check is `skipped` (not `fail`), TCP/TLS use the given port, default 443. (Task 2 test)

---

## File Structure

| File | Responsibility |
|---|---|
| `agent/internal/doctor/bundle.go` | Schema v1 types, status and code constants |
| `agent/internal/doctor/probes.go` | `Probes` interface + real implementation over `transport` |
| `agent/internal/doctor/checks_net.go` | dns, tcp, tls, http, clock checks |
| `agent/internal/doctor/checks_enroll.go` | config, credential, identity checks |
| `agent/internal/doctor/checks_tunnel.go` | service and tunnel checks |
| `agent/internal/doctor/doctor.go` | `Inputs`, `Run`: ordering, skip rules, deadline |
| `agent/internal/doctor/repairs.go` | `Actions` interface, `PlanRepairs`, `ApplyRepairs` |
| `agent/internal/doctor/actions_{windows,linux,other}.go` | real `Actions` per OS |
| `agent/internal/doctor/render.go`, `strings.go`, `lang_{windows,other}.go` | text output en/tr |
| `agent/cmd/openidx-agent/doctor.go` | cobra command, input gathering, export, exit code |

---

### Task 1: Bundle schema v1

**Files:**
- Create: `agent/internal/doctor/bundle.go`
- Test: `agent/internal/doctor/bundle_test.go`, `agent/internal/doctor/testdata/bundle_v1.golden.json`

**Interfaces — Produces:**

```go
const SchemaVersion = 1

type CheckStatus string // "pass" | "fail" | "warn" | "skipped"
const (StatusPass CheckStatus = "pass"; StatusFail = "fail"; StatusWarn = "warn"; StatusSkipped = "skipped")

type Check struct {
    ID     string      `json:"id"`               // see check IDs below
    Status CheckStatus `json:"status"`
    Code   string      `json:"code,omitempty"`   // empty on pass
    Detail string      `json:"detail,omitempty"` // ≤200 chars, machine-ish, never a secret
    Millis int64       `json:"ms"`
}
type Repair struct {
    ID      string `json:"id"`      // "flush_dns" | "restart_service"
    Outcome string `json:"outcome"` // "applied" | "failed" | "needs_elevation" | "planned"
    Detail  string `json:"detail,omitempty"`
}
type Enrollment struct {
    Enrolled      bool       `json:"enrolled"`
    AuthInvalid   bool       `json:"auth_invalid"`
    Revoked       bool       `json:"revoked"`
    CertNotAfter  *time.Time `json:"cert_not_after,omitempty"`
}
type Net struct {
    ProxyMode string `json:"proxy_mode"`           // "none" | "configured" | "environment" | "system"
    ProxyHost string `json:"proxy_host,omitempty"` // host:port only
    DNSOK     bool   `json:"dns_ok"`
}
type Bundle struct {
    Schema       int            `json:"schema"`
    AgentID      string         `json:"agent_id,omitempty"`
    AgentVersion string         `json:"agent_version"`
    OS           string         `json:"os"`   // runtime.GOOS
    CollectedAt  time.Time      `json:"collected_at"` // UTC
    ClockSkewS   *int64         `json:"clock_skew_s,omitempty"`
    Checks       []Check        `json:"checks"`
    Repairs      []Repair       `json:"repairs"`
    Tunnel       *tunnel.Status `json:"tunnel,omitempty"`
    Enrollment   Enrollment     `json:"enrollment"`
    Net          Net            `json:"net"`
}
func (b Bundle) Failing() []Check // status fail, in order
func (b Bundle) Healthy() bool    // no check with status fail
```

Check IDs (fixed order): `config`, `credentials`, `dns`, `tcp`, `tls`, `http`, `clock`, `identity`, `service`, `tunnel`.

Codes: `CONFIG_UNREADABLE`, `NOT_ENROLLED`, `AUTH_INVALID`, `DEVICE_REVOKED`, `DNS_FAIL`, `DNS_TIMEOUT`, `TCP_BLOCKED`, `TCP_TIMEOUT`, `TLS_UNTRUSTED`, `TLS_FAIL`, `PROXY_AUTH_REQUIRED`, `SERVER_HTTP_ERROR`, `HTTP_TIMEOUT`, `CLOCK_SKEW`, `IDENTITY_MISSING`, `IDENTITY_EXPIRED`, `IDENTITY_EXPIRING`, `SERVICE_NOT_RUNNING`, `TUNNEL_DOWN`, `TUNNEL_NOT_INSTALLED`, `TUNNEL_OFF`. Export them as `Code*` string constants and as `var AllCodes []string`.

- [ ] **Step 1: Write failing tests** — `TestBundleGoldenJSON` (a fully populated `Bundle` with fixed times marshals byte-identical to the golden file; `-update` flag rewrites it), `TestBundleEmptySlicesMarshalAsArrays` (`Checks`/`Repairs` nil → `[]`, not `null`; implement via `MarshalJSON` or by normalising in a constructor `NewBundle(agentID, version string, now time.Time) Bundle`), `TestFailingAndHealthy`.
- [ ] **Step 2: Run** `go test ./internal/doctor/ -run Bundle` → FAIL (package missing).
- [ ] **Step 3: Implement `bundle.go`.**
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(agent): diagnostic bundle schema v1`.

### Task 2: Network checks

**Files:**
- Create: `agent/internal/doctor/probes.go`, `agent/internal/doctor/checks_net.go`
- Test: `agent/internal/doctor/checks_net_test.go`, `agent/internal/doctor/fake_test.go`

**Interfaces — Produces:**

```go
type HTTPResult struct { Status int; Date time.Time; ViaProxy bool }

type Probes interface {
    Resolve(ctx context.Context, host string) ([]string, error)
    DialTCP(ctx context.Context, hostport string) error
    TLSHandshake(ctx context.Context, hostport, serverName string) error // error wraps x509 errors unchanged
    HTTPGet(ctx context.Context, url string) (HTTPResult, error)         // through transport.SharedTransport()
    Now() time.Time
}
func NewProbes() Probes                       // real; each call bounded by ProbeTimeout
const ProbeTimeout = 5 * time.Second
const MaxClockSkew = 5 * time.Minute

type target struct { Host, Port, HostPort string; IsIP bool }
func parseServer(serverURL string) (target, error) // default port 443 (80 for http)

func checkDNS(ctx, p Probes, t target) Check
func checkTCP(ctx, p Probes, t target) Check
func checkTLS(ctx, p Probes, t target) Check
func checkHTTP(ctx, p Probes, serverURL string) (Check, *HTTPResult)
func checkClock(p Probes, r *HTTPResult) (Check, *int64)
func proxyInfo(configuredProxyURL string) (mode, host string) // strips userinfo
```

Rules the tests pin:
- `checkDNS`: IP literal → `skipped`; `context.DeadlineExceeded` → `DNS_TIMEOUT`; other error or zero addresses → `DNS_FAIL`.
- `checkTCP`: timeout → `TCP_TIMEOUT`; else error → `TCP_BLOCKED`. When a proxy is in use (`proxyInfo` mode ≠ `none`) the TCP and TLS checks are `skipped` with detail `via proxy` (a direct dial says nothing), and `http` is the authority.
- `checkTLS`: `x509.UnknownAuthorityError`, `x509.HostnameError`, `x509.CertificateInvalidError` (via `errors.As`) → `TLS_UNTRUSTED`; anything else → `TLS_FAIL`. The real `TLSHandshake` uses the root pool and `ServerName` that `transport.SharedTransport().TLSClientConfig` carries, so a configured `server_ca` is honoured.
- `checkHTTP`: probes `GET <server>/api/v1/access/agent/config` with no credentials. Any status < 500 except 407 → `pass` (401 is the expected answer); 407 → `PROXY_AUTH_REQUIRED`; ≥ 500 → `SERVER_HTTP_ERROR` with the status in `Detail`; timeout → `HTTP_TIMEOUT`.
- `checkClock`: nil result or zero `Date` → `skipped`; `|Now − Date| > MaxClockSkew` → `fail CLOCK_SKEW`, skew seconds returned either way (positive = device ahead).
- `proxyInfo("http://user:pass@proxy.example.test:8080")` → `("configured", "proxy.example.test:8080")`; empty config with `HTTPS_PROXY` set → `environment`; otherwise `none`. (`system` is reported only on Windows when `transport` resolves a WinHTTP proxy; if no exported helper exists, add `transport.ProxyMode() string` next to `systemProxy` in `internal/transport/network.go` rather than duplicating its logic.)

- [ ] **Step 1: Write `fake_test.go`** — `fakeProbes` with per-method func fields and a fixed `now`; then the failing table tests `TestCheckDNS`, `TestCheckTCP`, `TestCheckTLS`, `TestCheckHTTP`, `TestCheckClock`, `TestParseServer` (cases: `https://idx.example.test`, `https://idx.example.test:8443`, `https://198.51.100.7`, `http://idx.example.test`, garbage → error), `TestProxyInfoStripsCredentials`.
- [ ] **Step 2: Run** `go test ./internal/doctor/ -run 'Check|Parse|Proxy'` → FAIL.
- [ ] **Step 3: Implement** `probes.go` and `checks_net.go`.
- [ ] **Step 4: Run** → PASS; `GOOS=windows go build ./...` → ok.
- [ ] **Step 5: Commit** `feat(agent): doctor network checks`.

### Task 3: Enrollment and identity checks

**Files:**
- Create: `agent/internal/doctor/checks_enroll.go`
- Test: `agent/internal/doctor/checks_enroll_test.go`

**Interfaces — Produces:**

```go
type Inputs struct {
    AgentID, AgentVersion string
    ServerURL             string
    ProxyURL              string         // from AgentConfig.ProxyURL
    ConfigErr             error          // non-nil: config could not be read
    Enrolled              bool
    AuthInvalid, Revoked  bool           // from ipc.Status when available
    IdentityFile          string         // AgentConfig.ZitiIdentityFile; "" = none expected
    TunnelExpected        bool           // AgentConfig.Tunnel != nil && .Enabled
    Tunnel                *tunnel.Status // nil = unknown
    ServiceRunning        *bool          // nil = unknown
}
const IdentityExpiryWarn = 14 * 24 * time.Hour

func checkConfig(in Inputs) Check
func checkCredentials(in Inputs) Check
func checkIdentity(in Inputs, readFile func(string) ([]byte, error), now time.Time) (Check, *time.Time)
```

Rules:
- `checkConfig`: `ConfigErr` satisfying `os.IsPermission` → `CONFIG_UNREADABLE`; `!Enrolled` (or `agent.IsNotEnrolled(ConfigErr)`) → `NOT_ENROLLED`; else pass.
- `checkCredentials`: `Revoked` → `DEVICE_REVOKED` (wins over `AuthInvalid`); `AuthInvalid` → `AUTH_INVALID`; not enrolled → `skipped`.
- `checkIdentity`: `IdentityFile == ""` → `skipped`; unreadable for permission → `skipped` with detail `needs elevation`; missing → `IDENTITY_MISSING`. Otherwise parse the OpenZiti identity JSON (`{"ztAPI":…,"id":{"cert":"pem:…"}}`; the `pem:` prefix is stripped, a `file:` reference is read through `readFile`), take the leaf certificate: `NotAfter < now` → `fail IDENTITY_EXPIRED`; within `IdentityExpiryWarn` → `warn IDENTITY_EXPIRING`; returns `NotAfter`. The key is never read or copied.

- [ ] **Step 1: Failing tests** — table tests for each rule; identity fixtures generated in-test with `x509.CreateCertificate` (expired, expiring in 3 days, valid 1 year). `TestIdentityCheckNeverReturnsKeyMaterial`: the returned `Check.Detail` does not contain `PRIVATE KEY` for a fixture whose JSON includes a key.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(agent): doctor enrollment and identity checks`.

### Task 4: Service and tunnel checks

**Files:**
- Create: `agent/internal/doctor/checks_tunnel.go`
- Test: `agent/internal/doctor/checks_tunnel_test.go`

**Interfaces — Consumes:** `Inputs` (Task 3), `tunnel.State*` constants. **Produces:**

```go
func checkService(in Inputs) Check
func checkTunnel(in Inputs) Check
```

Rules:
- `checkService`: `ServiceRunning == nil` → `skipped`; `false` → `SERVICE_NOT_RUNNING`.
- `checkTunnel`: `!TunnelExpected` → `warn TUNNEL_OFF` when `Tunnel` is nil or `StateOff` (not a failure: the org may not use the tunnel); `Tunnel == nil` → `skipped`; `StateNotInstalled` → `fail TUNNEL_NOT_INSTALLED`; `StateDegraded` → `fail TUNNEL_DOWN` with `Detail` = `Tunnel.LastError` clipped to 200 runes; `StateConnected` → pass with `Detail` = `"<n> services"`.

- [ ] **Step 1: Failing table tests** covering every state × `TunnelExpected`, plus `TestTunnelDetailIsClipped` (a 5 000-char `LastError` → `len([]rune(Detail)) == 200`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(agent): doctor service and tunnel checks`.

### Task 5: Orchestrator

**Files:**
- Create: `agent/internal/doctor/doctor.go`
- Test: `agent/internal/doctor/doctor_test.go`

**Interfaces — Consumes:** everything above. **Produces:**

```go
const RunDeadline = 25 * time.Second
type Options struct { ReadFile func(string) ([]byte, error) } // nil → os.ReadFile
func Run(ctx context.Context, in Inputs, p Probes, opt Options) Bundle
```

Behaviour:
- Emits exactly the ten checks in the fixed order from Task 1, always (a check that cannot run is `skipped`, never omitted).
- Skip chain: no `ServerURL` → `dns`,`tcp`,`tls`,`http`,`clock` skipped with detail `no server configured`. `dns` fail → `tcp`,`tls` skipped (`http` still runs: a proxy may resolve for us). `tcp` fail → `tls` skipped.
- `ctx` is wrapped with `RunDeadline`; each check gets a child context of `ProbeTimeout`. A panic inside a check is recovered and recorded as that check `fail` with code `INTERNAL` (add the constant to Task 1's list and `AllCodes`).
- Fills `Enrollment`, `Net` (`DNSOK` = dns check passed or skipped-for-IP), `ClockSkewS`, `Tunnel`, `OS`, `CollectedAt = p.Now().UTC()`.

- [ ] **Step 1: Failing tests** — `TestRunHealthy` (all pass, `Healthy()`), `TestRunNotEnrolledSkipsServerChecks` (Review Focus 1: zero-value `Inputs` → `config` fails `NOT_ENROLLED`, five server checks skipped, no panic), `TestRunDNSFailSkipsTCPAndTLSButRunsHTTP`, `TestRunHungProbeDoesNotBlockLaterChecks` (Review Focus 4: fake `DialTCP` blocks until its ctx is done → `tcp` is `TCP_TIMEOUT`, `http` and `tunnel` still evaluated; use a fake with a short injected timeout, no real sleep > 50 ms), `TestRunAlwaysTenChecksInOrder`, `TestRunRecoversCheckPanic`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** `go test ./internal/doctor/ -race` → PASS.
- [ ] **Step 5: Commit** `feat(agent): doctor orchestrator`.

### Task 6: Repairs

**Files:**
- Create: `agent/internal/doctor/repairs.go`, `actions_windows.go`, `actions_linux.go`, `actions_other.go`
- Test: `agent/internal/doctor/repairs_test.go`

**Interfaces — Produces:**

```go
var ErrNeedsElevation = errors.New("needs elevation")
var ErrUnsupported   = errors.New("not supported on this platform")

type Actions interface {
    FlushDNS(ctx context.Context) error
    RestartService(ctx context.Context) error
}
func NewActions() Actions
func PlanRepairs(b Bundle) []Repair                               // outcome "planned"
func ApplyRepairs(ctx context.Context, b *Bundle, a Actions)      // fills b.Repairs
```

Rules:
- Plan: `DNS_FAIL` or `DNS_TIMEOUT` → `flush_dns`; `SERVICE_NOT_RUNNING` or `TUNNEL_DOWN` → `restart_service`. Nothing else is repairable in 1a. Order: `flush_dns` first. No duplicates.
- Apply: error `ErrNeedsElevation` → `needs_elevation`; `ErrUnsupported` or any other error → `failed` with the error text (clipped 200); nil → `applied`. One failure does not stop the next repair.
- Real actions: Windows `ipconfig /flushdns` and restart of the service whose name the `winservice` package exports (read `agent/internal/winservice` for the constant; use `golang.org/x/sys/windows/svc/mgr`, map `ERROR_ACCESS_DENIED` to `ErrNeedsElevation`). Linux `resolvectl flush-caches` (missing binary → `ErrUnsupported`) and `systemctl restart openidx-agent` (non-zero euid → `ErrNeedsElevation` without executing). Other OS → `ErrUnsupported`. Commands run with absolute paths resolved via `exec.LookPath` and no shell.

- [ ] **Step 1: Failing tests** with a `fakeActions` — `TestPlanRepairs` (table: code set → repair IDs), `TestApplyRepairsOutcomes`, `TestApplyContinuesAfterFailure`, `TestPlanNothingForHealthyBundle`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; `GOOS=windows go build ./...`, `GOOS=darwin go build ./...` → ok.
- [ ] **Step 5: Commit** `feat(agent): doctor safe repairs`.

### Task 7: Rendering (en/tr)

**Files:**
- Create: `agent/internal/doctor/strings.go`, `render.go`, `lang_windows.go`, `lang_other.go`
- Test: `agent/internal/doctor/render_test.go`

**Interfaces — Produces:**

```go
type Lang string // "en" | "tr"
func DetectLang() Lang                            // windows: GetUserDefaultUILanguage primary id 0x1f → tr (same rule as tray/lang_windows.go); others: LC_ALL, then LANG, prefix "tr" → tr
func ParseLang(s string) (Lang, error)            // "en","tr"; "" → DetectLang()
type Message struct{ Title, Action string }
func MessageFor(code string, l Lang) Message
func Render(w io.Writer, b Bundle, l Lang)
```

`Render` output shape (one line per check, then causes):

```
OpenIDX bağlantı teşhisi — 2026-11-16 14:02 UTC
  ✓ Yapılandırma
  ✗ Tünel                 TUNNEL_DOWN
  – TLS                   (atlandı)

Sorun: Güvenli tünel çalışmıyor.
Ne yapmalı: `openidx-agent doctor --fix` komutunu yönetici olarak çalıştırın; düzelmezse BT'ye bu çıktıyı gönderin.
```

Healthy bundle ends with the single line `No problems found.` / `Sorun bulunmadı.`. Each failing check prints its `Sorun/Problem` + `Ne yapmalı/What to do` pair; warnings print under `Not/Note`. Repairs, when present, print `Onarım/Repair: <id> — <outcome>`. Write plain, non-technical sentences; each `Action` tells the user one concrete thing to do.

- [ ] **Step 1: Failing tests** — `TestEveryCodeHasBothLanguages` (for each of `AllCodes`, `MessageFor(code, en)` and `(code, tr)` have non-empty `Title` and `Action`, and tr ≠ en), `TestEveryCheckIDHasALabelInBothLanguages`, `TestRenderHealthy`, `TestRenderFailingTurkish` (golden string for a bundle with `TUNNEL_DOWN`), `TestDetectLangFromEnv` (`t.Setenv("LC_ALL","tr_TR.UTF-8")` → tr; unset → en; non-Windows build tag), `TestRenderNeverPrintsProxyCredentials`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(agent): doctor text output in English and Turkish`.

### Task 8: CLI command

**Files:**
- Create: `agent/cmd/openidx-agent/doctor.go`, `agent/cmd/openidx-agent/doctor_test.go`, `changelog.d/agent-doctor.md`
- Modify: `agent/cmd/openidx-agent/main.go` (add `rootCmd.AddCommand(doctorCmd)` beside the other registrations near line 727), `docs/AGENT-TUNNEL.md` (short "Troubleshooting: `openidx-agent doctor`" section)

**Interfaces — Consumes:** `doctor.Run`, `PlanRepairs`, `ApplyRepairs`, `Render`, `NewProbes`, `NewActions`; `agent.LoadConfig(configDir)`, `ipc.Query()`, `transport.SetNetworkOptions(cfg.NetworkOptions())`, package vars `Version`, `configDir`. **Produces:**

```go
// seam for tests
type doctorDeps struct {
    loadConfig func(dir string) (*agent.AgentConfig, error)
    queryIPC   func() (*ipc.Status, error)
    probes     doctor.Probes
    actions    doctor.Actions
    stdout     io.Writer
}
func gatherInputs(d doctorDeps, dir string) doctor.Inputs
func runDoctor(ctx context.Context, d doctorDeps, dir string, flags doctorFlags) (exitCode int, err error)
type doctorFlags struct{ JSON, Fix bool; Export, Lang string }
```

Flags: `--json` (print the bundle, indented, instead of text), `--fix` (apply planned repairs, then re-run all checks once and report the second bundle with the repairs attached), `--export <file>` (also write the bundle JSON; create with mode 0600, refuse to overwrite an existing file), `--lang en|tr`.

`gatherInputs`: try `loadConfig`. On success fill from the config (`Enrolled = AgentID != ""`) and call `transport.SetNetworkOptions` so probes honour `proxy_url`/`server_ca`. Then, regardless, try `queryIPC`: when it answers, take `AuthInvalid`, `Revoked`, `Tunnel`, set `ServiceRunning = true`, and — only if the config was unreadable — `ServerURL`, `AgentID`, `Enrolled` from it and clear `ConfigErr`. When `queryIPC` fails with anything other than `ipc.ErrWindowsOnly`, `ServiceRunning = false`. On `ErrWindowsOnly`, `ServiceRunning` stays nil.

Exit codes: `0` healthy, `1` at least one failing check, `2` usage or internal error. Without `--fix`, planned repairs are listed with outcome `planned`.

- [ ] **Step 1: Failing tests** — `TestGatherInputsFromConfig`, `TestGatherInputsFallsBackToIPCWhenConfigUnreadable` (Review Focus 2: `loadConfig` returns `fs.ErrPermission`, `queryIPC` returns enrolled status → `Inputs.Enrolled`, `ConfigErr == nil`), `TestGatherInputsConfigUnreadableNoIPC` (→ bundle has `CONFIG_UNREADABLE`), `TestRunDoctorExitCodes`, `TestRunDoctorJSONIsValidBundle` (unmarshals into `doctor.Bundle`, `Schema == 1`), `TestRunDoctorFixReRunsChecks` (fake actions flip the fake service to running → final bundle healthy, `Repairs[0].Outcome == "applied"`, exit 0), `TestExportRefusesToOverwrite`, `TestExportFileMode0600` (skip on Windows), `TestJSONOutputHasNoAuthToken` (config fixture with `AuthToken: "s3cret-fixture"` → not in output).
- [ ] **Step 2: Run** `go test ./cmd/openidx-agent/ -run Doctor` → FAIL.
- [ ] **Step 3: Implement** `doctor.go`; register the command; write the changelog fragment and the docs section.
- [ ] **Step 4: Run** `go test ./...` (in `agent/`), `go vet ./...`, `gofmt -l .` (empty), `GOOS=windows go build ./...`, `GOOS=darwin go build ./...`.
- [ ] **Step 5: Manual check on this Linux box** — `go run ./cmd/openidx-agent doctor --config-dir <empty temp dir>` prints `NOT_ENROLLED` and exits 1; with `LC_ALL=tr_TR.UTF-8` the text is Turkish; `--json` output parses with `python3 -m json.tool`. (Use whatever the existing config-dir flag is called in `main.go`.)
- [ ] **Step 6: Commit** `feat(agent): openidx-agent doctor command`.

---

## After the last task

Windows behaviour (IPC fallback, service restart, `ipconfig`) is covered only by cross-compilation and fakes here. Real verification needs wintest: stop the tunneler, run `openidx-agent doctor`, expect `TUNNEL_DOWN`; run `doctor --fix` elevated, expect recovery. That requires an agent build on the device, which is the owner's call (agent release = `agent-v*` tag).
