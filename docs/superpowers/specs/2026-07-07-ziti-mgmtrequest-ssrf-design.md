# Ziti mgmtRequest SSRF (last 2 critical CodeQL alerts)

**Goal:** Route the generic Ziti `mgmtRequest` helper through the validated `mgmtURL()` builder,
clearing the last 2 open **critical** `go/request-forgery` alerts (`internal/access/ziti.go:1719/1748`)
→ **0 open critical CodeQL alerts** in the repo.

**Verified current state:**
- `mgmtRequest(method, path, body)` builds `http.NewRequest(method, zm.cfg.ZitiCtrlURL+path, …)` at two
  sites (initial ~:1709 and the 401-retry ~:1740), each flagged critical `go/request-forgery`.
- The `mgmtURL(pathAndQuery)` helper (added in #343) parses + validates `ZitiCtrlURL` (http/https scheme
  + host, rebuilt from scheme+host only) and already cleared the 3 direct ziti mgmt calls on that PR's
  merge-ref. Routing `mgmtRequest` through it is the identical, verified fix. `path` (with any
  caller-interpolated segment) is appended to the validated base as before — no behavior change for
  valid controller URLs.

## Design
In `mgmtRequest`, compute the URL once via the validated helper and reuse it for both the initial
request and the retry:
```go
fullURL, err := zm.mgmtURL(path)
if err != nil {
	return nil, 0, err
}
req, err := http.NewRequest(method, fullURL, reqBody)   // was: zm.cfg.ZitiCtrlURL+path
...
req, _ = http.NewRequest(method, fullURL, reqBody)       // retry: was: zm.cfg.ZitiCtrlURL+path
```

## Testing / verification
- `go build ./... && go vet ./internal/access/ && gofmt -l && go run ./tools/orgscope -fail ./internal/access && go test ./internal/access/` clean; `golangci-lint run ./internal/access/` clean.
- Existing ziti tests stay green (same endpoints, validated base).
- Post-PR: confirm the 2 `go/request-forgery` alerts clear on the merge-ref → **0 open critical**.
- Box-relevant (access-service uses the Ziti mgmt path) → deploy after merge; the box's Ziti data-plane
  health (controller reachable, reconcile routes) is the smoke.

## Scope / risk
- One helper in `internal/access/ziti.go` (2 request-build sites). No behavior change for valid
  `ZitiCtrlURL`; a malformed controller URL now errors cleanly instead of issuing a request.
- Out of scope (documented remaining critical+high backlog): `go/path-injection` ×7 (remote_support_recording.go
  = charset-sanitized FP → dismiss; audit/reports.go = add a `filepath.Base` guard), `go/weak-sensitive-data-hashing`
  ×5, `js/empty-password-in-configuration-file` ×2, `go/disabled-certificate-check` (profiler), js/* e2e.
