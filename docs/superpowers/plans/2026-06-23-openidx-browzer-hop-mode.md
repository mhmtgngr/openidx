# OpenZiti BrowZer — Productized Host-Rewrite Hop (`hop` hosting mode) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Turn the hand-run `oidx-psm-hop` nginx into a first-class, access-service-managed `hop` hosting mode, so Host-routed / https BrowZer upstreams (e.g. psm/IIS) render clientlessly without manual containers.

**Architecture:** The BrowZer WASM runtime sends a fixed `Host: unknown` over the overlay, so a Host-routed upstream 404s on the pure `direct`/host.v1 path (raw TCP, no Host rewrite). BUT for an https route the runtime's WASM-TLS sends `SNI = vhost` (it validates the upstream cert). So a single TLS **hop** nginx can demux by **SNI** (`server_name <vhost>`), rewrite `Host: <vhost>`, and TLS-proxy to the real upstream — no per-app ports. A new `hosting_mode='hop'` makes the reconciler point that route's per-app Ziti service's `host.v1` at the shared hop's TLS port (instead of the upstream), and the access-service generates the hop's nginx config (one `server{}` per hop route) the same way it generates `browzer-router.conf`.

**Data path (hop route, e.g. psm):**
```
browser --WASM-TLS (SNI=psm.tdv.org)--> overlay (svc psm-zt)
  --> edge router host.v1 --> hop nginx :8095 (TLS; server_name psm.tdv.org; *.tdv.org cert)
  --> proxy_set_header Host psm.tdv.org; proxy_pass https://psm.tdv.org   (TLS to real upstream)
```

**Tech stack:** Go (reconciler `ziti_reconciler.go`, generator `browzer_targets.go`, config `config.go`), nginx (the hop container, dir-mount + poll-reload like `browzer-router-entrypoint.sh`), OpenZiti mgmt API.

---

## Design decisions (settled)
- **SNI demux, single hop port** — one hop nginx, one TLS listen port (default `8095`), one `server{}` per hop route keyed by `server_name <vhost>`. No per-app port allocation.
- **`hosting_mode='hop'`** is the explicit per-route signal (a route is set to `hop` when its upstream is Host-routed). `EffectiveMode()` returns `hop` when `hosting_mode=='hop'` (takes precedence over the browzer→direct default).
- **Reconciler**: for `hop` mode the per-app Ziti service's `host.v1` target is the **hop's address:port** (config `ZitiBrowZerHopAddr`, e.g. `127.0.0.1:8095`), NOT the route's `to_url`. Bind/Dial/SERP identical to `direct`.
- **Generator**: a new `GenerateBrowZerHopConfig` emits the hop nginx config from the `hop` routes (`server_name`=vhost, `proxy_set_header Host`=vhost, `proxy_pass`=to_url, `proxy_ssl_*` for the https upstream). The **bootstrapper target** for a hop route uses `scheme=https` (already derived from `to_url`), so the runtime does WASM-TLS with SNI=vhost.
- **Deploy**: the hop nginx container (`oidx-browzer-hop`) mounts the shared cert + the generated config via the same dir-mount + `browzer-router-entrypoint.sh` poll-reload pattern. Config written to `BROWZER_HOP_CONFIG_PATH`.

## File structure
- **Modify** `internal/access/ziti_reconciler.go` — `EffectiveMode` + `HostingModeHop` const; `ensureService`/`ensureHosting` use the hop addr for `host.v1` when mode=hop.
- **Modify** `internal/common/config/config.go` — `ZitiBrowZerHopAddr` (default `127.0.0.1:8095`) + env `BROWZER_HOP_ADDR`; `BrowZerHopConfigPath` + env `BROWZER_HOP_CONFIG_PATH`.
- **Modify** `internal/access/browzer_targets.go` — `GenerateBrowZerHopConfig` + `WriteBrowZerHopConfig`; `queryBrowZerRoutes` already returns `hostingMode`; hop routes excluded from the shared router config (already are, since they're not `identity`).
- **Modify** `cmd/access-service/main.go` — write the hop config alongside the bootstrapper targets (`writeBrowZerConfigs`).
- **Test** `internal/access/ziti_reconciler_test.go`, `internal/access/browzer_targets_test.go`.
- **Deploy (live)** the `oidx-browzer-hop` container; migrate psm from the manual `oidx-psm-hop` to it.

---

## Task 1: `HostingModeHop` + `EffectiveMode`

**Files:** Modify `internal/access/ziti_reconciler.go`; Test `internal/access/ziti_reconciler_test.go`.

- [ ] **Step 1: failing test** — add to `ziti_reconciler_test.go`:
```go
func TestEffectiveModeHop(t *testing.T) {
	if (DesiredRoute{HostingMode: "hop", BrowZerEnabled: true}).EffectiveMode() != HostingModeHop {
		t.Fatal("explicit hop must win over browzer->direct")
	}
	if (DesiredRoute{HostingMode: "hop"}).EffectiveMode() != HostingModeHop {
		t.Fatal("hop must be honored")
	}
}
```
- [ ] **Step 2:** run `go test ./internal/access/ -run TestEffectiveModeHop -v` → FAIL (HostingModeHop undefined).
- [ ] **Step 3:** in `ziti_reconciler.go` add the const and update `EffectiveMode`:
```go
	// HostingModeHop — edge router hosts a per-app service whose host.v1 points at
	// the shared TLS hop nginx; the hop SNI-demuxes and rewrites Host for
	// Host-routed/https upstreams the runtime can't address directly.
	HostingModeHop = "hop"
```
In `EffectiveMode()`, BEFORE the browzer→direct rule, add:
```go
	if r.HostingMode == HostingModeHop {
		return HostingModeHop
	}
```
(Keep: BrowZerEnabled→direct, hosting_mode==direct→direct, else identity.)
- [ ] **Step 4:** run the test → PASS; also run the full existing reconciler suite → no regression.
- [ ] **Step 5:** commit `feat(ziti): HostingModeHop + EffectiveMode precedence`.

## Task 2: reconciler hosts `hop` routes at the hop addr

**Files:** Modify `internal/access/ziti_reconciler.go` (+`ZitiReconciler` needs the hop addr); `internal/common/config/config.go`; Test `ziti_reconciler_test.go`.

- [ ] **Step 1:** add config `ZitiBrowZerHopAddr string` (mapstructure `ziti_browzer_hop_addr`), `v.SetDefault("ziti_browzer_hop_addr","127.0.0.1:8095")`, `bindEnvVars` `"ziti_browzer_hop_addr":"BROWZER_HOP_ADDR"`. Pass it into `NewZitiReconciler` (add a `hopAddr string` field; thread from `cfg.ZitiBrowZerHopAddr` in main.go's `NewZitiReconciler` call — update the constructor signature and the one call site).
- [ ] **Step 2: failing test** — extend the direct test or add `TestEnsureServiceHopUsesHopAddr`: a `DesiredRoute{ServiceName:"psm-zt", ToURL:"https://psm.tdv.org", HostingMode:"hop"}` must create a host.v1 config whose `address`/`port` are the **hop addr** (`127.0.0.1`/`8095`), NOT the to_url host. Assert via the mock controller's config POST body.
- [ ] **Step 3:** in `ensureService`, the `host,port` for the host.v1 config is mode-dependent:
```go
	host, port := parseHostPort(d.ToURL)
	if d.EffectiveMode() == HostingModeHop {
		host, port = parseHostPort("//" + rec.hopAddr) // hopAddr is "host:port"
	}
```
(or split `rec.hopAddr` on `:`). Use this `host,port` in `CreateHostV1ConfigFixed`. `ensurePolicies` for hop == direct (Bind `#ziti-routers`, Dial `#browzer-users`, +EnsureRouterRoleAttribute). `ensureHosting` hop == direct (no-op). Easiest: treat hop like direct everywhere EXCEPT the host.v1 target. Update the `switch`/`if` in `ensureService` and `ensurePolicies` to treat `HostingModeHop` the same as `HostingModeDirect` for policies/hosting.
- [ ] **Step 4:** test PASS + full suite green.
- [ ] **Step 5:** commit `feat(ziti): reconciler routes hop mode host.v1 to the shared hop addr`.

## Task 3: `GenerateBrowZerHopConfig` + write it

**Files:** Modify `internal/access/browzer_targets.go`; Test `internal/access/browzer_targets_test.go`.

- [ ] **Step 1: failing test:**
```go
func TestGenerateHopConfigPerVhost(t *testing.T) {
	routes := []browzerRouteInfo{
		{hostname:"psm.tdv.org", toURL:"https://psm.tdv.org", serviceName:"psm-zt", hostingMode:"hop"},
		{hostname:"netgraph.tdv.org", toURL:"http://127.0.0.1:8088", serviceName:"openidx-Netgraph", hostingMode:"direct"},
	}
	cfg := buildBrowZerHopConfig(routes, "/certs/tdv-fullchain.pem", "/certs/tdv-key.pem", 8095)
	if !strings.Contains(cfg, "server_name psm.tdv.org;") { t.Fatal("hop vhost missing") }
	if !strings.Contains(cfg, "proxy_set_header Host psm.tdv.org;") { t.Fatal("Host rewrite missing") }
	if !strings.Contains(cfg, "proxy_pass https://psm.tdv.org;") { t.Fatal("upstream missing") }
	if strings.Contains(cfg, "netgraph.tdv.org") { t.Fatal("non-hop route must be excluded") }
	if !strings.Contains(cfg, "listen 8095 ssl;") { t.Fatal("tls listen missing") }
}
```
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3:** add pure `buildBrowZerHopConfig(routes []browzerRouteInfo, certPath, keyPath string, port int) string` that, for each route where `hostingMode==HostingModeHop`, emits:
```
server {
    listen <port> ssl;
    server_name <vhost>;
    ssl_certificate <certPath>;
    ssl_certificate_key <keyPath>;
    location / {
        proxy_pass <toURL>;
        proxy_ssl_server_name on;
        proxy_ssl_name <vhost>;
        proxy_ssl_verify off;
        proxy_set_header Host <vhost>;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400s;
        proxy_set_header Remote-User $http_remote_user;
    }
}
```
Then `GenerateBrowZerHopConfig(ctx)` = query routes + `buildBrowZerHopConfig(routes, tm.certsPath+"/tdv-fullchain.pem", tm.certsPath+"/tdv-key.pem", tm.hopPort)`, and `WriteBrowZerHopConfig(ctx)` writes it to the hop config path (mirror `WriteBrowZerRouterConfig`, atomic write). Add `hopConfigPath`/`hopPort` fields + setters to `BrowZerTargetManager` (default port 8095). Cert filenames: confirm the actual names under `certsPath` (the live box uses `tdv-fullchain.pem`/`tdv-key.pem` under `/tmp/oidx-tls`; the hop container will mount that dir).
- [ ] **Step 4:** test PASS + full suite.
- [ ] **Step 5:** commit `feat(browzer): generate TLS SNI-demux hop nginx config for hop routes`.

## Task 4: wire hop-config write into startup

**Files:** Modify `cmd/access-service/main.go`.

- [ ] **Step 1:** in the `writeBrowZerConfigs` closure (added in Phase 2's T4b), after `WriteBrowZerRouterConfig`, add `WriteBrowZerHopConfig` (same error/log pattern). Set the manager's hop config path + port from config (`SetHopConfigPath`, `SetHopPort`) where the other paths are set during manager init. Build + vet + gofmt. (No unit test for main wiring.)
- [ ] **Step 2:** commit `feat(access): write the BrowZer hop config alongside bootstrapper targets`.

## Task 5: deploy + migrate psm to the managed hop (live)

**Files:** none (operational).

- [ ] Set `BROWZER_HOP_ADDR=127.0.0.1:8095`, `BROWZER_HOP_CONFIG_PATH=/tmp/oidx-ziti/browzer-config/browzer-hop.conf` in run-access.sh; rebuild binary.
- [ ] Set psm's route `hosting_mode='hop'` (DB) and `to_url='https://psm.tdv.org'` (the real upstream again, not the manual hop). Delete the psm-zt Ziti objects so the reconciler rebuilds host.v1 → the hop addr.
- [ ] Run `oidx-browzer-hop` (nginx:alpine, dir-mount the browzer-config dir + the cert dir + `browzer-router-entrypoint.sh` adapted for the hop config path; publish `127.0.0.1:8095:8095`). Restart access-service → it generates `browzer-hop.conf` (psm `server{}` on :8095) + reconciles psm-zt host.v1 → `127.0.0.1:8095`.
- [ ] Verify in a browser: psm renders (via the managed hop); netgraph still renders. Then `podman rm -f oidx-psm-hop` (retire the manual hop).

## Final review + finish
Dispatch a code reviewer over `origin/main..HEAD`; confirm identity/direct modes unchanged, no DB write-back, hop config only emitted for `hop` routes. Then open the PR.

## Risks
- **SNI assumption:** relies on the runtime sending `SNI=vhost` for https routes (observed live when host.v1 pointed at the real psm). If a future runtime changes this, the SNI demux breaks — the hop's first `server{}` is the implicit default, so add a `default_server` only if there's exactly one hop route, else require correct SNI.
- **Cert coverage:** the hop presents `*.tdv.org`; vhosts must be under that wildcard (psm.tdv.org ✓). Other domains need their own cert.
- **One hop port:** all hop apps share `:8095` via SNI; fine. If two hop apps share a vhost (impossible) it'd collide.
