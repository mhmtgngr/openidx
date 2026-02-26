# 🎬 Demo Report — 2026-02-25 18:07

## Service Health
```
  ❌ :1025 → UNREACHABLE
  ❌ :11280 → UNREACHABLE
  ❌ :1280 → UNREACHABLE
  ❌ :3022 → UNREACHABLE
  ❌ :3023 → UNREACHABLE
  ✅ :8001 → {"status":"up","components":{"database":{"status":"up","latency_ms":0,"checked_at":"2026-02-25T18:07:50Z"},"redis":{"status":"up","latency_ms":0,"checked_at":"2026-02-25T18:07:50Z"}},"dependencies":[{"name":"database","status":"up"},{"name":"redis","status":"up"}],"version":"dev","uptime":"2h 49m 33s","checked_at":"2026-02-25T18:07:50Z"}
  ❌ :8002 → UNREACHABLE
  ❌ :8003 → UNREACHABLE
  ❌ :8004 → UNREACHABLE
  ✅ :8005 → {"status":"up","components":{"database":{"status":"up","latency_ms":0,"checked_at":"2026-02-25T18:07:50Z"},"redis":{"status":"up","latency_ms":0,"checked_at":"2026-02-25T18:07:50Z"}},"dependencies":[{"name":"redis","status":"up"},{"name":"database","status":"up"}],"version":"dev","uptime":"3h 8m 5s","checked_at":"2026-02-25T18:07:50Z"}
  ✅ :8006 → {"status":"up","components":{"database":{"status":"up","latency_ms":0,"checked_at":"2026-02-25T18:07:50Z"},"redis":{"status":"up","latency_ms":0,"checked_at":"2026-02-25T18:07:50Z"}},"dependencies":[{"name":"redis","status":"up"},{"name":"database","status":"up"}],"version":"dev","uptime":"3h 8m 7s","checked_at":"2026-02-25T18:07:50Z"}
  ❌ :8007 → UNREACHABLE
  ❌ :8025 → UNREACHABLE
  ❌ :8085 → UNREACHABLE
  ❌ :8088 → UNREACHABLE
  ✅ :8090 → {"service":"demo-app","status":"healthy"}
  ❌ :8091 → UNREACHABLE
  ❌ :8281 → UNREACHABLE
  ❌ :8443 → UNREACHABLE
  ❌ :8446 → UNREACHABLE
  ❌ :9188 → UNREACHABLE
  ❌ :9200 → UNREACHABLE
```
## Test Results
```
ok  	github.com/openidx/openidx/internal/gateway/middleware	0.387s
ok  	github.com/openidx/openidx/internal/gateway/proxy	0.027s
ok  	github.com/openidx/openidx/internal/gateway/routes	0.036s
ok  	github.com/openidx/openidx/internal/governance	77.770s
ok  	github.com/openidx/openidx/internal/health	0.019s
ok  	github.com/openidx/openidx/internal/identity	0.024s
ok  	github.com/openidx/openidx/internal/metrics	0.149s
ok  	github.com/openidx/openidx/internal/mfa	6.987s
ok  	github.com/openidx/openidx/internal/middleware	2.175s
?   	github.com/openidx/openidx/internal/notifications	[no test files]
ok  	github.com/openidx/openidx/internal/oauth	11.423s
?   	github.com/openidx/openidx/internal/organization	[no test files]
?   	github.com/openidx/openidx/internal/portal	[no test files]
ok  	github.com/openidx/openidx/internal/provisioning	0.010s
ok  	github.com/openidx/openidx/internal/risk	0.052s
ok  	github.com/openidx/openidx/internal/server	0.755s
ok  	github.com/openidx/openidx/internal/sms	0.011s
?   	github.com/openidx/openidx/internal/webhooks	[no test files]
ok  	github.com/openidx/openidx/pkg/storage	0.218s
ok  	github.com/openidx/openidx/test/integration	0.014s
```
