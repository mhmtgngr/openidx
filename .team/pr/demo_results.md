# 🎬 Demo Report — 2026-02-26 21:18

## Service Health
```
  ❌ :1025 → UNREACHABLE
  ❌ :11280 → UNREACHABLE
  ❌ :1280 → UNREACHABLE
  ❌ :3022 → UNREACHABLE
  ❌ :3023 → UNREACHABLE
  ✅ :8001 → {"status":"up","components":{"database":{"status":"up","latency_ms":0,"checked_at":"2026-02-26T21:18:27Z"},"redis":{"status":"up","latency_ms":0,"checked_at":"2026-02-26T21:18:27Z"}},"dependencies":[{"name":"redis","status":"up"},{"name":"database","status":"up"}],"version":"dev","uptime":"1d 6h 0m 10s","checked_at":"2026-02-26T21:18:27Z"}
  ❌ :8002 → UNREACHABLE
  ❌ :8003 → UNREACHABLE
  ❌ :8004 → UNREACHABLE
  ✅ :8005 → {"status":"up","components":{"database":{"status":"up","latency_ms":0,"checked_at":"2026-02-26T21:18:27Z"},"redis":{"status":"up","latency_ms":0,"checked_at":"2026-02-26T21:18:27Z"}},"dependencies":[{"name":"redis","status":"up"},{"name":"database","status":"up"}],"version":"dev","uptime":"1d 6h 18m 42s","checked_at":"2026-02-26T21:18:27Z"}
  ✅ :8006 → {"status":"up","components":{"database":{"status":"up","latency_ms":0,"checked_at":"2026-02-26T21:18:27Z"},"redis":{"status":"up","latency_ms":0,"checked_at":"2026-02-26T21:18:27Z"}},"dependencies":[{"name":"redis","status":"up"},{"name":"database","status":"up"}],"version":"dev","uptime":"1d 6h 18m 44s","checked_at":"2026-02-26T21:18:27Z"}
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
ok  	github.com/openidx/openidx/internal/gateway/middleware	0.115s
ok  	github.com/openidx/openidx/internal/gateway/proxy	0.017s
ok  	github.com/openidx/openidx/internal/gateway/routes	0.024s
ok  	github.com/openidx/openidx/internal/governance	95.207s
ok  	github.com/openidx/openidx/internal/health	0.036s
ok  	github.com/openidx/openidx/internal/identity	0.038s
ok  	github.com/openidx/openidx/internal/metrics	0.183s
ok  	github.com/openidx/openidx/internal/mfa	7.348s
ok  	github.com/openidx/openidx/internal/middleware	2.191s
?   	github.com/openidx/openidx/internal/notifications	[no test files]
ok  	github.com/openidx/openidx/internal/oauth	16.009s
?   	github.com/openidx/openidx/internal/organization	[no test files]
?   	github.com/openidx/openidx/internal/portal	[no test files]
ok  	github.com/openidx/openidx/internal/provisioning	0.020s
ok  	github.com/openidx/openidx/internal/risk	0.053s
ok  	github.com/openidx/openidx/internal/server	0.771s
ok  	github.com/openidx/openidx/internal/sms	0.015s
?   	github.com/openidx/openidx/internal/webhooks	[no test files]
ok  	github.com/openidx/openidx/pkg/storage	0.183s
ok  	github.com/openidx/openidx/test/integration	0.020s
```
