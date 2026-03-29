# OpenIDX Endpoint Agent Design

## Problem

Endpoints today require multiple separate agents (Ziti tunneler, MDM, AV, compliance) that are hard to manage and don't share context. OpenIDX needs a unified endpoint agent that provides zero-trust networking, posture checking, and extensibility through plugins — deployable on everything from laptops to IoT devices.

## Architecture

Single Go binary (`openidx-agent`) with three layers:

- **Ziti Core**: Embeds `openziti/sdk-golang` for tunneling and secure communication to OpenIDX
- **Check Engine**: Runs built-in posture checks (OS version, encryption, firewall, etc.) on server-defined schedules
- **Plugin Runtime**: Discovers and runs external plugins from a directory via JSON-over-stdin/stdout protocol

All communication is Ziti-first with HTTPS fallback for enrollment and degraded mode.

## Agent Lifecycle

### Enrollment
1. Admin generates one-time enrollment token in OpenIDX console
2. Agent contacts OpenIDX over HTTPS, presents token
3. Server validates, creates Ziti identity, returns Ziti JWT + agent config + CA certs
4. Agent enrolls with Ziti controller, stores identity in local secure storage
5. All subsequent communication over Ziti

### Runtime Loop
```
Boot → Load identity → Connect Ziti → Sync config from server
  → Run scheduled checks → Report results → Sleep → Repeat
  → Plugin discovery → Load plugins → Include in check cycle
  → Tunnel services → Route traffic through Ziti overlay
```

### Degraded Modes
- Ziti controller down: agent continues with cached config, queues results
- Server unreachable: checks run locally, results cached until connectivity returns
- Plugin crash: isolated, doesn't affect core or other plugins

## Plugin Protocol

Plugins are external executables in `/etc/openidx-agent/plugins/` (platform equivalent on Windows/macOS).

### Manifest (`manifest.json` next to executable)
```json
{
  "name": "mdm-intune",
  "version": "1.0.0",
  "description": "Microsoft Intune compliance check",
  "platforms": ["windows", "darwin"],
  "check_types": ["mdm_compliance", "mdm_enrollment"],
  "schedule": "inherit",
  "timeout_seconds": 30
}
```

### Protocol (JSON over stdin/stdout)
```
Agent → Plugin:  {"action": "check", "type": "mdm_compliance", "params": {...}}
Plugin → Agent:  {"status": "pass|fail|warn|error", "score": 0.85, "details": {...}}

Agent → Plugin:  {"action": "info"}
Plugin → Agent:  {"name": "...", "version": "...", "check_types": [...]}

Agent → Plugin:  {"action": "remediate", "type": "mdm_compliance", "params": {...}}
Plugin → Agent:  {"status": "success|failed", "message": "..."}
```

Language-agnostic: plugins can be Go, Python, Bash, or anything that reads stdin/writes stdout.

### Example Plugins
- `plugin-osquery` — wraps osquery, exposes FleetDM-compatible queries as checks
- `plugin-intune` — Microsoft Intune enrollment/compliance
- `plugin-jamf` — JAMF MDM compliance on macOS
- `plugin-crowdstrike` — verifies CrowdStrike Falcon is running
- `plugin-diskencrypt` — BitLocker/FileVault/LUKS status
- `plugin-fw` — firewall rule validation

## Built-in Checks

Ship with agent, no plugins needed. Map to existing `internal/access/device_health.go` check types:

| Check | Platforms | Description |
|-------|-----------|-------------|
| `os_version` | All | Compares OS version against server policy minimum |
| `disk_encryption` | Win/Mac/Linux | BitLocker, FileVault, LUKS status |
| `screen_lock` | Win/Mac/Linux | Screen lock enabled with timeout |
| `firewall` | Win/Mac/Linux | OS firewall active |
| `antivirus` | Win/Mac | Windows Security Center, XProtect |
| `process_running` | All | Required processes running (configurable) |
| `domain_joined` | Win/Mac/Linux | AD/LDAP domain membership |
| `patch_level` | Win/Mac/Linux | Days since last security update |
| `integrity` | Mobile | Jailbreak/root detection |
| `agent_version` | All | Self-check agent is current |

### Server-Defined Config (synced over Ziti)
```yaml
checks:
  - type: os_version
    params:
      min_version: "14.0"
    severity: high
    interval: 1h
  - type: disk_encryption
    severity: critical
    interval: 6h
  - type: process_running
    params:
      processes: ["falcon-sensor", "openidx-agent"]
    severity: medium
    interval: 15m
```

Failed critical checks can revoke Ziti services in real-time.

## Project Structure

```
agent/
├── cmd/openidx-agent/main.go        # Entry point
├── internal/
│   ├── core/
│   │   ├── agent.go                  # Agent runtime (boot, loop, shutdown)
│   │   └── config.go                 # Config model + sync
│   ├── transport/
│   │   ├── ziti.go                   # Ziti SDK connection + tunneler
│   │   └── https.go                  # HTTPS fallback client
│   ├── enrollment/enroll.go          # Token-based enrollment
│   ├── checks/
│   │   ├── engine.go                 # Check scheduler + runner
│   │   ├── os_version.go             # Built-in checks (one per file)
│   │   ├── disk_encryption.go
│   │   ├── firewall.go
│   │   ├── process.go
│   │   └── registry.go              # Check type registry
│   ├── plugin/
│   │   ├── runtime.go                # Plugin discovery + lifecycle
│   │   ├── protocol.go              # JSON stdin/stdout protocol
│   │   └── sandbox.go               # Timeout, resource limits
│   └── reporter/reporter.go         # Result reporting to server
├── plugins/                          # Example plugins
│   ├── plugin-osquery/
│   └── plugin-diskencrypt/
└── Makefile
```

### Server-Side Additions (minimal)
- `internal/access/agent_api.go` — endpoints: `POST /agent/enroll`, `POST /agent/report`, `GET /agent/config`
- Reuses existing `device_health.go` check types and `posture.go` models

### Build Targets
```bash
make agent          # Build for current platform
make agent-all      # Cross-compile: linux/amd64, darwin/amd64, darwin/arm64, windows/amd64, linux/arm64
make agent-plugins  # Build example plugins
```

## Platforms
- Linux amd64/arm64 (servers, desktops, IoT)
- macOS amd64/arm64 (desktops)
- Windows amd64 (desktops)
- Mobile (future: Android/iOS via gomobile)

## Integration with Existing Code
- Reuse `internal/access/device_health.go` check type definitions
- Reuse `internal/access/posture.go` posture check models
- Reuse `internal/risk/device.go` fingerprinting (reference)
- Reuse `internal/identity/device_trust_approval.go` trust workflow
- Agent results feed into existing posture check evaluation in access-service

## Out of Scope (Future)
- Mobile native apps (Android/iOS)
- GUI installer/tray icon
- Auto-update mechanism (ship with package managers first)
- Admin console UI for agent management (API-first, UI later)
