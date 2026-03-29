# Agent Server-Side Completion Design

## Problem

The agent API handlers are stubs — HandleEnroll generates UUIDs without persisting, HandleReport discards posture data, HandleConfig returns hardcoded defaults. Agents can enroll and report but nothing is stored, evaluated, or enforced. The agent also lacks deployment artifacts (Dockerfile, systemd service).

## Scope

Complete the server-side agent lifecycle: enrollment with DB persistence and Ziti identity creation, posture result processing with severity-based enforcement, dynamic config based on agent state, plus deployment artifacts. No admin console UI (API-first, UI follows independently).

## Database Schema

### enrolled_agents

Stores agent enrollment records.

```sql
CREATE TABLE enrolled_agents (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id          VARCHAR(64) UNIQUE NOT NULL,
    device_id         VARCHAR(64) NOT NULL,
    ziti_identity_id  VARCHAR(255),
    status            VARCHAR(20) DEFAULT 'pending',
    auth_token_hash   VARCHAR(128) NOT NULL,
    enrolled_at       TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at      TIMESTAMPTZ,
    last_report_at    TIMESTAMPTZ,
    compliance_status VARCHAR(20) DEFAULT 'unknown',
    compliance_score  FLOAT DEFAULT 0.0,
    metadata          JSONB DEFAULT '{}',
    created_by        VARCHAR(255)
);

CREATE INDEX idx_enrolled_agents_status ON enrolled_agents(status);
CREATE INDEX idx_enrolled_agents_last_seen ON enrolled_agents(last_seen_at);
CREATE INDEX idx_enrolled_agents_agent_id ON enrolled_agents(agent_id);
```

Status values: pending, active, suspended, revoked.
Compliance values: compliant, non_compliant, grace_period, unknown.
Auth token stored as SHA256 hash, never plaintext.

### agent_posture_results

Stores per-check results from agent reports with enforcement tracking.

```sql
CREATE TABLE agent_posture_results (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id           VARCHAR(64) NOT NULL,
    check_type         VARCHAR(64) NOT NULL,
    status             VARCHAR(10) NOT NULL,
    score              FLOAT DEFAULT 0.0,
    severity           VARCHAR(10) NOT NULL,
    details            JSONB DEFAULT '{}',
    message            TEXT,
    reported_at        TIMESTAMPTZ DEFAULT NOW(),
    expires_at         TIMESTAMPTZ,
    enforced           BOOLEAN DEFAULT FALSE,
    enforcement_action VARCHAR(20)
);

CREATE INDEX idx_agent_posture_agent ON agent_posture_results(agent_id);
CREATE INDEX idx_agent_posture_reported ON agent_posture_results(reported_at);
```

Enforcement actions: revoke, grace, alert, none.

## Enrollment Flow

1. Agent POSTs to `/api/v1/access/agent/enroll` with enrollment token
2. Server validates token, generates agent_id, device_id, auth_token (UUID)
3. Hashes auth_token with SHA256, inserts into enrolled_agents (status=pending)
4. Checks auto-approval policy (reuses DeviceTrustSettings pattern):
   - Corporate device / known IP: auto-approve, status=active
   - Unknown device: status=pending, admin notified
   - Development mode: auto-approve all
5. If active AND Ziti enabled:
   - Calls ZitiManager.CreateIdentity(agentID) to create Ziti identity
   - Stores ziti_identity_id in DB
   - Includes ziti_jwt in response for agent-side Ziti enrollment
6. Returns: agent_id, device_id, auth_token, status, ziti_jwt (optional)

Pending agents communicate over HTTPS only (no Ziti until approved). They receive limited config.

## Posture Result Processing

1. Agent POSTs to `/api/v1/access/agent/report` with results array
2. Server validates agent via auth_token_hash lookup
3. Updates last_seen_at and last_report_at on enrolled_agents
4. For each result, inserts into agent_posture_results and evaluates enforcement:

| Severity | On Fail | Enforcement Action |
|----------|---------|-------------------|
| critical | Immediate revoke | Revoke Ziti service dial policies |
| high | Grace period (24h default) | Mark non-compliant, escalate after window |
| medium | Alert | Log + notify admin |
| low | Log only | No enforcement |

5. Computes overall compliance_score (weighted average by severity)
6. Updates enrolled_agents compliance_status and compliance_score
7. If any enforcement=revoke: calls ZitiManager.RemoveServiceDialPolicies()
8. If grace period expired on previous non-compliant: escalates to revoke
9. Returns 202 with compliance_score and enforcement_actions array

Grace period duration is configurable as a system setting (default 24h).

## Dynamic Config

1. Agent GETs `/api/v1/access/agent/config` with X-Agent-ID header
2. Server looks up agent in enrolled_agents
3. Returns config based on agent status:

| Status | Config |
|--------|--------|
| pending | Minimal: os_version check only, 1h interval |
| active | Full: all enabled posture_checks from DB with params |
| suspended | Empty checks (agent idles) |
| revoked | 403 Forbidden |

4. Active agents get checks from the posture_checks table (already has check_type, parameters, severity, enabled)
5. Response includes enforcement_policy so agent knows consequences

## Deployment Artifacts

### Dockerfile (`deployments/docker/Dockerfile.agent`)

Multi-stage Go build, alpine runtime, non-root user. Entrypoint script auto-enrolls if no config exists (using OPENIDX_AGENT_TOKEN and OPENIDX_SERVER_URL env vars), then runs.

Deployment modes via OPENIDX_AGENT_MODE env var:
- daemonset: K8s node agent
- sidecar: per-pod agent
- standalone: testing/CI

### systemd service (`agent/deploy/openidx-agent.service`)

Standard systemd unit with Restart=always, RestartSec=10, non-root user, EnvironmentFile for server URL and config dir.

### launchd plist (`agent/deploy/com.openidx.agent.plist`)

macOS launchd service with KeepAlive, RunAtLoad, non-root user.

## Files to Create/Modify

| File | Action |
|------|--------|
| `migrations/030_enrolled_agents.up.sql` | Create: both tables + indexes |
| `migrations/030_enrolled_agents.down.sql` | Create: drop tables |
| `internal/access/agent_api.go` | Modify: complete all 3 handlers |
| `internal/access/agent_api_test.go` | Modify: update tests for real logic |
| `deployments/docker/Dockerfile.agent` | Create: agent container image |
| `deployments/docker/agent-entrypoint.sh` | Create: auto-enroll + run script |
| `agent/deploy/openidx-agent.service` | Create: systemd unit |
| `agent/deploy/com.openidx.agent.plist` | Create: launchd plist |
| `Makefile` | Modify: add docker-build-agent target |

## Out of Scope

- Admin console agent management UI (API-first, UI follows)
- Agent auto-update mechanism
- Agent metrics/Prometheus endpoint
- Per-agent policy group assignment (all agents get same posture checks for now)
