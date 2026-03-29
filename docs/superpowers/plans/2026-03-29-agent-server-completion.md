# Agent Server-Side Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete agent API handlers with DB persistence, Ziti identity creation, severity-based posture enforcement, dynamic config, plus deployment artifacts.

**Architecture:** Enhance existing AgentAPIHandler to accept ZitiManager, persist to PostgreSQL, create Ziti identities on enrollment, evaluate posture results with severity-based enforcement, and serve dynamic config. Add migration, Dockerfile, and systemd/launchd service files.

**Tech Stack:** Go 1.25, PostgreSQL (pgx), Gin, OpenZiti SDK, Docker

---

## Task 1: Database migration

**Files to create/modify:**
- `migrations/202503290001_enrolled_agents.up.sql` (create)
- `migrations/202503290001_enrolled_agents.down.sql` (create)
- `deployments/docker/init-db.sql` (append)

### Step 1a: Create up migration

**File:** `/home/cmit/openidx/migrations/202503290001_enrolled_agents.up.sql`

```sql
-- Migration 202503290001: Create enrolled_agents and agent_posture_results tables
-- These tables support the agent enrollment, posture reporting, and enforcement lifecycle.

CREATE TABLE IF NOT EXISTS enrolled_agents (
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

CREATE INDEX IF NOT EXISTS idx_enrolled_agents_status ON enrolled_agents(status);
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_last_seen ON enrolled_agents(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_agent_id ON enrolled_agents(agent_id);

CREATE TABLE IF NOT EXISTS agent_posture_results (
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

CREATE INDEX IF NOT EXISTS idx_agent_posture_agent ON agent_posture_results(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_posture_reported ON agent_posture_results(reported_at);
```

### Step 1b: Create down migration

**File:** `/home/cmit/openidx/migrations/202503290001_enrolled_agents.down.sql`

```sql
-- Rollback migration 202503290001: Drop enrolled_agents and agent_posture_results tables

DROP TABLE IF EXISTS agent_posture_results;
DROP TABLE IF EXISTS enrolled_agents;
```

### Step 1c: Append tables to init-db.sql

**File:** `/home/cmit/openidx/deployments/docker/init-db.sql`

Append the following at the very end of the file (after the last line `ALTER TABLE directory_sync_state ADD COLUMN IF NOT EXISTS last_delta_link TEXT;`):

```sql

-- ============================================================================
-- AGENT ENROLLMENT AND POSTURE TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS enrolled_agents (
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

CREATE INDEX IF NOT EXISTS idx_enrolled_agents_status ON enrolled_agents(status);
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_last_seen ON enrolled_agents(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_agent_id ON enrolled_agents(agent_id);

CREATE TABLE IF NOT EXISTS agent_posture_results (
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

CREATE INDEX IF NOT EXISTS idx_agent_posture_agent ON agent_posture_results(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_posture_reported ON agent_posture_results(reported_at);
```

### Build/test commands

```bash
# No Go build needed for SQL-only changes. Verify files exist:
ls -la migrations/202503290001_enrolled_agents.up.sql
ls -la migrations/202503290001_enrolled_agents.down.sql
tail -5 deployments/docker/init-db.sql
```

### Commit

```
feat(agent): add database migration for enrolled_agents and agent_posture_results

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 2: Update AgentAPIHandler to accept ZitiManager

**Files to modify:**
- `internal/access/agent_api.go`
- `internal/access/service.go` (line 405)
- `internal/access/agent_api_test.go`

### Step 2a: Modify AgentAPIHandler struct and constructor

**File:** `/home/cmit/openidx/internal/access/agent_api.go`

Replace the struct and constructor:

```go
// AgentAPIHandler handles HTTP endpoints for agent communication.
type AgentAPIHandler struct {
	logger *zap.Logger
	db     *database.PostgresDB
	zm     *ZitiManager
}

// NewAgentAPIHandler constructs an AgentAPIHandler with the given logger, database, and optional ZitiManager.
// zm may be nil if Ziti is not configured.
func NewAgentAPIHandler(logger *zap.Logger, db *database.PostgresDB, zm *ZitiManager) *AgentAPIHandler {
	return &AgentAPIHandler{
		logger: logger,
		db:     db,
		zm:     zm,
	}
}
```

### Step 2b: Update service.go call site

**File:** `/home/cmit/openidx/internal/access/service.go`

Change line 405 from:

```go
agentHandler := NewAgentAPIHandler(svc.logger, svc.db)
```

To:

```go
agentHandler := NewAgentAPIHandler(svc.logger, svc.db, svc.zitiManager)
```

### Step 2c: Update test helper

**File:** `/home/cmit/openidx/internal/access/agent_api_test.go`

Change the `newTestAgentHandler` function from:

```go
func newTestAgentHandler() *AgentAPIHandler {
	logger := zap.NewNop()
	return NewAgentAPIHandler(logger, nil)
}
```

To:

```go
func newTestAgentHandler() *AgentAPIHandler {
	logger := zap.NewNop()
	return NewAgentAPIHandler(logger, nil, nil)
}
```

### Build/test commands

```bash
cd /home/cmit/openidx
go build ./internal/access/...
# Expected: clean build, no errors

go test ./internal/access/ -run TestAgent -v
# Expected: all 4 existing tests pass (TestAgentEnroll_ValidToken, TestAgentEnroll_MissingToken,
# TestAgentReport_Accepted, TestAgentConfig_ReturnsDefaults)
```

### Commit

```
refactor(agent): add ZitiManager parameter to AgentAPIHandler constructor

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 3: Complete HandleEnroll

**Files to modify:**
- `internal/access/agent_api_test.go` (add tests first)
- `internal/access/agent_api.go` (implement)

### Step 3a: Write tests (TDD)

**File:** `/home/cmit/openidx/internal/access/agent_api_test.go`

Add the following tests after the existing tests:

```go
// TestAgentEnroll_ResponseIncludesStatus verifies the enrollment response
// includes status and that auth_token is a valid UUID.
func TestAgentEnroll_ResponseIncludesStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/enroll", handler.HandleEnroll)

	body, _ := json.Marshal(map[string]interface{}{
		"hostname": "dev-laptop",
		"platform": "linux",
	})
	req := httptest.NewRequest(http.MethodPost, "/agent/enroll", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-enrollment-token")
	req.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Must include status field
	assert.Contains(t, resp, "status")
	status, ok := resp["status"].(string)
	assert.True(t, ok)
	// Without DB, status should be "active" (dev mode auto-approve)
	assert.Equal(t, "active", status)

	// agent_id, device_id, auth_token must be present and non-empty
	assert.NotEmpty(t, resp["agent_id"])
	assert.NotEmpty(t, resp["device_id"])
	assert.NotEmpty(t, resp["auth_token"])
}

// TestAgentEnroll_WithHostnameInMetadata verifies hostname/platform from the
// request body are captured (visible in response metadata when DB is nil).
func TestAgentEnroll_WithHostnameInMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/enroll", handler.HandleEnroll)

	body, _ := json.Marshal(map[string]interface{}{
		"hostname": "test-host",
		"platform": "darwin",
	})
	req := httptest.NewRequest(http.MethodPost, "/agent/enroll", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer enroll-token-123")
	req.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp["agent_id"])
}
```

### Step 3b: Implement HandleEnroll

**File:** `/home/cmit/openidx/internal/access/agent_api.go`

Add `"crypto/sha256"`, `"encoding/hex"`, `"encoding/json"`, and `"os"` to imports. Update the `enrollResponse` struct and `HandleEnroll` method.

Replace the entire imports block, struct definitions, and HandleEnroll:

```go
package access

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)
```

Replace the `enrollResponse` struct:

```go
// enrollResponse is returned by HandleEnroll on success.
type enrollResponse struct {
	AgentID   string `json:"agent_id"`
	DeviceID  string `json:"device_id"`
	AuthToken string `json:"auth_token"`
	Status    string `json:"status"`
	ZitiJWT   string `json:"ziti_jwt,omitempty"`
}
```

Replace the entire `HandleEnroll` method:

```go
// HandleEnroll validates the Authorization header, persists the agent enrollment
// to the database, optionally creates a Ziti identity, and returns credentials.
func (h *AgentAPIHandler) HandleEnroll(c *gin.Context) {
	if c.GetHeader("Authorization") == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
		return
	}

	// Parse optional body for hostname/platform metadata
	var req enrollRequest
	_ = c.ShouldBindJSON(&req) // best-effort, body is optional

	agentID := uuid.New().String()
	deviceID := uuid.New().String()
	authToken := uuid.New().String()

	// Hash the auth token for storage (never store plaintext)
	tokenHash := sha256.Sum256([]byte(authToken))
	authTokenHash := hex.EncodeToString(tokenHash[:])

	// Build metadata JSON
	metadata := map[string]string{
		"hostname": req.Hostname,
		"platform": req.Platform,
	}
	metadataJSON, _ := json.Marshal(metadata)

	// Determine initial status: auto-approve in development mode
	status := "pending"
	appEnv := os.Getenv("APP_ENV")
	if appEnv == "" || appEnv == "development" || appEnv == "dev" {
		status = "active"
	}

	// Persist to database if available
	if h.db != nil && h.db.Pool != nil {
		_, err := h.db.Pool.Exec(c.Request.Context(),
			`INSERT INTO enrolled_agents (agent_id, device_id, status, auth_token_hash, enrolled_at, metadata)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			agentID, deviceID, status, authTokenHash, time.Now(), metadataJSON,
		)
		if err != nil {
			h.logger.Error("failed to persist agent enrollment", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "enrollment persistence failed"})
			return
		}
	}

	resp := enrollResponse{
		AgentID:   agentID,
		DeviceID:  deviceID,
		AuthToken: authToken,
		Status:    status,
	}

	// If active and Ziti is configured, create a Ziti identity
	if status == "active" && h.zm != nil {
		zitiID, enrollmentJWT, err := h.zm.CreateIdentity(
			c.Request.Context(),
			"agent-"+agentID,
			"Device",
			[]string{"agent", "posture-reporting"},
		)
		if err != nil {
			h.logger.Warn("ziti identity creation failed, agent enrolled without ziti",
				zap.String("agent_id", agentID),
				zap.Error(err),
			)
		} else {
			resp.ZitiJWT = enrollmentJWT
			// Update DB with Ziti identity ID
			if h.db != nil && h.db.Pool != nil {
				_, _ = h.db.Pool.Exec(c.Request.Context(),
					`UPDATE enrolled_agents SET ziti_identity_id = $1 WHERE agent_id = $2`,
					zitiID, agentID,
				)
			}
		}
	}

	h.logger.Info("agent enrolled",
		zap.String("agent_id", agentID),
		zap.String("device_id", deviceID),
		zap.String("status", status),
	)

	c.JSON(http.StatusOK, resp)
}
```

### Build/test commands

```bash
cd /home/cmit/openidx
go build ./internal/access/...
# Expected: clean build

go test ./internal/access/ -run TestAgent -v -count=1
# Expected: all tests pass including new TestAgentEnroll_ResponseIncludesStatus
# and TestAgentEnroll_WithHostnameInMetadata
```

### Commit

```
feat(agent): implement HandleEnroll with DB persistence and Ziti identity creation

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 4: Complete HandleReport

**Files to modify:**
- `internal/access/agent_api_test.go` (add tests first)
- `internal/access/agent_api.go` (implement)

### Step 4a: Write tests (TDD)

**File:** `/home/cmit/openidx/internal/access/agent_api_test.go`

Add these tests:

```go
// TestAgentReport_WithResults verifies that a report with posture results
// returns 202 with a compliance_score and enforcement_actions array.
func TestAgentReport_WithResults(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/report", handler.HandleReport)

	body, _ := json.Marshal(map[string]interface{}{
		"results": []map[string]interface{}{
			{
				"check_type": "os_version",
				"status":     "pass",
				"score":      1.0,
				"severity":   "high",
				"message":    "OS is up to date",
			},
			{
				"check_type": "disk_encryption",
				"status":     "fail",
				"score":      0.0,
				"severity":   "critical",
				"message":    "Disk encryption disabled",
			},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/agent/report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", "test-agent-001")

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusAccepted, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Must include compliance_score
	assert.Contains(t, resp, "compliance_score")
	score, ok := resp["compliance_score"].(float64)
	assert.True(t, ok)
	assert.GreaterOrEqual(t, score, 0.0)
	assert.LessOrEqual(t, score, 100.0)

	// Must include enforcement_actions array
	assert.Contains(t, resp, "enforcement_actions")
	actions, ok := resp["enforcement_actions"].([]interface{})
	assert.True(t, ok)
	// critical failure should produce a revoke action
	assert.GreaterOrEqual(t, len(actions), 1)
}

// TestAgentReport_MissingAgentID verifies that a report without X-Agent-ID
// returns 400.
func TestAgentReport_MissingAgentID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/report", handler.HandleReport)

	body, _ := json.Marshal(map[string]interface{}{
		"results": []map[string]interface{}{},
	})
	req := httptest.NewRequest(http.MethodPost, "/agent/report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No X-Agent-ID header

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestAgentReport_EmptyResults verifies that an empty results array returns 202
// with score 100 (fully compliant) and no enforcement actions.
func TestAgentReport_EmptyResults(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.POST("/agent/report", handler.HandleReport)

	body, _ := json.Marshal(map[string]interface{}{
		"results": []map[string]interface{}{},
	})
	req := httptest.NewRequest(http.MethodPost, "/agent/report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", "test-agent-002")

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusAccepted, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	score := resp["compliance_score"].(float64)
	assert.Equal(t, 100.0, score)

	actions := resp["enforcement_actions"].([]interface{})
	assert.Empty(t, actions)
}
```

### Step 4b: Implement HandleReport

**File:** `/home/cmit/openidx/internal/access/agent_api.go`

Add the following types and replace the `HandleReport` method:

```go
// postureResult represents a single posture check result in an agent report.
type postureResult struct {
	CheckType string                 `json:"check_type"`
	Status    string                 `json:"status"` // "pass" or "fail"
	Score     float64                `json:"score"`
	Severity  string                 `json:"severity"` // "critical", "high", "medium", "low"
	Details   map[string]interface{} `json:"details"`
	Message   string                 `json:"message"`
}

// reportRequest is the JSON body accepted by HandleReport.
type reportRequest struct {
	Results []postureResult `json:"results"`
}

// reportResponse is returned by HandleReport.
type reportResponse struct {
	ComplianceScore    float64              `json:"compliance_score"`
	EnforcementActions []enforcementAction  `json:"enforcement_actions"`
}

// enforcementAction describes an action taken in response to a posture failure.
type enforcementAction struct {
	CheckType string `json:"check_type"`
	Severity  string `json:"severity"`
	Action    string `json:"action"` // "revoke", "grace", "alert", "none"
	Message   string `json:"message"`
}

// severityWeight returns the numeric weight for a severity level.
func severityWeight(severity string) float64 {
	switch severity {
	case "critical":
		return 4.0
	case "high":
		return 3.0
	case "medium":
		return 2.0
	case "low":
		return 1.0
	default:
		return 1.0
	}
}

// enforcementForSeverity returns the enforcement action string for a failed check.
func enforcementForSeverity(severity string) string {
	switch severity {
	case "critical":
		return "revoke"
	case "high":
		return "grace"
	case "medium":
		return "alert"
	case "low":
		return "none"
	default:
		return "none"
	}
}

// HandleReport accepts a status report from an enrolled agent, persists results,
// computes compliance score, and returns enforcement actions.
func (h *AgentAPIHandler) HandleReport(c *gin.Context) {
	agentID := c.GetHeader("X-Agent-ID")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing X-Agent-ID header"})
		return
	}

	var req reportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Fall back to reading raw body for backwards compatibility
		body, readErr := io.ReadAll(c.Request.Body)
		if readErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
			return
		}
		if len(body) > 0 {
			if jsonErr := json.Unmarshal(body, &req); jsonErr != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
				return
			}
		}
	}

	now := time.Now()

	// Update last_seen_at and last_report_at on enrolled_agents
	if h.db != nil && h.db.Pool != nil {
		_, _ = h.db.Pool.Exec(c.Request.Context(),
			`UPDATE enrolled_agents SET last_seen_at = $1, last_report_at = $1 WHERE agent_id = $2`,
			now, agentID,
		)
	}

	// Process each result: persist and determine enforcement
	var actions []enforcementAction
	var totalWeightedScore float64
	var totalWeight float64

	for _, result := range req.Results {
		weight := severityWeight(result.Severity)
		totalWeight += weight

		passed := result.Status == "pass"
		if passed {
			totalWeightedScore += weight * result.Score
		}

		// Determine enforcement action for failures
		var action string
		var enforced bool
		if !passed {
			action = enforcementForSeverity(result.Severity)
			enforced = action == "revoke"

			actions = append(actions, enforcementAction{
				CheckType: result.CheckType,
				Severity:  result.Severity,
				Action:    action,
				Message:   result.Message,
			})
		} else {
			action = "none"
		}

		// Persist to agent_posture_results
		if h.db != nil && h.db.Pool != nil {
			detailsJSON, _ := json.Marshal(result.Details)
			_, err := h.db.Pool.Exec(c.Request.Context(),
				`INSERT INTO agent_posture_results
				 (agent_id, check_type, status, score, severity, details, message, reported_at, enforced, enforcement_action)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
				agentID, result.CheckType, result.Status, result.Score,
				result.Severity, detailsJSON, result.Message, now, enforced, action,
			)
			if err != nil {
				h.logger.Error("failed to persist posture result",
					zap.String("agent_id", agentID),
					zap.String("check_type", result.CheckType),
					zap.Error(err),
				)
			}
		}
	}

	// Compute compliance score (0-100)
	complianceScore := 100.0
	if totalWeight > 0 {
		complianceScore = (totalWeightedScore / totalWeight) * 100.0
	}

	// Determine compliance status
	complianceStatus := "compliant"
	if complianceScore < 70 {
		complianceStatus = "non_compliant"
	} else if complianceScore < 90 {
		complianceStatus = "grace_period"
	}

	// Update enrolled_agents with compliance data
	if h.db != nil && h.db.Pool != nil {
		_, _ = h.db.Pool.Exec(c.Request.Context(),
			`UPDATE enrolled_agents SET compliance_score = $1, compliance_status = $2 WHERE agent_id = $3`,
			complianceScore, complianceStatus, agentID,
		)
	}

	// If any critical failure requires revoke and Ziti is available, revoke policies
	for _, a := range actions {
		if a.Action == "revoke" && h.zm != nil {
			h.logger.Warn("critical posture failure — revoking ziti access",
				zap.String("agent_id", agentID),
				zap.String("check_type", a.CheckType),
			)
			// Note: ZitiManager.RemoveServiceDialPolicies is not yet implemented.
			// When available, call: h.zm.RemoveServiceDialPolicies(ctx, agentID)
			// For now, update agent status to suspended as a safety measure.
			if h.db != nil && h.db.Pool != nil {
				_, _ = h.db.Pool.Exec(c.Request.Context(),
					`UPDATE enrolled_agents SET status = 'suspended' WHERE agent_id = $1`,
					agentID,
				)
			}
			break // One revoke is enough
		}
	}

	if actions == nil {
		actions = []enforcementAction{}
	}

	h.logger.Info("agent report processed",
		zap.String("agent_id", agentID),
		zap.Float64("compliance_score", complianceScore),
		zap.String("compliance_status", complianceStatus),
		zap.Int("result_count", len(req.Results)),
		zap.Int("action_count", len(actions)),
	)

	c.JSON(http.StatusAccepted, reportResponse{
		ComplianceScore:    complianceScore,
		EnforcementActions: actions,
	})
}
```

### Build/test commands

```bash
cd /home/cmit/openidx
go build ./internal/access/...
# Expected: clean build

go test ./internal/access/ -run TestAgentReport -v -count=1
# Expected: TestAgentReport_WithResults PASS (score computed, revoke action present)
# Expected: TestAgentReport_MissingAgentID PASS (400 returned)
# Expected: TestAgentReport_EmptyResults PASS (score=100, no actions)
# Expected: TestAgentReport_Accepted PASS (existing test, still 202)
```

### Commit

```
feat(agent): implement HandleReport with posture evaluation and severity-based enforcement

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 5: Complete HandleConfig

**Files to modify:**
- `internal/access/agent_api_test.go` (add tests first)
- `internal/access/agent_api.go` (implement)

### Step 5a: Write tests (TDD)

**File:** `/home/cmit/openidx/internal/access/agent_api_test.go`

Add these tests:

```go
// TestAgentConfig_WithAgentID verifies that a GET to /agent/config with
// X-Agent-ID returns 200 with checks and enforcement_policy.
func TestAgentConfig_WithAgentID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.GET("/agent/config", handler.HandleConfig)

	req := httptest.NewRequest(http.MethodGet, "/agent/config", nil)
	req.Header.Set("X-Agent-ID", "test-agent-active")

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Contains(t, resp, "checks")
	assert.Contains(t, resp, "report_interval")
	assert.Contains(t, resp, "enforcement_policy")
}

// TestAgentConfig_NoAgentID verifies that a GET without X-Agent-ID still returns
// default config (backwards compatibility / pending agent behavior).
func TestAgentConfig_NoAgentID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.GET("/agent/config", handler.HandleConfig)

	req := httptest.NewRequest(http.MethodGet, "/agent/config", nil)
	// No X-Agent-ID header

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Should return minimal/pending config
	checks := resp["checks"].([]interface{})
	assert.Equal(t, 1, len(checks))
	assert.Equal(t, "1h", resp["report_interval"])
}
```

### Step 5b: Implement HandleConfig

**File:** `/home/cmit/openidx/internal/access/agent_api.go`

Replace the `agentConfigResponse` struct and the `HandleConfig` method:

```go
// enforcementPolicy describes the enforcement rules sent to agents.
type enforcementPolicy struct {
	CriticalAction string `json:"critical_action"`
	HighAction     string `json:"high_action"`
	MediumAction   string `json:"medium_action"`
	LowAction      string `json:"low_action"`
	GracePeriodH   int    `json:"grace_period_hours"`
}

// agentConfigResponse is returned by HandleConfig.
type agentConfigResponse struct {
	Checks            []agentCheck       `json:"checks"`
	ReportInterval    string             `json:"report_interval"`
	EnforcementPolicy *enforcementPolicy `json:"enforcement_policy,omitempty"`
}

// HandleConfig returns agent configuration based on the agent's enrollment status.
// Agents identify themselves via the X-Agent-ID header. Without a header or DB,
// returns default/pending config.
func (h *AgentAPIHandler) HandleConfig(c *gin.Context) {
	agentID := c.GetHeader("X-Agent-ID")

	// Default enforcement policy
	policy := &enforcementPolicy{
		CriticalAction: "revoke",
		HighAction:     "grace",
		MediumAction:   "alert",
		LowAction:      "none",
		GracePeriodH:   24,
	}

	// If no agent ID or no DB, return minimal/pending config
	if agentID == "" || h.db == nil || h.db.Pool == nil {
		cfg := agentConfigResponse{
			Checks: []agentCheck{
				{Name: "os_version", Enabled: true},
			},
			ReportInterval: "1h",
		}
		if agentID == "" {
			// Truly anonymous request - no enforcement policy
			c.JSON(http.StatusOK, cfg)
			return
		}
		cfg.EnforcementPolicy = policy
		c.JSON(http.StatusOK, cfg)
		return
	}

	// Look up agent status from DB
	var status string
	err := h.db.Pool.QueryRow(c.Request.Context(),
		`SELECT status FROM enrolled_agents WHERE agent_id = $1`, agentID,
	).Scan(&status)

	if err != nil {
		h.logger.Debug("agent not found in DB, returning pending config",
			zap.String("agent_id", agentID),
			zap.Error(err),
		)
		// Fall back to pending config
		c.JSON(http.StatusOK, agentConfigResponse{
			Checks: []agentCheck{
				{Name: "os_version", Enabled: true},
			},
			ReportInterval:    "1h",
			EnforcementPolicy: policy,
		})
		return
	}

	// Update last_seen_at
	_, _ = h.db.Pool.Exec(c.Request.Context(),
		`UPDATE enrolled_agents SET last_seen_at = $1 WHERE agent_id = $2`,
		time.Now(), agentID,
	)

	switch status {
	case "revoked":
		c.JSON(http.StatusForbidden, gin.H{"error": "agent access revoked"})
		return

	case "suspended":
		// Suspended agents get empty checks (idle)
		c.JSON(http.StatusOK, agentConfigResponse{
			Checks:            []agentCheck{},
			ReportInterval:    "1h",
			EnforcementPolicy: policy,
		})
		return

	case "pending":
		// Pending agents get minimal checks
		c.JSON(http.StatusOK, agentConfigResponse{
			Checks: []agentCheck{
				{Name: "os_version", Enabled: true},
			},
			ReportInterval:    "1h",
			EnforcementPolicy: policy,
		})
		return

	case "active":
		// Active agents get full checks from posture_checks table
		checks := []agentCheck{}

		rows, err := h.db.Pool.Query(c.Request.Context(),
			`SELECT name, enabled FROM posture_checks WHERE enabled = true ORDER BY name`,
		)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var check agentCheck
				if scanErr := rows.Scan(&check.Name, &check.Enabled); scanErr == nil {
					checks = append(checks, check)
				}
			}
		}

		// If no checks found in DB, use sensible defaults
		if len(checks) == 0 {
			checks = []agentCheck{
				{Name: "os_version", Enabled: true},
				{Name: "disk_encryption", Enabled: true},
				{Name: "firewall", Enabled: true},
				{Name: "screen_lock", Enabled: true},
				{Name: "antivirus", Enabled: true},
			}
		}

		c.JSON(http.StatusOK, agentConfigResponse{
			Checks:            checks,
			ReportInterval:    "5m",
			EnforcementPolicy: policy,
		})
		return

	default:
		// Unknown status — treat as pending
		c.JSON(http.StatusOK, agentConfigResponse{
			Checks: []agentCheck{
				{Name: "os_version", Enabled: true},
			},
			ReportInterval:    "1h",
			EnforcementPolicy: policy,
		})
	}
}
```

### Step 5c: Update existing TestAgentConfig_ReturnsDefaults

The existing test `TestAgentConfig_ReturnsDefaults` sends no `X-Agent-ID` header, so it now gets the minimal/pending config (1 check instead of 3). Update the assertion:

**File:** `/home/cmit/openidx/internal/access/agent_api_test.go`

Replace the existing `TestAgentConfig_ReturnsDefaults` function:

```go
// TestAgentConfig_ReturnsDefaults verifies that a GET to /agent/config without
// X-Agent-ID returns 200 with minimal pending config (1 check, 1h interval).
func TestAgentConfig_ReturnsDefaults(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	handler := newTestAgentHandler()
	router.GET("/agent/config", handler.HandleConfig)

	req := httptest.NewRequest(http.MethodGet, "/agent/config", nil)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp agentConfigResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.Checks)
	assert.Equal(t, 1, len(resp.Checks))
	assert.Equal(t, "os_version", resp.Checks[0].Name)
	assert.Equal(t, "1h", resp.ReportInterval)
}
```

Also update `TestRegisterAgentRoutes` — the `/agent/config` route without `X-Agent-ID` still returns 200, so the assertion remains valid. The `/agent/report` route now requires `X-Agent-ID`, so update that sub-test:

Replace the `TestRegisterAgentRoutes` function:

```go
// TestRegisterAgentRoutes verifies that all three routes are registered and
// respond to the correct HTTP methods.
func TestRegisterAgentRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	handler := newTestAgentHandler()
	group := router.Group("/")
	handler.RegisterAgentRoutes(group)

	// /agent/enroll — requires Authorization header
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/agent/enroll", nil)
	req.Header.Set("Authorization", "Bearer tok")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// /agent/report — requires X-Agent-ID header
	w = httptest.NewRecorder()
	reportBody, _ := json.Marshal(map[string]interface{}{"results": []interface{}{}})
	req = httptest.NewRequest(http.MethodPost, "/agent/report", bytes.NewReader(reportBody))
	req.Header.Set("X-Agent-ID", "route-test-agent")
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusAccepted, w.Code)

	// /agent/config
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/agent/config", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
```

### Build/test commands

```bash
cd /home/cmit/openidx
go build ./internal/access/...
# Expected: clean build

go test ./internal/access/ -run TestAgentConfig -v -count=1
# Expected: TestAgentConfig_ReturnsDefaults PASS (1 check, 1h)
# Expected: TestAgentConfig_WithAgentID PASS (defaults with enforcement_policy, since DB=nil)
# Expected: TestAgentConfig_NoAgentID PASS (1 check, no enforcement_policy)

go test ./internal/access/ -run TestAgent -v -count=1
# Expected: ALL agent tests pass
```

### Commit

```
feat(agent): implement HandleConfig with status-based dynamic configuration

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 6: Agent Dockerfile

**Files to create:**
- `deployments/docker/Dockerfile.agent`
- `deployments/docker/agent-entrypoint.sh`

**Files to modify:**
- `deployments/docker/docker-compose.yml` (add commented-out service)

### Step 6a: Create Dockerfile.agent

**File:** `/home/cmit/openidx/deployments/docker/Dockerfile.agent`

```dockerfile
# Multi-stage Dockerfile for the OpenIDX endpoint agent
# Builds the agent binary from the agent/ subdirectory

# ============================================
# Stage 1: Build
# ============================================
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates gcc musl-dev && \
    echo 'precedence ::ffff:0:0/96 100' >> /etc/gai.conf

WORKDIR /app

# Copy agent module files first for layer caching
COPY agent/go.mod agent/go.sum ./agent/
RUN cd agent && go mod download && go mod verify

# Copy agent source
COPY agent/ ./agent/

ARG VERSION=dev

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
    -a \
    -ldflags="-w -s -X main.Version=${VERSION}" \
    -trimpath \
    -o /app/openidx-agent \
    ./agent/cmd/openidx-agent && \
    ls -lh /app/openidx-agent

# ============================================
# Stage 2: Runtime
# ============================================
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata curl jq && \
    rm -rf /var/cache/apk/*

RUN addgroup -S openidx && \
    adduser -S openidx -G openidx

WORKDIR /app

COPY --from=builder /app/openidx-agent /app/openidx-agent
COPY deployments/docker/agent-entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Config and data directories
RUN mkdir -p /etc/openidx-agent /var/lib/openidx-agent && \
    chown -R openidx:openidx /etc/openidx-agent /var/lib/openidx-agent

USER openidx

# Environment variables for enrollment
ENV OPENIDX_SERVER_URL=""
ENV OPENIDX_AGENT_TOKEN=""
ENV OPENIDX_AGENT_MODE="standalone"
ENV OPENIDX_CONFIG_DIR="/etc/openidx-agent"

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD pgrep openidx-agent || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
```

### Step 6b: Create agent-entrypoint.sh

**File:** `/home/cmit/openidx/deployments/docker/agent-entrypoint.sh`

```bash
#!/bin/sh
set -e

CONFIG_FILE="${OPENIDX_CONFIG_DIR}/agent.json"

# Auto-enroll if no config exists and enrollment token is provided
if [ ! -f "$CONFIG_FILE" ] && [ -n "$OPENIDX_AGENT_TOKEN" ] && [ -n "$OPENIDX_SERVER_URL" ]; then
    echo "[entrypoint] No config found, enrolling with server at ${OPENIDX_SERVER_URL}..."

    ENROLL_RESPONSE=$(curl -sf \
        -X POST \
        -H "Authorization: Bearer ${OPENIDX_AGENT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"hostname\": \"$(hostname)\", \"platform\": \"$(uname -s)\"}" \
        "${OPENIDX_SERVER_URL}/api/v1/access/agent/enroll" \
    ) || {
        echo "[entrypoint] ERROR: Enrollment failed. Check OPENIDX_SERVER_URL and OPENIDX_AGENT_TOKEN."
        exit 1
    }

    # Extract credentials and write config
    AGENT_ID=$(echo "$ENROLL_RESPONSE" | jq -r '.agent_id')
    AUTH_TOKEN=$(echo "$ENROLL_RESPONSE" | jq -r '.auth_token')
    STATUS=$(echo "$ENROLL_RESPONSE" | jq -r '.status')
    ZITI_JWT=$(echo "$ENROLL_RESPONSE" | jq -r '.ziti_jwt // empty')

    cat > "$CONFIG_FILE" <<EOCFG
{
    "server_url": "${OPENIDX_SERVER_URL}",
    "agent_id": "${AGENT_ID}",
    "auth_token": "${AUTH_TOKEN}",
    "mode": "${OPENIDX_AGENT_MODE:-standalone}"
}
EOCFG

    echo "[entrypoint] Enrolled successfully. Agent ID: ${AGENT_ID}, Status: ${STATUS}"

    # If Ziti JWT was provided, save it for the agent to use
    if [ -n "$ZITI_JWT" ]; then
        echo "$ZITI_JWT" > "${OPENIDX_CONFIG_DIR}/ziti-enrollment.jwt"
        echo "[entrypoint] Ziti enrollment JWT saved."
    fi
fi

echo "[entrypoint] Starting openidx-agent (mode: ${OPENIDX_AGENT_MODE:-standalone})..."
exec /app/openidx-agent --config "$CONFIG_FILE" "$@"
```

### Step 6c: Add commented-out service to docker-compose.yml

**File:** `/home/cmit/openidx/deployments/docker/docker-compose.yml`

Append the following at the end of the `services:` block (before any `volumes:` or `networks:` block at the bottom of the file). Find the last service definition and add after it, but before the closing infrastructure:

Find the appropriate place to add (just before the `volumes:` section at the bottom) and append:

```yaml
  # ---------------------------------------------------------------------------
  # Agent (optional — typically runs on endpoints, not in the compose stack)
  # Uncomment to test agent enrollment and reporting locally.
  # ---------------------------------------------------------------------------
  # agent:
  #   build:
  #     context: ../../
  #     dockerfile: deployments/docker/Dockerfile.agent
  #     args:
  #       VERSION: ${VERSION:-dev}
  #   container_name: openidx-agent
  #   restart: unless-stopped
  #   environment:
  #     OPENIDX_SERVER_URL: http://access-service:8000
  #     OPENIDX_AGENT_TOKEN: ${AGENT_ENROLLMENT_TOKEN:-dev-agent-token}
  #     OPENIDX_AGENT_MODE: standalone
  #     OPENIDX_CONFIG_DIR: /etc/openidx-agent
  #   depends_on:
  #     access-service:
  #       condition: service_healthy
  #   networks:
  #     - openidx-network
```

### Build/test commands

```bash
# Verify Dockerfile syntax (no actual build needed without Docker daemon)
cat deployments/docker/Dockerfile.agent
cat deployments/docker/agent-entrypoint.sh

# Verify shell script is valid
sh -n deployments/docker/agent-entrypoint.sh
# Expected: no output (valid syntax)
```

### Commit

```
feat(agent): add Dockerfile and entrypoint with auto-enrollment support

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 7: Systemd and launchd service files

**Files to create:**
- `agent/deploy/openidx-agent.service`
- `agent/deploy/com.openidx.agent.plist`
- `agent/deploy/openidx-agent.env`

### Step 7a: Create systemd unit file

**File:** `/home/cmit/openidx/agent/deploy/openidx-agent.service`

```ini
[Unit]
Description=OpenIDX Endpoint Agent
Documentation=https://docs.openidx.dev/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=openidx-agent
Group=openidx-agent
EnvironmentFile=/etc/openidx-agent/openidx-agent.env
ExecStart=/usr/local/bin/openidx-agent --config /etc/openidx-agent/agent.json
Restart=always
RestartSec=10
StartLimitIntervalSec=300
StartLimitBurst=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/openidx-agent /etc/openidx-agent
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=openidx-agent

[Install]
WantedBy=multi-user.target
```

### Step 7b: Create launchd plist

**File:** `/home/cmit/openidx/agent/deploy/com.openidx.agent.plist`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.openidx.agent</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/openidx-agent</string>
        <string>--config</string>
        <string>/etc/openidx-agent/agent.json</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>NetworkState</key>
        <true/>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>ThrottleInterval</key>
    <integer>10</integer>

    <key>UserName</key>
    <string>_openidx</string>

    <key>GroupName</key>
    <string>_openidx</string>

    <key>WorkingDirectory</key>
    <string>/var/lib/openidx-agent</string>

    <key>StandardOutPath</key>
    <string>/var/log/openidx-agent/agent.log</string>

    <key>StandardErrorPath</key>
    <string>/var/log/openidx-agent/agent-error.log</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>OPENIDX_CONFIG_DIR</key>
        <string>/etc/openidx-agent</string>
    </dict>
</dict>
</plist>
```

### Step 7c: Create environment file template

**File:** `/home/cmit/openidx/agent/deploy/openidx-agent.env`

```bash
# OpenIDX Agent Environment Configuration
# Copy this file to /etc/openidx-agent/openidx-agent.env and fill in values.

# Server URL for the OpenIDX access service (required)
OPENIDX_SERVER_URL=https://access.openidx.example.com

# Enrollment token (only needed for initial enrollment, can be removed after)
# OPENIDX_AGENT_TOKEN=your-enrollment-token-here

# Agent configuration directory
OPENIDX_CONFIG_DIR=/etc/openidx-agent

# Agent mode: standalone, daemonset, or sidecar
OPENIDX_AGENT_MODE=standalone

# Log level: debug, info, warn, error
LOG_LEVEL=info
```

### Build/test commands

```bash
# Verify files exist and are well-formed
cat agent/deploy/openidx-agent.service
cat agent/deploy/com.openidx.agent.plist
cat agent/deploy/openidx-agent.env

# Validate XML plist syntax
xmllint --noout agent/deploy/com.openidx.agent.plist 2>&1 || echo "xmllint not available, skipping"
```

### Commit

```
feat(agent): add systemd, launchd, and env template deployment files

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 8: Verify and push

### Step 8a: Build all Go code

```bash
cd /home/cmit/openidx
go build ./...
# Expected: clean build, exit 0
```

### Step 8b: Run all tests

```bash
cd /home/cmit/openidx
go test ./... 2>&1 | tail -30
# Expected: all packages PASS (or skip for integration-tagged tests)
# Key line: ok  github.com/openidx/openidx/internal/access
```

### Step 8c: Run agent tests with race detector

```bash
cd /home/cmit/openidx/agent
go test -race ./... 2>&1 | tail -20
# Expected: all agent packages PASS with no race conditions detected
```

### Step 8d: Push to remote

```bash
cd /home/cmit/openidx
git push origin HEAD
# Expected: push succeeds to current branch
```

No commit for this task (verification only).
