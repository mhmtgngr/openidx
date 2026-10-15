# Agent API examples

The exact JSON the shipped agents send, kept as files so the server's contract
test (`internal/access/agent_contract_flow_testdb_test.go`) drives the real
handlers with them and a field renamed on one side fails the build. The
desktop agent's own transport tests send the same shapes
(`agent/internal/transport`); keep the two in step.

| File | Who sends it | Route |
|---|---|---|
| `enroll-request.json` | the desktop agent (`agent/internal/transport/client.go` `Enroll`); `public_key` is a placeholder the test fills | `POST /api/v1/access/agent/enroll` |
| `report-desktop-agent.json` | the desktop agent (`agent/internal/agent/agent.go` `reportPayload`): the outcome nested under `result`, tunnel services as names, state `connected` | `POST /api/v1/access/agent/report` |
| `report-android-agent.json` | the Android agent (`agent-android/core` `ServerApi.kt`), and the shape the server accepted before v1.41: the outcome flat beside `check_type`, tunnel services as objects, state `up` | `POST /api/v1/access/agent/report` |

The contract itself is `api/agent-v1.yaml`.
