# Guacamole recording legal-hold UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give operators admin-console controls to place/release recording legal-holds on Guacamole sessions, wired to the existing v1.15.0 backend endpoints.

**Architecture:** Two-part change. (1) Backend: surface two read-only computed flags (`recording_available`, `on_legal_hold`) on the existing `session-history` endpoint so the UI can render place-vs-release state — no new table, no migration (`guacamole_recording_legal_holds` exists as of v68; place/release/list endpoints ship in v1.15.0). (2) Frontend: per-history-row "Place hold"/"Release hold" button + "On hold" badge in `guacamole-sessions.tsx`, mirroring the proven `remote-support.tsx` legal-hold UX.

**Tech Stack:** Go (Gin, pgx v5, zap), testcontainers; React 18 + TypeScript, @tanstack/react-query, Vitest + Testing Library.

---

### Task 1: Backend — surface `recording_available` + `on_legal_hold` on session-history

**Files:**
- Modify: `internal/access/guacamole_sessions.go` (struct `GuacSessionRow` ~line 215-226; handler `handleListGuacSessionHistory` ~line 236-277)
- Test: `internal/access/guacamole_test.go` (add a DTO test) + `internal/access/guacamole_history_flags_test.go` (new, testcontainer integration)

- [ ] **Step 1: Write the failing DTO test**

Add to `internal/access/guacamole_test.go` (it already imports `encoding/json`, `strings`, `testing`):

```go
// The session-history DTO must expose the legal-hold + recording availability
// booleans the console needs to render place-vs-release controls.
func TestGuacSessionRowExposesLegalHoldFlags(t *testing.T) {
	b, _ := json.Marshal(GuacSessionRow{})
	s := string(b)
	for _, want := range []string{"recording_available", "on_legal_hold"} {
		if !strings.Contains(s, want) {
			t.Fatalf("GuacSessionRow is missing JSON field %q: %s", want, b)
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /home/cmit/openidx && go test ./internal/access/ -run TestGuacSessionRowExposesLegalHoldFlags -v`
Expected: FAIL — `GuacSessionRow is missing JSON field "recording_available"`.

- [ ] **Step 3: Add the fields to `GuacSessionRow`**

In `internal/access/guacamole_sessions.go`, the struct currently ends with:

```go
	TranscriptGeneratedAt *time.Time `json:"transcript_generated_at,omitempty"`
}
```

Add the two fields immediately before the closing brace:

```go
	TranscriptGeneratedAt *time.Time `json:"transcript_generated_at,omitempty"`
	RecordingAvailable    bool       `json:"recording_available"`
	OnLegalHold           bool       `json:"on_legal_hold"`
}
```

- [ ] **Step 4: Run the DTO test + the path-leak guard to verify they pass**

Run: `cd /home/cmit/openidx && go test ./internal/access/ -run 'TestGuacSessionRowExposesLegalHoldFlags|TestGuacSessionRowHidesFilePaths' -v`
Expected: PASS both (the new booleans add no `recording_path`/`transcript_path` substring, so the existing leak guard still passes).

- [ ] **Step 5: Update the query + scan to populate the flags**

In `handleListGuacSessionHistory`, the query is currently:

```go
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, connection_id, user_id, guac_session_uuid,
		        started_at, ended_at, status,
		        (COALESCE(transcript_path, '') <> '') AS transcript_available,
		        transcript_generated_at
		   FROM guacamole_sessions
		  WHERE org_id = $1
		  ORDER BY started_at DESC
		  LIMIT 200`,
		org.ID)
```

Replace it with (the table has no alias, so the subquery references `guacamole_sessions.id`; the flags stay inside the org-scoped `WHERE`):

```go
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, connection_id, user_id, guac_session_uuid,
		        started_at, ended_at, status,
		        (COALESCE(transcript_path, '') <> '') AS transcript_available,
		        transcript_generated_at,
		        (COALESCE(recording_path, '') <> '') AS recording_available,
		        EXISTS (SELECT 1 FROM guacamole_recording_legal_holds h
		                 WHERE h.session_id = guacamole_sessions.id
		                   AND h.released_at IS NULL) AS on_legal_hold
		   FROM guacamole_sessions
		  WHERE org_id = $1
		  ORDER BY started_at DESC
		  LIMIT 200`,
		org.ID)
```

And extend the `rows.Scan(...)` call (currently ends `&r.TranscriptAvailable, &r.TranscriptGeneratedAt,`) to append the two new destinations, matching the SELECT order:

```go
		if err := rows.Scan(
			&r.ID, &r.ConnectionID, &r.UserID, &r.GuacSessionUUID,
			&r.StartedAt, &r.EndedAt, &r.Status,
			&r.TranscriptAvailable, &r.TranscriptGeneratedAt,
			&r.RecordingAvailable, &r.OnLegalHold,
		); err != nil {
```

- [ ] **Step 6: Write the failing integration test**

Create `internal/access/guacamole_history_flags_test.go`:

```go
package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// TestGuacSessionHistoryLegalHoldFlags proves handleListGuacSessionHistory reports
// recording_available and on_legal_hold correctly: a recorded session under an active
// hold shows both true; releasing the hold flips on_legal_hold back to false. Uses a
// migrated testcontainer DB (container superuser bypasses RLS, so the org GUC isn't
// needed — the handler's explicit WHERE org_id filter still applies).
func TestGuacSessionHistoryLegalHoldFlags(t *testing.T) {
	db, cleanup := setupTestDB(t) // skips if testcontainers unavailable
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const defaultOrg = "00000000-0000-0000-0000-000000000010" // seeded by migrations

	var sessionID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO guacamole_sessions (org_id, connection_id, recording_path, status, started_at, ended_at)
		VALUES ($1::uuid, gen_random_uuid(), '/rec/sess', 'ended', NOW() - INTERVAL '1 hour', NOW())
		RETURNING id::text`, defaultOrg).Scan(&sessionID); err != nil {
		t.Fatalf("seed guac session: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO guacamole_recording_legal_holds (session_id, reason) VALUES ($1::uuid, 'litigation')`,
		sessionID); err != nil {
		t.Fatalf("place hold: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}

	row := fetchHistoryRow(t, s, defaultOrg, sessionID)
	if !row.RecordingAvailable {
		t.Errorf("recording_available = false, want true (session has a recording_path)")
	}
	if !row.OnLegalHold {
		t.Errorf("on_legal_hold = false, want true (active hold exists)")
	}

	if _, err := db.Pool.Exec(ctx,
		`UPDATE guacamole_recording_legal_holds SET released_at = NOW() WHERE session_id = $1::uuid`,
		sessionID); err != nil {
		t.Fatalf("release hold: %v", err)
	}
	row = fetchHistoryRow(t, s, defaultOrg, sessionID)
	if row.OnLegalHold {
		t.Errorf("on_legal_hold = true after release, want false")
	}
}

// fetchHistoryRow drives the real handler over a gin test context whose request
// carries the org, then returns the single history row for sessionID.
func fetchHistoryRow(t *testing.T, s *Service, orgID, sessionID string) GuacSessionRow {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/access/guacamole/session-history", nil)
	req = req.WithContext(orgctx.With(req.Context(), orgctx.Org{ID: orgID}))
	c.Request = req

	s.handleListGuacSessionHistory(c)
	if w.Code != http.StatusOK {
		t.Fatalf("history handler status = %d, body = %s", w.Code, w.Body.String())
	}

	var body struct {
		Sessions []GuacSessionRow `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode history response: %v", err)
	}
	for _, r := range body.Sessions {
		if r.ID == sessionID {
			return r
		}
	}
	t.Fatalf("session %s not found in history (%d rows)", sessionID, len(body.Sessions))
	return GuacSessionRow{}
}
```

- [ ] **Step 7: Run the integration test to verify it passes**

Run: `cd /home/cmit/openidx && go test ./internal/access/ -run TestGuacSessionHistoryLegalHoldFlags -v`
Expected: PASS (or SKIP if testcontainers/Docker is unavailable in the environment — note which in the task summary; the query is also covered by the box smoke).

- [ ] **Step 8: Full backend gates**

Run: `cd /home/cmit/openidx && go build ./... && go vet ./internal/access/ && gofmt -l internal/access/ && go run ./tools/orgscope -fail ./internal/access`
Expected: build/vet clean; `gofmt -l` prints nothing; orgscope passes (the new subquery lives inside the existing org-scoped query, so no `//orgscope:ignore` is added).

- [ ] **Step 9: Commit**

```bash
cd /home/cmit/openidx
git add internal/access/guacamole_sessions.go internal/access/guacamole_test.go internal/access/guacamole_history_flags_test.go
git commit -m "feat(access): expose recording_available + on_legal_hold on guac session-history

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Frontend — legal-hold controls on the Session History table

**Files:**
- Modify: `web/admin-console/src/pages/guacamole-sessions.tsx` (imports ~line 4-11; `GuacSessionRow` interface ~line 68-77; `SessionHistoryTab` ~line 445-537)
- Test: `web/admin-console/src/pages/guacamole-sessions.test.tsx`

- [ ] **Step 1: Extend the test fixtures + add failing legal-hold tests**

In `guacamole-sessions.test.tsx`, add the two flags to the existing history fixtures and add a held fixture. Change `sessionRowWithTranscript` and `sessionRowNoTranscript` to include the flags, and add a new row:

```ts
const sessionRowWithTranscript = {
  id: 'hist-row-1',
  connection_id: 'conn-db-prod',
  user_id: 'user-charlie',
  started_at: '2026-06-30T08:00:00Z',
  ended_at: '2026-06-30T09:00:00Z',
  status: 'completed',
  transcript_available: true,
  recording_available: true,
  on_legal_hold: false,
}

const sessionRowNoTranscript = {
  id: 'hist-row-2',
  connection_id: 'conn-web-01',
  user_id: 'user-dave',
  started_at: '2026-06-29T08:00:00Z',
  status: 'active',
  transcript_available: false,
  recording_available: false,
  on_legal_hold: false,
}

const sessionRowOnHold = {
  id: 'hist-row-3',
  connection_id: 'conn-app-02',
  user_id: 'user-erin',
  started_at: '2026-06-28T08:00:00Z',
  ended_at: '2026-06-28T09:00:00Z',
  status: 'completed',
  transcript_available: true,
  recording_available: true,
  on_legal_hold: true,
}
```

Update `routeGet` to return all three history rows:

```ts
  if (url.includes('/session-history')) {
    return Promise.resolve({
      sessions: [sessionRowWithTranscript, sessionRowNoTranscript, sessionRowOnHold],
    })
  }
```

Then add three tests inside the `describe('GuacamoleSessionsPage', ...)` block, after the existing transcript tests:

```ts
  it('recorded, un-held row shows "Place hold" and calls POST /legal-hold with a reason', async () => {
    const user = userEvent.setup()
    vi.spyOn(window, 'prompt').mockReturnValue('litigation case #1234')
    vi.mocked(api.post).mockResolvedValueOnce({})

    render(<GuacamoleSessionsPage />, { wrapper: createWrapper() })
    await screen.findByText('Pending Session Requests')
    await user.click(screen.getByRole('tab', { name: /session history/i }))
    await screen.findByText('user-charlie')

    const placeBtns = await screen.findAllByRole('button', { name: /place hold/i })
    fireEvent.click(placeBtns[0]) // hist-row-1

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/access/guacamole/sessions/hist-row-1/legal-hold',
        { reason: 'litigation case #1234' },
      )
    })
  })

  it('held row shows "Release hold" + an On hold badge and calls DELETE /legal-hold', async () => {
    const user = userEvent.setup()
    vi.spyOn(window, 'prompt').mockReturnValue('case closed')
    vi.mocked(api.delete).mockResolvedValueOnce({})

    render(<GuacamoleSessionsPage />, { wrapper: createWrapper() })
    await screen.findByText('Pending Session Requests')
    await user.click(screen.getByRole('tab', { name: /session history/i }))
    await screen.findByText('user-erin')

    expect(screen.getByText(/on hold/i)).toBeInTheDocument()

    const releaseBtn = await screen.findByRole('button', { name: /release hold/i })
    fireEvent.click(releaseBtn)

    await waitFor(() => {
      expect(api.delete).toHaveBeenCalledWith(
        '/api/v1/access/guacamole/sessions/hist-row-3/legal-hold',
        { data: { reason: 'case closed' } },
      )
    })
  })

  it('row without a recording shows no legal-hold button', async () => {
    const user = userEvent.setup()
    render(<GuacamoleSessionsPage />, { wrapper: createWrapper() })
    await screen.findByText('Pending Session Requests')
    await user.click(screen.getByRole('tab', { name: /session history/i }))
    await screen.findByText('user-dave')

    // Only the two recorded rows (hist-row-1, hist-row-3) expose a hold control.
    const placeBtns = screen.queryAllByRole('button', { name: /place hold/i })
    const releaseBtns = screen.queryAllByRole('button', { name: /release hold/i })
    expect(placeBtns).toHaveLength(1)
    expect(releaseBtns).toHaveLength(1)
  })
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/cmit/openidx/web/admin-console && npx vitest run src/pages/guacamole-sessions.test.tsx`
Expected: the three new tests FAIL (no "Place hold"/"Release hold" buttons rendered yet); the existing tests still pass.

- [ ] **Step 3: Add the two flags to the `GuacSessionRow` TS interface**

In `guacamole-sessions.tsx`, the interface currently ends:

```ts
  transcript_available: boolean
  transcript_generated_at?: string
}
```

Extend it:

```ts
  transcript_available: boolean
  transcript_generated_at?: string
  recording_available: boolean
  on_legal_hold: boolean
}
```

- [ ] **Step 4: Add the Lock/Unlock icons to the lucide-react import**

The import block currently is:

```ts
import {
  MonitorPlay,
  CheckCircle2,
  XCircle,
  Clock,
  Download,
  StopCircle,
  Eye,
} from 'lucide-react'
```

Add `Lock` and `Unlock`:

```ts
import {
  MonitorPlay,
  CheckCircle2,
  XCircle,
  Clock,
  Download,
  StopCircle,
  Eye,
  Lock,
  Unlock,
} from 'lucide-react'
```

- [ ] **Step 5: Add the place/release mutations to `SessionHistoryTab`**

`SessionHistoryTab` currently opens with:

```ts
function SessionHistoryTab() {
  const { toast } = useToast()

  const { data, isLoading, isError } = useQuery({
```

Insert a `useQueryClient()` and the two mutations right after `const { toast } = useToast()` (the `useQueryClient` and `useMutation` hooks are already imported at the top of the file):

```ts
function SessionHistoryTab() {
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const placeHoldMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.post(`/api/v1/access/guacamole/sessions/${id}/legal-hold`, { reason }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['guac-session-history'] })
      toast({ title: 'Recording placed on legal hold — exempt from retention sweep.' })
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.error || 'Failed to place hold'
      toast({ title: msg, variant: 'destructive' })
    },
  })

  const releaseHoldMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.delete(`/api/v1/access/guacamole/sessions/${id}/legal-hold`, {
        data: { reason },
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['guac-session-history'] })
      toast({ title: 'Legal hold released — recording subject to retention again.' })
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.error || 'Failed to release hold'
      toast({ title: msg, variant: 'destructive' })
    },
  })

  const { data, isLoading, isError } = useQuery({
```

- [ ] **Step 6: Add the legal-hold button + "On hold" badge to the history row's actions cell**

The actions `<TableCell>` currently holds only the Transcript button:

```tsx
                  <TableCell>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={!s.transcript_available}
                      title={
                        s.transcript_available
                          ? 'Download keystroke transcript'
                          : 'Transcript not available'
                      }
                      onClick={() => downloadTranscript(s.id, toast)}
                    >
                      <Download className="mr-1 h-3 w-3" />
                      Transcript
                    </Button>
                  </TableCell>
```

Wrap both actions in a flex container and add the legal-hold control (only for recorded rows):

```tsx
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={!s.transcript_available}
                        title={
                          s.transcript_available
                            ? 'Download keystroke transcript'
                            : 'Transcript not available'
                        }
                        onClick={() => downloadTranscript(s.id, toast)}
                      >
                        <Download className="mr-1 h-3 w-3" />
                        Transcript
                      </Button>
                      {s.recording_available &&
                        (s.on_legal_hold ? (
                          <>
                            <Badge variant="secondary" className="text-amber-700">
                              On hold
                            </Badge>
                            <Button
                              size="sm"
                              variant="outline"
                              title="Release legal hold (recording becomes subject to retention again)"
                              onClick={() => {
                                const reason = window.prompt(
                                  'Reason for releasing this legal hold (logged in audit):',
                                  '',
                                )
                                if (reason === null) return
                                releaseHoldMutation.mutate({ id: s.id, reason })
                              }}
                            >
                              <Unlock className="mr-1 h-3 w-3 text-amber-600" />
                              Release hold
                            </Button>
                          </>
                        ) : (
                          <Button
                            size="sm"
                            variant="outline"
                            title="Place this recording on legal hold (exempt from retention sweep)"
                            onClick={() => {
                              const reason = window.prompt(
                                'Reason for the legal hold (e.g. "litigation case #1234"):',
                                '',
                              )
                              if (!reason) return
                              placeHoldMutation.mutate({ id: s.id, reason })
                            }}
                          >
                            <Lock className="mr-1 h-3 w-3" />
                            Place hold
                          </Button>
                        ))}
                    </div>
                  </TableCell>
```

- [ ] **Step 7: Run the page tests to verify they pass**

Run: `cd /home/cmit/openidx/web/admin-console && npx vitest run src/pages/guacamole-sessions.test.tsx`
Expected: PASS all — existing tests plus the three new legal-hold tests. (The `transcript` disabled/enabled test still passes: adding a third row keeps index 0 enabled, index 1 disabled.)

- [ ] **Step 8: Type-check + build the console**

Run: `cd /home/cmit/openidx/web/admin-console && npm run build`
Expected: `tsc -b` clean (no unused-import or type errors) and the vite build succeeds.

- [ ] **Step 9: Commit**

```bash
cd /home/cmit/openidx
git add web/admin-console/src/pages/guacamole-sessions.tsx web/admin-console/src/pages/guacamole-sessions.test.tsx
git commit -m "feat(admin-console): guacamole recording legal-hold controls on session history

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage:**
- Backend two flags (`recording_available`, `on_legal_hold`) inside org-scoped query → Task 1, steps 3/5. ✓
- Frontend place/release mutations + reason prompts + toast + invalidate → Task 2, step 5. ✓
- Per-row button gated on recording, place-vs-release by `on_legal_hold`, "On hold" indicator → Task 2, step 6. ✓
- Tests (place→post, release→delete, no-recording→no button) → Task 2, step 1. ✓
- No migration / no new endpoint → confirmed (uses existing v68 table + v1.15.0 endpoints). ✓
- Out-of-scope items (holds list drawer, bulk actions, live-session holds) → not implemented. ✓

**2. Placeholder scan:** No TBD/TODO/"handle edge cases"; every code step shows full code and exact commands. ✓

**3. Type consistency:** Go fields `RecordingAvailable`/`OnLegalHold` (json `recording_available`/`on_legal_hold`) match the TS interface fields and the test fixtures/assertions. Endpoint URLs (`.../sessions/${id}/legal-hold`) and `api.delete(url, { data: { reason } })` shape match the backend routes and the remote-support reference. queryKey `['guac-session-history']` matches the existing `useQuery`. ✓
