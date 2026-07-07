# Admin-console code-splitting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the admin console's single ~3.4 MB JS bundle into a small shell + lazy per-route chunks + cacheable vendor chunks, so the initial load excludes unvisited pages and heavy libs (`swagger-ui-react`, `recharts`).

**Architecture:** (1) `vite.config.ts` gains a `manualChunks` bucketer so `node_modules` vendors land in their own chunks; (2) the `@/pages` barrel (imported only by `App.tsx`) is converted from static re-exports to `React.lazy` components, and `App.tsx` wraps its `<Routes>` in `<Suspense>`. `tsc` type-checks every lazy import's export name.

**Tech Stack:** React 18 `lazy`/`Suspense`, Vite/Rollup `manualChunks`, TypeScript, Vitest. All changes in `web/admin-console/` (3 files).

---

### Task 1: Vendor `manualChunks` in vite.config

**Files:**
- Modify: `web/admin-console/vite.config.ts` (the `defineConfig({...})` object — add a `build` key)

- [ ] **Step 1: Capture the current single-bundle baseline**

Run: `cd /home/cmit/openidx/web/admin-console && npm run build 2>&1 | grep -E 'dist/assets/.*\.js' | sort -k2 -h | tail -5`
Expected: a single dominant `dist/assets/index-*.js` around ~3.4 MB (874 KB gzip). Note it for comparison.

- [ ] **Step 2: Add the `manualChunks` bucketer**

In `vite.config.ts`, add a `build` property to the `defineConfig({...})` object (a sibling of `plugins`, `resolve`, `server`). Insert it right after the `plugins: [react()],` line:

```ts
  build: {
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return
          if (id.includes('swagger-ui')) return 'swagger'
          if (id.includes('recharts') || id.includes('/d3-') || id.includes('victory')) return 'charts'
          if (id.includes('react-router')) return 'router'
          if (id.includes('@radix-ui')) return 'radix'
          if (id.includes('/react-dom/') || id.includes('/react/') || id.includes('/scheduler/')) return 'react'
          return 'vendor'
        },
      },
    },
  },
```

- [ ] **Step 3: Build and verify vendor chunks appear**

Run: `cd /home/cmit/openidx/web/admin-console && npm run build 2>&1 | grep -E 'dist/assets/(swagger|charts|radix|react|router|vendor)-.*\.js'`
Expected: distinct chunk files for `swagger`, `charts`, `radix`, `react`, `router`, `vendor` are emitted. (The entry `index-*.js` is still large at this stage — route lazy-loading in Task 2 is what shrinks it; this task only proves the vendor split works and is a valid standalone improvement for caching.)

- [ ] **Step 4: Type-check + lint**

Run: `cd /home/cmit/openidx/web/admin-console && npx tsc -b && npx eslint vite.config.ts`
Expected: both clean. (`manualChunks(id: string)` is typed; if eslint flags the param type as unnecessary, leave it — it documents intent and is harmless.)

- [ ] **Step 5: Commit**

```bash
cd /home/cmit/openidx
git add web/admin-console/vite.config.ts
git commit -m "perf(admin-console): split vendor libs into cacheable chunks (manualChunks)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Lazy page barrel + `<Suspense>` in App.tsx

**Files:**
- Modify: `web/admin-console/src/pages/index.ts` (convert all ~93 re-exports to `React.lazy`)
- Modify: `web/admin-console/src/App.tsx` (imports line 1; wrap `<Routes>` ~line 157-297 in `<Suspense>`)

- [ ] **Step 1: Convert the barrel to lazy exports**

`src/pages/index.ts` currently has ~93 lines in two shapes. Add `import { lazy } from 'react'` as the first import, then transform **every** `export … from './…'` line:

Shape A — named page export (the vast majority):
```ts
// before
export { DashboardPage as Dashboard } from './dashboard'
// after
export const Dashboard = lazy(() => import('./dashboard').then((m) => ({ default: m.DashboardPage })))
```

Shape B — default export (exactly two lines today: `mfa-management` → `MFAManagement`, `login-anomalies` → `LoginAnomalies`):
```ts
// before
export { default as MFAManagement } from './mfa-management'
// after
export const MFAManagement = lazy(() => import('./mfa-management'))
```

Apply mechanically to every line, preserving the exported alias name exactly (so `App.tsx`'s destructured import needs no change) and the comment headers. Keep the module `.ts` (no JSX — `lazy(...)` returns a component without JSX here).

- [ ] **Step 2: Type-check to validate every lazy export name**

Run: `cd /home/cmit/openidx/web/admin-console && npx tsc -b`
Expected: clean. If tsc errors like `Property 'FooPage' does not exist on type ...`, the alias→export-name in that barrel line was wrong — fix that specific `.then((m) => ({ default: m.XxxPage }))` to the real exported symbol (open the referenced page file to confirm its export name). Re-run until clean. This step is the safety net for the bulk conversion.

- [ ] **Step 3: Add `Suspense` + `LoadingSpinner` and wrap `<Routes>` in App.tsx**

(a) Change the first import of `App.tsx`:
```ts
// before
import { useEffect } from 'react'
// after
import { useEffect, Suspense } from 'react'
```
(b) Add the spinner import alongside the other component imports (e.g. right after `import { Layout } from '@/components/layout'`):
```ts
import { LoadingSpinner } from '@/components/ui/loading-spinner'
```
(c) Wrap the returned `<Routes>…</Routes>` (the `return (` at ~line 157, `<Routes>` at 158 through `</Routes>` at 297) in a `<Suspense>`:
```tsx
  return (
    <Suspense
      fallback={
        <div className="flex h-screen items-center justify-center">
          <LoadingSpinner size="lg" />
        </div>
      }
    >
      <Routes>
        {/* …all existing routes unchanged… */}
      </Routes>
    </Suspense>
  )
```
Do NOT change any `<Route>` element or the `import { … } from '@/pages'` line — only add the wrapper.

- [ ] **Step 4: Build and verify the split**

Run: `cd /home/cmit/openidx/web/admin-console && npm run build 2>&1 | tail -40`
Expected:
- `tsc -b` passes and vite emits **many** small `dist/assets/*.js` chunks (one per lazy page plus the vendor chunks from Task 1).
- The entry `index-*.js` chunk is **dramatically smaller** than the ~3.4 MB baseline from Task 1 Step 1.
- Confirm `swagger` is its own chunk and is **not** merged into the entry chunk:
  `cd /home/cmit/openidx/web/admin-console && npm run build 2>&1 | grep -E 'swagger-.*\.js'` shows a `swagger` chunk.
- The >500 kB chunk-size warning should no longer apply to the entry chunk (a large lazily-loaded `swagger` vendor chunk may still warn — that's acceptable; note it in the report).

- [ ] **Step 5: Run the full console test suite + lint**

Run: `cd /home/cmit/openidx/web/admin-console && npx vitest run 2>&1 | tail -15`
Expected: all tests pass (page tests import page modules directly, not the barrel, so they are unaffected; there is no `App.test.tsx`).
Run: `cd /home/cmit/openidx/web/admin-console && npx eslint src/App.tsx src/pages/index.ts`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
cd /home/cmit/openidx
git add web/admin-console/src/pages/index.ts web/admin-console/src/App.tsx
git commit -m "perf(admin-console): lazy-load route pages (React.lazy + Suspense)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage:**
- vite `manualChunks` vendor split (swagger/charts/radix/react/router/vendor) → Task 1. ✓
- Barrel → `React.lazy`, both shapes (named `XxxPage as X`, and `default as X`) → Task 2 Step 1. ✓
- `tsc` validates lazy export names → Task 2 Step 2. ✓
- App.tsx `<Suspense>` wrap + spinner, import line unchanged, routes unchanged → Task 2 Step 3. ✓
- Verification: build shows split + smaller entry + swagger separate; full vitest; eslint → Task 1 Steps 3-4, Task 2 Steps 4-5. ✓
- Barrel stays the (App-only) lazy registry; per-page tests untouched; no backend/route change → respected (only 3 files, no `<Route>`/URL edits). ✓
- Out of scope (prefetch, login-flow change, barrel removal) → not touched. ✓

**2. Placeholder scan:** No TBD/TODO. The barrel conversion is a deterministic rule (two concrete before/after shapes given) rather than a placeholder; reproducing all 93 identical-shape lines verbatim adds no information and `tsc` verifies correctness. Every other step has complete code + exact commands.

**3. Type consistency:** `Suspense`/`lazy` from `react`; `LoadingSpinner` from `@/components/ui/loading-spinner` (confirmed exported, accepts `size`); barrel aliases preserved so `App.tsx`'s `import { … } from '@/pages'` is unchanged; `manualChunks` chunk names (`swagger`,`charts`,`radix`,`react`,`router`,`vendor`) are consistent between Task 1 and the Task 2 verification. ✓
