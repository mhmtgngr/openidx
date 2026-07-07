# Admin-console bundle code-splitting

**Goal:** The admin console ships as a single ~3.4 MB (874 KB gzip) JS chunk — vite warns on every
build, and every user downloads all ~90 pages plus heavy libs (`swagger-ui-react`, `recharts`) up
front, even though `swagger-ui-react` is used by exactly one page (`api-docs`) and `recharts` by one
(`dashboard`). Split the bundle so the initial load is a small shell + only the landing route, and
heavy/unvisited pages load on demand.

**Verified current state (2026-07-07):**
- `web/admin-console/src/App.tsx` statically imports ~93 page components from the `@/pages` barrel
  (`src/pages/index.ts`, 122 lines of `export { XxxPage as Xxx } from './file'`) and mounts 96 `<Route>`s.
- **Only `App.tsx` imports the barrel.** Per-page tests import their page module directly
  (e.g. `import { GuacamoleSessionsPage } from './guacamole-sessions'`), so they are unaffected by how
  the barrel re-exports.
- Heavy deps are page-local: `swagger-ui-react` → only `api-docs.tsx`; `recharts` → only `dashboard.tsx`.
- `vite.config.ts` has no `build.rollupOptions` / `manualChunks`. React 18.3 (supports `lazy`/`Suspense`).

## Design

Two complementary changes:

### 1. Route-level lazy loading — convert the barrel to lazy exports
Because only `App.tsx` consumes the barrel, transform `src/pages/index.ts` from static re-exports to
`React.lazy` components — a mechanical 1:1 per-line transform that preserves every existing exported
name (so `App.tsx`'s destructured import is unchanged):

```ts
// before
export { DashboardPage as Dashboard } from './dashboard'
// after
import { lazy } from 'react'
export const Dashboard = lazy(() => import('./dashboard').then((m) => ({ default: m.DashboardPage })))
```

- Every `import('./file')` is typed, so `m.XxxPage` is **type-checked** — a wrong export name fails
  `tsc`, which is the safety net for all ~93 conversions.
- Only the component re-export lines are converted; if any non-component export exists in the barrel it
  is left as a plain re-export (the implementer converts only `export { …Page as … } from './…'` lines).
- The per-page test files are untouched (they never imported the barrel).

### 2. `App.tsx` — wrap routes in `<Suspense>`
Add `Suspense` (from `react`) and `LoadingSpinner` (from `@/components/ui/loading-spinner`) imports, and
wrap the whole `<Routes>…</Routes>` in a single `<Suspense fallback={<LoadingSpinner />}>`. Lazy route
elements suspend on first visit and show the spinner; navigation is otherwise unchanged. The
destructured `import { … } from '@/pages'` line stays exactly as-is.

### 3. `vite.config.ts` — vendor `manualChunks`
Add `build.rollupOptions.output.manualChunks` that buckets `node_modules` into cacheable vendor chunks,
so heavy libs live in their own files (loaded only by the lazy page chunk that needs them, and cached
across app deploys):

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

With route-level lazy + this split, `swagger` (the biggest single lib) is pulled only into the
`api-docs` page chunk and its `swagger` vendor chunk — it leaves the initial download entirely.

## Testing / verification
- `cd web/admin-console && npm run build` — `tsc -b` clean (validates every lazy `m.XxxPage` export name)
  and vite emits **many** chunks. Confirm from the build output that:
  - `swagger` is its own chunk and is **not** part of the entry/`index-*.js` chunk;
  - the entry/`index-*.js` chunk is dramatically smaller than the current ~3.4 MB single chunk;
  - the chunk-size >500 kB warning is gone for the entry chunk (a large `swagger` vendor chunk that
    loads lazily is acceptable — note it if it still warns).
- `npx vitest run` (full console suite) — all pass unchanged (page tests import page modules directly,
  not the barrel; there is no `App.test.tsx`).
- `npx eslint src/App.tsx src/pages/index.ts vite.config.ts` — clean.
- Manual smoke acceptable but optional: `npm run dev`, confirm login → dashboard renders and a couple of
  routes (api-docs, rotation-policies) lazy-load with the spinner.

## Scope / risk
- **Frontend-only, single PR**, low risk: `src/pages/index.ts` (barrel → lazy), `src/App.tsx` (Suspense
  wrapper), `vite.config.ts` (manualChunks). No backend, no API, no route/URL change, no behavior change
  beyond a brief per-route loading spinner on first visit. `tsc` guards the lazy conversions.
- Out of scope: converting page-local heavy imports to dynamic (`swagger`/`recharts` already isolate via
  their one page); prefetch hints; changing the login/landing flow; removing the (now App-only) barrel
  file — it stays as the lazy registry.

## Resolved at investigation
1. Only `App.tsx` imports `@/pages` → transforming the barrel is safe and keeps `App.tsx`'s import line
   unchanged.
2. `tsc` type-checks `import('./file').then(m => m.XxxPage)`, so mistyped export names fail the build —
   the safety net for the bulk conversion.
3. `swagger-ui-react` (api-docs) and `recharts` (dashboard) are each single-page → lazy routes + a
   `swagger`/`charts` vendor chunk remove them from the initial load.
