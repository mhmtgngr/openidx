# Admin-console code-splitting follow-ups

**Goal:** Two small, review-driven refinements to the v1.20.0 code-splitting work (from the #333
code-quality review): (1) split the eager ~1.17 MB `vendor` chunk finer for better caching, and (2)
move the route-loading `<Suspense>` into the `Layout` outlet so intra-app navigation shows a
content-area spinner instead of a full-screen flash that replaces the sidebar/header.

**Verified current state (2026-07-07):**
- `web/admin-console/vite.config.ts` `manualChunks` buckets `swagger`/`charts`/`router`/`radix`/`react`,
  everything else → `vendor` (which holds `@tanstack/react-query`, `lucide-react`, `axios`, `date-fns`,
  `zustand`, `qrcode.react`, `clsx`, etc.).
- `web/admin-console/src/App.tsx` wraps the entire `<Routes>` in one full-screen `<Suspense>`
  (fallback = centered `LoadingSpinner`). This fires on every first visit to any lazy route, replacing
  the whole viewport (including the `Layout` shell).
- `web/admin-console/src/components/layout.tsx` renders `<Outlet />` (line ~432) inside an
  `<ErrorBoundary key={location.pathname}>`, within `<main>`. `Layout` imports `useState` from react.
  No `App.test.tsx`/`layout.test.tsx` exist.

## Design

### 1. Finer vendor chunks (`vite.config.ts`)
Add two buckets before the `return 'vendor'` fallback, so the two largest/most-cacheable libs the
review named get their own long-lived chunks:
```ts
if (id.includes('lucide-react')) return 'icons'
if (id.includes('@tanstack')) return 'query'
```
`react-router`/`@radix-ui`/`react` checks stay ahead of these (unaffected). `qrcode.react` is imported
only by MFA pages, so it already lands in those lazy page chunks — no bucket needed. This improves cache
granularity (a `vendor` bump no longer invalidates the icon/query bytes); it does not change initial
bytes materially (these libs are still eagerly imported by the shell).

### 2. Shell-preserving Suspense (`layout.tsx` + keep `App.tsx` outer boundary)
Wrap the `Layout`'s `<Outlet />` in its own `<Suspense>` so a lazy protected page suspends **inside** the
shell — the sidebar/header stay rendered and only the content area shows a spinner:
```tsx
// layout.tsx: import { useState, Suspense } from 'react'; import { LoadingSpinner } ...
<ErrorBoundary key={location.pathname}>
  <Suspense fallback={<div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>}>
    <Outlet />
  </Suspense>
</ErrorBoundary>
```
Keep `App.tsx`'s existing outer `<Suspense>` — it still covers the public routes (login/landing/etc.,
which are lazy and NOT under `Layout`) and acts as a safety boundary. For protected-route navigation the
inner boundary resolves first, so the outer full-screen fallback no longer fires.

## Testing / verification
- `cd web/admin-console && npm run build` — `tsc -b` clean; build output shows new `icons-*.js` and
  `query-*.js` chunks (separate from `vendor-*.js`); entry chunk unchanged (~62 KB).
- `npx vitest run` — full suite passes unchanged (page tests import page modules directly; they don't
  exercise App/Layout Suspense). `npx eslint src/App.tsx src/components/layout.tsx vite.config.ts` clean.
- Manual (optional): `npm run dev`, navigate between two unvisited sections — the sidebar/header stay
  and only the content area spins.

## Scope / risk
- Frontend-only, low risk. Files: `vite.config.ts`, `src/components/layout.tsx` (App.tsx unchanged —
  its outer boundary is retained by design). No behavior change beyond where the loading spinner appears
  and how vendor bytes are chunked.
- Out of scope: further vendor splitting beyond the two named libs; route-prefetch; lazy-loading the
  shell itself.
