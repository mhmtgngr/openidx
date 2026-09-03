# OpenIDX Admin Console

React + TypeScript (Vite) console for the OpenIDX platform.

```bash
npm install
npm run dev         # Vite dev server
npm run test        # vitest
npm run lint        # eslint
npm run type-check  # tsc -b
npm run build       # production build (tsc -b && vite build)
```

## Internationalization (i18n)

The console uses [i18next](https://www.i18next.com/) with `react-i18next`.
The landing page (`src/pages/landing.tsx`) is the reference extraction —
copy its pattern when extracting a page.

Conventions:

- **English is the source of truth**: `src/i18n/locales/en.ts`. Every other
  locale is typed against it (`const tr: typeof en = { ... }`), so a
  missing or extra key fails `npm run type-check` — there is no way to ship
  a half-translated catalog silently.
- **Components** call `useTranslation()` and reference dotted keys
  (`t('landing.hero.badge')`). Interpolation uses i18next syntax:
  `t('landing.footer.copyright', { year })` with `{{year}}` in the catalog.
- **Language choice** persists in `localStorage` under `openidx.lang`
  (falling back to browser language, then English). The
  `LanguageSwitcher` component (`src/components/language-switcher.tsx`)
  changes it live.
- **Proper nouns stay untranslated**: product names (Okta, Slack),
  protocol names (SAML, OIDC, SCIM), and the OpenIDX name itself.
- **Server-sourced text stays untranslated**: names, descriptions, status
  values, tips/summaries, and error messages that come out of an API
  response render as-is. Only strings authored in the frontend go into the
  catalogs.
- **Page bodies** live under the `pages.*` section, one subsection per
  page. Where a page's `<h1>` is exactly its navigation name, the page
  reuses the `nav.items.*` key instead of duplicating it. Keys referenced
  through runtime maps (e.g. a `Record<status, labelKey>`) are invisible
  to the `typeof en` check — pin them in `src/i18n/i18n.test.ts`.
- **`QueryError`** localizes its own sentences; the `resource` prop is
  interpolated as-is, so pass it already translated
  (`resource={t('pages.sessions.resourceName')}`).
- **Tests** render with the same i18n singleton (initialized from
  `src/test/setup.ts`), in English — assert English strings, and restore
  `en` if a test changes the language.

To add a language: add its catalog under `src/i18n/locales/`, typed
`typeof en`; register it in the `resources` map and `supportedLanguages`
list in `src/i18n/index.ts`. Type-check enforces completeness.

## Truthful marketing surfaces

The public-facing pages (landing) state **verifiable facts only** — no
invented SLAs, trials, pricing, latency figures, or adoption numbers. A
regression test (`src/pages/landing.test.tsx`, "makes no claims a
self-hosted OSS project cannot keep") pins this.

## Accessibility

Three checks cover three different things, because no single one of them can
cover the others:

| Check | Runs | Covers | Cannot cover |
| --- | --- | --- | --- |
| `src/test/a11y.test.tsx` | CI (vitest/jsdom) | The axe WCAG 2.1 A/AA rule set over **every page in `src/pages`**, derived from the directory so a new page is covered the day it lands | Colour contrast — jsdom has no layout or paint, so the rule is disabled there rather than left to fail silently. Also anything behind an interaction: a dialog body or dropdown is not mounted until it is opened |
| `src/test/design-token-contrast.test.ts` | CI (vitest) | Every design-token pair the components render, in **both** themes, straight out of `index.css` | Pairings built from Tailwind palette utilities, and tinted surfaces that composite per theme |
| `scripts/contrast-audit.mjs` | By hand | axe's `color-contrast` over 36 routes × 2 colour schemes in real Chromium, with a stubbed API so authenticated pages render | Only what a route actually paints — a control inside an unopened dialog is never measured |

Running the browser audit:

```bash
npm run build
npx vite preview --port 4173 &
node scripts/contrast-audit.mjs                  # all routes
ROUTES="my-security vault" node scripts/contrast-audit.mjs
```

It exits non-zero on any violation **or** on any route that renders blank —
a page that rendered nothing reports zero violations, which looks exactly
like a pass, so it is called out instead of counted.

The page sweep replaced a hand-written list of thirteen surfaces. The list was
right about priority — the pre-login and end-user screens are the ones someone
may have no choice about using — and wrong about scope: it left ninety-four
admin pages ungated, and they held twenty-nine violations of exactly the class
the gate existed to catch, including sixteen filter dropdowns that announced
nothing at all and five filters whose visible labels were bare `<label>`
elements with no `htmlFor`. An admin who uses a screen reader is not a lesser
user, and "the surfaces that matter" is not a list anyone keeps up to date.

One page is exempt: `api-docs`, because `swagger-ui-react` bundles its own copy
of React and cannot render in this environment. The exemption is itself a test
— it fails if the page starts rendering — so the list cannot quietly grow into
a list of the awkward cases.

Keyboard reachability is gated separately, by
`scripts/check-keyboard-reachable.sh` at the repo root (with the other UI
guards): a control you can click must be a control you can reach with a
keyboard. Prefer `components/selectable-row.tsx` over hand-rolling
`role="button"` + `tabIndex` + `onKeyDown` — Space has to be
`preventDefault`'d or it scrolls the page instead of activating the control,
and that is the part that goes missing when the pattern is copied by hand.

None of this is a VPAT. What a screen reader actually *announces*, and whether
a person can finish each journey using one, is not something any of these
tools judges — that still needs a person with a screen reader.
